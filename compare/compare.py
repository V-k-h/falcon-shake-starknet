#!/usr/bin/env python3
"""Benchmark this repo's Falcon-512 verifiers against other Cairo implementations.

Every implementation is checked out at a pinned commit into `compare/.work/<name>`, the
same adapter tests are added to it (with only the manifest and visibility changes listed
in compare/README.md), and all of them are measured with this repo's toolchain
(`.tool-versions`) by paired-test subtraction:

    cost(K) = cmp_K - cmp_K_base

where `cmp_K_base` builds the identical inputs and skips only the measured call. L2 gas
comes from a sierra-gas run and steps from a cairo-steps run, as in `scripts/run_bench.py`.

Shared inputs. The NTT and lattice-core rows feed every implementation the same Falcon-512
signature (this repo's SHAKE fixture, unpacked to coefficients), so they compare like for
like. Hash-to-point, full verification and `__validate__` use each implementation's own
hash and its own valid fixture, because the hash constructions differ.

Every measured test asserts acceptance, and each adapter also carries `cmpcheck_*` tests
(tampered inputs must be rejected, the shared message point must match the implementation's
own hash where the hashes agree). The run fails if any check fails.

Usage:
    python3 compare/compare.py            # check out, measure, write results.json + RESULTS.md
    python3 compare/compare.py --keep     # reuse the checkouts already in compare/.work
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
WORK = HERE / ".work"
sys.path.insert(0, str(REPO / "scripts"))

import gen_falcon_fixture  # noqa: E402
import gen_ntt_tables  # noqa: E402
import gen_shake_h2p_kat  # noqa: E402
from run_bench import CAPS, parse  # noqa: E402

Q = 12289
MAX_N_STEPS = "50000000"


def git(*args, cwd=REPO):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


IMPLS = {
    "ours": {
        "title": "falcon-shake-starknet (this repo)",
        "url": str(REPO),
        "rev": None,  # HEAD of this repository
    },
    "oz": {
        "title": "OpenZeppelin/cairo-pq-verifiers",
        "url": "https://github.com/OpenZeppelin/cairo-pq-verifiers.git",
        "rev": "bece5c07eeea5784e570c01108ec000d2d04ae40",
    },
    "s2morrow": {
        "title": "feltroidprime/s2morrow",
        "url": "https://github.com/feltroidprime/s2morrow.git",
        "rev": "4eff9ab9f5a4eb3d65ea0570dc53813bf9acb12b",
    },
    "falcon_starknet": {
        "title": "V-k-h/falcon-starknet",
        "url": "https://github.com/V-k-h/falcon-starknet.git",
        "rev": "05c1f5426a66e6ca1d5bedb3e005cdcba1276c84",
    },
}


# --- Shared fixture -------------------------------------------------------------------


def shared_fixture():
    """This repo's SHAKE fixture, unpacked and re-derived independently of Cairo."""
    src = gen_shake_h2p_kat.FIXTURE.read_text()
    msg = int(re.search(r"pub fn msg\(\) -> felt252 \{\s*(\d+)", src).group(1))
    pk_src = src[src.index("pub fn public_key") : src.index("pub fn signature")]
    pk = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", pk_src)]
    sig = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", src[src.index("pub fn signature") :])]
    assert len(pk) == 29 and len(sig) == 60

    h_ntt = gen_falcon_fixture.unpack_512(pk)
    s1 = gen_falcon_fixture.unpack_512(sig[:29])
    mul_hint = gen_falcon_fixture.unpack_512(sig[31:])
    roots = next(p for p in gen_ntt_tables.ROOTS_LOCATIONS if p.exists())
    tables = gen_ntt_tables.parse_tables(roots)
    h = gen_ntt_tables.intt_rec(h_ntt, tables)
    msg_point = gen_shake_h2p_kat.hash_to_point(msg, sig[29], sig[30])

    assert gen_ntt_tables.ntt_rec(h, tables) == h_ntt
    assert gen_ntt_tables.negacyclic_mul(s1, h) == mul_hint, "fixture hint is not s1*h"
    centered = gen_falcon_fixture.centered
    norm = sum(centered((msg_point[i] - mul_hint[i]) % Q) ** 2 + centered(s1[i]) ** 2 for i in range(512))
    assert norm <= gen_falcon_fixture.SIG_BOUND_512, "fixture does not verify"
    return {
        "msg": msg, "public_key": pk, "signature": sig, "salt_a": sig[29], "salt_b": sig[30],
        "h_ntt": h_ntt, "h": h, "s1": s1, "mul_hint": mul_hint, "msg_point": msg_point,
        "ntt_expected": gen_ntt_tables.ntt_rec(mul_hint, tables),
    }


def cairo_array_fn(name, ty, values, per_line=16):
    rows = [", ".join(str(v) for v in values[i : i + per_line]) for i in range(0, len(values), per_line)]
    body = ",\n        ".join(rows)
    return f"fn {name}() -> Array<{ty}> {{\n    array![\n        {body},\n    ]\n}}\n"


def cairo_felt_fn(name, value):
    return f"fn {name}() -> felt252 {{\n    {hex(value)}\n}}\n"


def shared_cairo(fx, with_packed=True):
    parts = [
        cairo_array_fn("fx_h", "u16", fx["h"]),
        cairo_array_fn("fx_h_ntt", "u16", fx["h_ntt"]),
        cairo_array_fn("fx_s1", "u16", fx["s1"]),
        cairo_array_fn("fx_mul_hint", "u16", fx["mul_hint"]),
        cairo_array_fn("fx_msg_point", "u16", fx["msg_point"]),
        cairo_array_fn("fx_ntt_expected", "u16", fx["ntt_expected"]),
    ]
    if with_packed:
        parts += [
            cairo_felt_fn("fx_msg", fx["msg"]),
            cairo_felt_fn("fx_salt_a", fx["salt_a"]),
            cairo_felt_fn("fx_salt_b", fx["salt_b"]),
            cairo_array_fn("fx_public_key", "felt252", [hex(v) for v in fx["public_key"]], 4),
            cairo_array_fn("fx_signature", "felt252", [hex(v) for v in fx["signature"]], 4),
        ]
    return "\n".join(parts)


HEADER = "//! Cross-implementation benchmark adapter, generated by compare/compare.py.\n\n"

HELPERS_U16 = """
fn to_felts(values: Span<u16>) -> Array<felt252> {
    let mut out = array![];
    for v in values {
        out.append((*v).into());
    }
    out
}

fn bump(values: Span<u16>, index: u32) -> Array<u16> {
    let mut out = array![];
    let mut i = 0;
    for v in values {
        out.append(if i == index {
            (*v + 1) % 12289
        } else {
            *v
        });
        i += 1;
    }
    out
}
"""

VALIDATE_IFACE = """
#[starknet::interface]
trait IAccountValidate<T> {
    fn __validate__(self: @T, calls: Array<Call>) -> felt252;
}
"""


# --- This repo and OpenZeppelin/cairo-pq-verifiers (same public API) ------------------

PQV_BENCH = """use pqbench_falcon_512::falcon::{{
    verify_512_direct, verify_512_direct_u16, verify_512_with_hint, verify_512_with_hint_u16,
}};
use pqbench_falcon_512::hashing::hash_to_point::hash_to_point_shake_512;
use pqbench_falcon_512::{{Falcon512ShakeDirectVerifier, Falcon512ShakeVerifier}};
use pqbench_interface::PqSignatureVerifier;
use pqbench_ntt::ntt_falcon512_fast_u16_unchecked;
{helpers}
{fixture}
#[test]
fn cmp_ntt_base() {{
    let input = fx_mul_hint();
    assert!(input.len() == 512);
}}

#[test]
fn cmp_ntt() {{
    let input = fx_mul_hint();
    assert!(input.len() == 512);
    assert!(ntt_falcon512_fast_u16_unchecked(input.span()).len() == 512);
}}

#[test]
fn cmp_core_hint_base() {{
    let (s1, h, m, c) = (to_felts(fx_s1().span()), to_felts(fx_h_ntt().span()), to_felts(fx_mul_hint().span()), fx_msg_point());
    assert!(s1.len() + h.len() + m.len() + c.len() == 2048);
}}

#[test]
fn cmp_core_hint() {{
    let (s1, h, m, c) = (to_felts(fx_s1().span()), to_felts(fx_h_ntt().span()), to_felts(fx_mul_hint().span()), fx_msg_point());
    assert!(s1.len() + h.len() + m.len() + c.len() == 2048);
    assert!(verify_512_with_hint(s1.span(), h.span(), m.span(), c.span()));
}}

#[test]
fn cmp_core_hint_typed_base() {{
    let (s1, h, m, c) = (fx_s1(), fx_h_ntt(), fx_mul_hint(), fx_msg_point());
    assert!(s1.len() + h.len() + m.len() + c.len() == 2048);
}}

#[test]
fn cmp_core_hint_typed() {{
    let (s1, h, m, c) = (fx_s1(), fx_h_ntt(), fx_mul_hint(), fx_msg_point());
    assert!(s1.len() + h.len() + m.len() + c.len() == 2048);
    assert!(verify_512_with_hint_u16(s1.span(), h.span(), m.span(), c.span()));
}}

#[test]
fn cmp_core_direct_typed_base() {{
    let (s1, h, c) = (fx_s1(), fx_h_ntt(), fx_msg_point());
    assert!(s1.len() + h.len() + c.len() == 1536);
}}

#[test]
fn cmp_core_direct_typed() {{
    let (s1, h, c) = (fx_s1(), fx_h_ntt(), fx_msg_point());
    assert!(s1.len() + h.len() + c.len() == 1536);
    assert!(verify_512_direct_u16(s1.span(), h.span(), c.span()));
}}

#[test]
fn cmp_core_direct_base() {{
    let (s1, h, c) = (to_felts(fx_s1().span()), to_felts(fx_h_ntt().span()), fx_msg_point());
    assert!(s1.len() + h.len() + c.len() == 1536);
}}

#[test]
fn cmp_core_direct() {{
    let (s1, h, c) = (to_felts(fx_s1().span()), to_felts(fx_h_ntt().span()), fx_msg_point());
    assert!(s1.len() + h.len() + c.len() == 1536);
    assert!(verify_512_direct(s1.span(), h.span(), c.span()));
}}

#[test]
fn cmp_h2p_base() {{
    let (m, a, b) = (fx_msg(), fx_salt_a(), fx_salt_b());
    assert!(m + a + b != 0);
}}

#[test]
fn cmp_h2p() {{
    let (m, a, b) = (fx_msg(), fx_salt_a(), fx_salt_b());
    assert!(m + a + b != 0);
    assert!(hash_to_point_shake_512(m, a, b).unwrap().len() == 512);
}}

#[test]
fn cmp_verify_hint_base() {{
    let (pk, sig) = (fx_public_key(), fx_signature());
    assert!(pk.len() + sig.len() == 89);
}}

#[test]
fn cmp_verify_hint() {{
    let (pk, sig) = (fx_public_key(), fx_signature());
    assert!(pk.len() + sig.len() == 89);
    assert!(Falcon512ShakeVerifier::verify(fx_msg(), pk.span(), sig.span()));
}}

#[test]
fn cmp_verify_direct_base() {{
    let (pk, sig) = (fx_public_key(), fx_signature());
    assert!(pk.len() + sig.len() == 89);
}}

#[test]
fn cmp_verify_direct() {{
    let (pk, sig) = (fx_public_key(), fx_signature());
    assert!(pk.len() + sig.len() == 89);
    assert!(Falcon512ShakeDirectVerifier::verify(fx_msg(), pk.span(), sig.span().slice(0, 31)));
}}

#[test]
fn cmpcheck_ntt_matches_model() {{
    assert!(ntt_falcon512_fast_u16_unchecked(fx_mul_hint().span()) == fx_ntt_expected());
}}

#[test]
fn cmpcheck_h2p_matches_shared_point() {{
    assert!(hash_to_point_shake_512(fx_msg(), fx_salt_a(), fx_salt_b()).unwrap() == fx_msg_point());
}}

#[test]
fn cmpcheck_core_hint_rejects_tampered_hint() {{
    let m = to_felts(bump(fx_mul_hint().span(), 100).span());
    let (s1, h) = (to_felts(fx_s1().span()), to_felts(fx_h_ntt().span()));
    assert!(!verify_512_with_hint(s1.span(), h.span(), m.span(), fx_msg_point().span()));
}}

#[test]
fn cmpcheck_core_direct_rejects_tampered_s1() {{
    let s1 = to_felts(bump(fx_s1().span(), 100).span());
    let h = to_felts(fx_h_ntt().span());
    assert!(!verify_512_direct(s1.span(), h.span(), fx_msg_point().span()));
}}

#[test]
fn cmpcheck_verify_rejects_other_message() {{
    let (pk, sig) = (fx_public_key(), fx_signature());
    assert!(!Falcon512ShakeVerifier::verify(fx_msg() + 1, pk.span(), sig.span()));
    assert!(!Falcon512ShakeDirectVerifier::verify(fx_msg() + 1, pk.span(), sig.span().slice(0, 31)));
}}
"""

PQV_VALIDATE = """use snforge_std::{{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_signature_global,
    start_cheat_transaction_hash_global,
}};
use starknet::ContractAddress;
use starknet::account::Call;
{iface}
{fixture}
fn deploy(name: ByteArray) -> ContractAddress {{
    let mut calldata = array![];
    fx_public_key().serialize(ref calldata);
    let (address, _) = declare(name).unwrap().contract_class().deploy(@calldata).unwrap();
    address
}}

fn signature(direct: bool) -> Array<felt252> {{
    let sig = fx_signature();
    let len = if direct {{
        31
    }} else {{
        60
    }};
    let mut out = array![];
    for f in sig.span().slice(0, len) {{
        out.append(*f);
    }}
    out
}}

fn setup(name: ByteArray, direct: bool, message: felt252) -> IAccountValidateDispatcher {{
    let address = deploy(name);
    start_cheat_transaction_hash_global(message);
    start_cheat_signature_global(signature(direct).span());
    IAccountValidateDispatcher {{ contract_address: address }}
}}

#[test]
fn cmp_validate_hint_base() {{
    let _account = setup("Falcon512ShakeAccount", false, fx_msg());
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
}}

#[test]
fn cmp_validate_hint() {{
    let account = setup("Falcon512ShakeAccount", false, fx_msg());
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
    assert!(account.__validate__(calls) == starknet::VALIDATED);
}}

#[test]
fn cmp_validate_direct_base() {{
    let _account = setup("Falcon512ShakeDirectAccount", true, fx_msg());
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
}}

#[test]
fn cmp_validate_direct() {{
    let account = setup("Falcon512ShakeDirectAccount", true, fx_msg());
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
    assert!(account.__validate__(calls) == starknet::VALIDATED);
}}

#[test]
#[should_panic]
fn cmpcheck_validate_hint_rejects_other_hash() {{
    let account = setup("Falcon512ShakeAccount", false, fx_msg() + 1);
    account.__validate__(array![]);
}}

#[test]
#[should_panic]
fn cmpcheck_validate_direct_rejects_other_hash() {{
    let account = setup("Falcon512ShakeDirectAccount", true, fx_msg() + 1);
    account.__validate__(array![]);
}}
"""


# --- feltroidprime/s2morrow (Poseidon hash-to-point) -----------------------------------

S2M_COMMON = """
fn to_zq(values: Span<u16>) -> Array<Zq> {
    let mut out = array![];
    for v in values {
        out.append(from_u16(*v));
    }
    out
}

fn packed_signature(salt: Array<felt252>, mul_hint: Span<u16>) -> PackedFalconSignatureWithHint {
    PackedFalconSignatureWithHint {
        signature: PackedFalconSignature {
            s1: PackedPolynomial512Trait::from_coeffs(to_zq(s2m_s1().span()).span()), salt,
        },
        hint: PackedFalconVerificationHint {
            mul_hint: PackedPolynomial512Trait::from_coeffs(to_zq(mul_hint).span()),
        },
    }
}

fn packed_public_key() -> PackedPolynomial512 {
    PackedPolynomial512Trait::from_coeffs(to_zq(s2m_pk_ntt().span()).span())
}
"""

S2M_BENCH = """use falcon::falcon::{{verify_packed, verify_with_msg_point}};
use falcon::hash_to_point::{{PoseidonHashToPoint, PoseidonHashToPointImpl}};
use falcon::ntt::ntt_fast;
use falcon::packing::{{PackedPolynomial512, PackedPolynomial512Trait}};
use falcon::types::{{
    FalconPublicKey, FalconSignature, FalconSignatureWithHint, FalconVerificationHint,
    PackedFalconSignature, PackedFalconSignatureWithHint, PackedFalconVerificationHint,
}};
use falcon::zq::{{Zq, from_u16}};
{helpers}{common}
{fixture}
{own}
fn core_inputs(mul_hint: Span<u16>) -> (FalconPublicKey, FalconSignatureWithHint, Array<Zq>) {{
    let h = to_zq(fx_h().span());
    let pk = FalconPublicKey {{ h_ntt: ntt_fast(h.span()) }};
    let sig = FalconSignatureWithHint {{
        signature: FalconSignature {{ s1: to_zq(fx_s1().span()), salt: array![] }},
        hint: FalconVerificationHint {{ mul_hint: to_zq(mul_hint) }},
    }};
    (pk, sig, to_zq(fx_msg_point().span()))
}}

#[test]
fn cmp_ntt_base() {{
    let input = to_zq(fx_mul_hint().span());
    assert!(input.len() == 512);
}}

#[test]
fn cmp_ntt() {{
    let input = to_zq(fx_mul_hint().span());
    assert!(input.len() == 512);
    assert!(ntt_fast(input.span()).len() == 512);
}}

#[test]
fn cmp_core_hint_typed_base() {{
    let (pk, sig, c) = core_inputs(fx_mul_hint().span());
    assert!(pk.h_ntt.len() + sig.signature.s1.len() + sig.hint.mul_hint.len() + c.len() == 2048);
}}

#[test]
fn cmp_core_hint_typed() {{
    let (pk, sig, c) = core_inputs(fx_mul_hint().span());
    assert!(pk.h_ntt.len() + sig.signature.s1.len() + sig.hint.mul_hint.len() + c.len() == 2048);
    assert!(verify_with_msg_point(@pk, sig, c.span()));
}}

#[test]
fn cmp_h2p_base() {{
    let (m, s) = (s2m_message(), s2m_salt());
    assert!(m.len() + s.len() == 3);
}}

#[test]
fn cmp_h2p() {{
    let (m, s) = (s2m_message(), s2m_salt());
    assert!(m.len() + s.len() == 3);
    assert!(PoseidonHashToPointImpl::hash_to_point(m.span(), s.span()).len() == 512);
}}

#[test]
fn cmp_verify_hint_base() {{
    let (pk, sig, m) = (packed_public_key(), packed_signature(s2m_salt(), s2m_mul_hint().span()), s2m_message());
    assert!(sig.signature.salt.len() + m.len() == 3);
    let _pk = pk;
}}

#[test]
fn cmp_verify_hint() {{
    let (pk, sig, m) = (packed_public_key(), packed_signature(s2m_salt(), s2m_mul_hint().span()), s2m_message());
    assert!(sig.signature.salt.len() + m.len() == 3);
    assert!(verify_packed::<PoseidonHashToPoint>(@pk, sig, m.span()));
}}

#[test]
fn cmpcheck_ntt_is_negacyclic() {{
    let (pk, sig, c) = core_inputs(fx_mul_hint().span());
    assert!(verify_with_msg_point(@pk, sig, c.span()));
}}

#[test]
#[should_panic]
fn cmpcheck_core_hint_rejects_tampered_hint() {{
    let (pk, sig, c) = core_inputs(bump(fx_mul_hint().span(), 100).span());
    assert!(!verify_with_msg_point(@pk, sig, c.span()));
}}

#[test]
fn cmpcheck_verify_rejects_other_message() {{
    let (pk, sig) = (packed_public_key(), packed_signature(s2m_salt(), s2m_mul_hint().span()));
    let mut m = s2m_message();
    m.append(1);
    assert!(!verify_packed::<PoseidonHashToPoint>(@pk, sig, m.span()));
}}
"""

S2M_VALIDATE = """use falcon::packing::{{PackedPolynomial512, PackedPolynomial512Trait}};
use falcon::types::{{
    PackedFalconSignature, PackedFalconSignatureWithHint, PackedFalconVerificationHint,
}};
use falcon::zq::{{Zq, from_u16}};
use snforge_std::{{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_signature_global,
    start_cheat_transaction_hash_global,
}};
use starknet::account::Call;
{iface}{common}
{own}
fn setup(message: felt252) -> IAccountValidateDispatcher {{
    let mut calldata = array![];
    packed_public_key().serialize(ref calldata);
    let class = declare("FalconAccount").unwrap().contract_class();
    let (address, _) = class.deploy(@calldata).unwrap();
    let mut signature = array![];
    packed_signature(s2m_salt(), s2m_mul_hint().span()).serialize(ref signature);
    start_cheat_transaction_hash_global(message);
    start_cheat_signature_global(signature.span());
    IAccountValidateDispatcher {{ contract_address: address }}
}}

#[test]
fn cmp_validate_hint_base() {{
    let _account = setup(*s2m_message().at(0));
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
}}

#[test]
fn cmp_validate_hint() {{
    let account = setup(*s2m_message().at(0));
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
    assert!(account.__validate__(calls) == starknet::VALIDATED);
}}

#[test]
#[should_panic]
fn cmpcheck_validate_rejects_other_hash() {{
    let account = setup(*s2m_message().at(0) + 1);
    account.__validate__(array![]);
}}
"""


def s2morrow_own(root):
    data = json.loads((root / "packages/falcon/tests/data/verify_test_int.json").read_text())["verify_test"]
    it = iter(data)

    def take():
        n = next(it)
        return [next(it) for _ in range(n)]

    message, salt, pk_ntt, s1, mul_hint = take(), take(), take(), take(), take()
    assert len(message) == 1 and len(pk_ntt) == len(s1) == len(mul_hint) == 512
    return "\n".join([
        cairo_array_fn("s2m_message", "felt252", message),
        cairo_array_fn("s2m_salt", "felt252", salt),
        cairo_array_fn("s2m_pk_ntt", "u16", pk_ntt),
        cairo_array_fn("s2m_s1", "u16", s1),
        cairo_array_fn("s2m_mul_hint", "u16", mul_hint),
    ])


# --- V-k-h/falcon-starknet (FN-DSA framing) -------------------------------------------

FS_BENCH = """use falcon::hash_to_point::hash_to_point;
use falcon::ntt_looped::ntt_512_looped;
use falcon::verify::{{verify_full_from_pk, verify_full_shake, verify_hint_512_looped}};
{helpers}
{fixture}
{own}
#[test]
fn cmp_ntt_base() {{
    let input = to_felts(fx_mul_hint().span());
    assert!(input.len() == 512);
}}

#[test]
fn cmp_ntt() {{
    let input = to_felts(fx_mul_hint().span());
    assert!(input.len() == 512);
    assert!(ntt_512_looped(input.span()).len() == 512);
}}

fn core_inputs(mul_hint: Span<u16>) -> (Array<felt252>, Array<felt252>, Array<felt252>, Array<felt252>) {{
    let pk_ntt = ntt_512_looped(to_felts(fx_h().span()).span());
    (to_felts(fx_s1().span()), pk_ntt, to_felts(mul_hint), to_felts(fx_msg_point().span()))
}}

#[test]
fn cmp_core_hint_typed_base() {{
    let (s2, pk, m, c) = core_inputs(fx_mul_hint().span());
    assert!(s2.len() + pk.len() + m.len() + c.len() == 2048);
}}

#[test]
fn cmp_core_hint_typed() {{
    let (s2, pk, m, c) = core_inputs(fx_mul_hint().span());
    assert!(s2.len() + pk.len() + m.len() + c.len() == 2048);
    assert!(verify_hint_512_looped(s2.span(), pk.span(), m.span(), c.span()));
}}

#[test]
fn cmp_core_hint_base() {{
    let (s2, pk, m, c) = core_inputs(fx_mul_hint().span());
    assert!(s2.len() + pk.len() + m.len() + c.len() == 2048);
}}

#[test]
fn cmp_core_hint() {{
    let (s2, pk, m, c) = core_inputs(fx_mul_hint().span());
    assert!(s2.len() + pk.len() + m.len() + c.len() == 2048);
    assert!(verify_hint_512_looped(s2.span(), pk.span(), m.span(), c.span()));
}}

#[test]
fn cmp_h2p_base() {{
    let framed = fs_framed();
    assert!(framed.len() != 0);
}}

#[test]
fn cmp_h2p() {{
    let framed = fs_framed();
    assert!(framed.len() != 0);
    assert!(hash_to_point(framed).len() == 512);
}}

#[test]
fn cmp_verify_hint_base() {{
    let (framed, s2, pk, m) = (fs_framed(), fs_s2(), fs_pk_ntt(), fs_mul_hint());
    assert!(framed.len() + s2.len() + pk.len() + m.len() != 0);
}}

#[test]
fn cmp_verify_hint() {{
    let (framed, s2, pk, m) = (fs_framed(), fs_s2(), fs_pk_ntt(), fs_mul_hint());
    assert!(framed.len() + s2.len() + pk.len() + m.len() != 0);
    assert!(verify_full_shake(framed, s2.span(), pk.span(), m.span()));
}}

#[test]
fn cmp_verify_from_pk_base() {{
    let (vk, nonce, msg) = (fs_vrfy_key(), fs_nonce(), fs_message());
    let (s2, pk, m) = (fs_s2(), fs_pk_ntt(), fs_mul_hint());
    assert!(vk.len() + nonce.len() + msg.len() + s2.len() + pk.len() + m.len() != 0);
}}

#[test]
fn cmp_verify_from_pk() {{
    let (vk, nonce, msg) = (fs_vrfy_key(), fs_nonce(), fs_message());
    let (s2, pk, m) = (fs_s2(), fs_pk_ntt(), fs_mul_hint());
    assert!(vk.len() + nonce.len() + msg.len() + s2.len() + pk.len() + m.len() != 0);
    assert!(verify_full_from_pk(vk, nonce, msg, s2.span(), pk.span(), m.span()));
}}

#[test]
fn cmpcheck_core_hint_rejects_tampered_hint() {{
    let (s2, pk, m, c) = core_inputs(bump(fx_mul_hint().span(), 100).span());
    assert!(!verify_hint_512_looped(s2.span(), pk.span(), m.span(), c.span()));
}}

#[test]
fn cmpcheck_verify_rejects_other_message() {{
    let mut framed = fs_framed();
    framed.append(0);
    assert!(!verify_full_shake(framed, fs_s2().span(), fs_pk_ntt().span(), fs_mul_hint().span()));
}}
"""

FS_UNROLLED = """use falcon::ntt512::ntt_512;
{helpers}
{fixture}
#[test]
fn cmp_ntt_unrolled_base() {{
    let input = to_felts(fx_mul_hint().span());
    assert!(input.len() == 512);
}}

#[test]
fn cmp_ntt_unrolled() {{
    let input = to_felts(fx_mul_hint().span());
    assert!(input.len() == 512);
    assert!(ntt_512(input.span()).len() == 512);
}}
"""


def falcon_starknet_own(root):
    data = root / "packages/falcon/tests/data"
    framed = json.loads((data / "verify512_framed.json").read_text())["framed"]
    kat = json.loads((data / "verify512_kat.json").read_text())["verify512"]
    pk_in = json.loads((data / "verify512_pk_inputs.json").read_text())

    def strip(arr):
        assert arr[0] == len(arr) - 1
        return arr[1:]

    it = iter(kat)
    arrays = []
    for _ in range(6):
        n = next(it)
        arrays.append([next(it) for _ in range(n)])
    s2, pk_ntt, mul_hint = arrays[0], arrays[1], arrays[2]
    return "\n".join([
        cairo_array_fn("fs_framed", "u8", strip(framed), 24),
        cairo_array_fn("fs_s2", "felt252", s2),
        cairo_array_fn("fs_pk_ntt", "felt252", pk_ntt),
        cairo_array_fn("fs_mul_hint", "felt252", mul_hint),
        cairo_array_fn("fs_vrfy_key", "u8", strip(pk_in["vrfy_key"]), 24),
        cairo_array_fn("fs_nonce", "u8", strip(pk_in["nonce"]), 24),
        cairo_array_fn("fs_message", "u8", strip(pk_in["message"]), 24),
    ])


# --- Checkout, patch, run -------------------------------------------------------------


def checkout(name, impl, keep):
    root = WORK / name
    rev = impl["rev"] or git("rev-parse", "HEAD")
    if not (keep and root.exists()):
        if root.exists():
            shutil.rmtree(root)
        WORK.mkdir(exist_ok=True)
        git("clone", "--quiet", impl["url"], str(root))
        git("checkout", "--quiet", rev, cwd=root)
    shutil.copy(REPO / ".tool-versions", root / ".tool-versions")
    return root, git("rev-parse", "HEAD", cwd=root)


def patch(path, old, new, count=1):
    text = path.read_text()
    if new in text:
        return
    assert text.count(old) == count, f"{path}: expected {count}x {old!r}"
    path.write_text(text.replace(old, new))


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEADER + content)


def prepare(name, root, fx):
    """Add the adapter tests; return [(package_dir, label)] to run and the classes to size."""
    helpers = HELPERS_U16
    if name in ("ours", "oz"):
        write(root / "crates/falcon_512/tests/compare_bench.cairo",
              PQV_BENCH.format(helpers=helpers, fixture=shared_cairo(fx)))
        validate = PQV_VALIDATE.format(iface=VALIDATE_IFACE, fixture=shared_cairo(fx))
        write(root / "pq-accounts/contracts/tests/compare_validate.cairo", validate)
        accounts = root / "pq-accounts/contracts"
        if (accounts / "tests/lib.cairo").exists():
            patch(accounts / "tests/lib.cairo", "mod accounts;\n", "mod accounts;\nmod compare_validate;\n")
        else:
            patch(accounts / "Scarb.toml", "[[target.starknet-contract]]",
                  "[lib]\n\n[dev-dependencies]\nsnforge_std.workspace = true\n\n[[target.starknet-contract]]")
        falcon = root / "crates/falcon_512/src/falcon.cairo"
        patch(falcon, "pub(crate) fn verify_512_with_hint_u16(", "pub fn verify_512_with_hint_u16(")
        patch(falcon, "pub(crate) fn verify_512_direct_u16(", "pub fn verify_512_direct_u16(")
        runs = [(root / "crates/falcon_512", "verifier"), (accounts, "account")]
        classes = {"validate_hint": (root, "pq_accounts_Falcon512ShakeAccount"),
                   "validate_direct": (root, "pq_accounts_Falcon512ShakeDirectAccount")}
        return runs, classes

    if name == "s2morrow":
        for manifest in root.glob("packages/*/Scarb.toml"):
            text = manifest.read_text()
            text = text.replace('tag = "v0.55.0"', 'tag = "v0.59.0"')
            text = text.replace('assert_macros = "2.15.1"', 'assert_macros = "2.18.0"')
            manifest.write_text(text)
        patch(root / "packages/falcon_account/Scarb.toml", "[[target.starknet-contract]]",
              "[lib]\n\n[[target.starknet-contract]]")
        own = s2morrow_own(root)
        write(root / "packages/falcon/tests/compare_bench.cairo",
              S2M_BENCH.format(helpers=helpers, common=S2M_COMMON, fixture=shared_cairo(fx, False), own=own))
        write(root / "packages/falcon_account/tests/compare_validate.cairo",
              S2M_VALIDATE.format(iface=VALIDATE_IFACE, common=S2M_COMMON, own=own))
        runs = [(root / "packages/falcon", "verifier"), (root / "packages/falcon_account", "account")]
        return runs, {"validate_hint": (root, "falcon_account_FalconAccount")}

    if name == "falcon_starknet":
        own = falcon_starknet_own(root)
        write(root / "packages/falcon/tests/compare_bench.cairo",
              FS_BENCH.format(helpers=helpers, fixture=shared_cairo(fx, False), own=own))
        write(root / "packages/falcon/tests/compare_unrolled.cairo",
              FS_UNROLLED.format(helpers=helpers, fixture=shared_cairo(fx, False)))
        contract = root / "packages/verifier_contract"
        patch(contract / "Scarb.toml", "sierra = true\n", "sierra = true\ncasm = true\n")
        runs = [(root / "packages/falcon", "verifier")]
        return runs, {"verifier_contract": (contract, "verifier_contract_FalconVerifier")}

    raise ValueError(name)


def snforge(cwd, filt, extra=()):
    cmd = ["snforge", "test", filt, "--detailed-resources", "--max-n-steps", MAX_N_STEPS, *extra]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + "\n" + proc.stderr


def class_size(root, stem):
    subprocess.run(["scarb", "--release", "build"], cwd=root, capture_output=True, text=True)
    target = root / "target/release"
    casm = target / f"{stem}.compiled_contract_class.json"
    sierra = target / f"{stem}.contract_class.json"
    if not casm.exists():
        candidates = sorted(p.name for p in target.glob("*.compiled_contract_class.json")) if target.exists() else []
        return {"error": f"{casm.name} not built", "available": candidates}
    return {"casm_felts": len(json.loads(casm.read_text())["bytecode"]), "sierra_bytes": sierra.stat().st_size}


def measure(name, impl, fx, keep, log):
    root, rev = checkout(name, impl, keep)
    runs, classes = prepare(name, root, fx)
    result = {"title": impl["title"], "url": impl["url"] if name != "ours" else "this repository",
              "rev": rev, "costs": {}, "checks": {}, "classes": {}, "errors": []}
    for cwd, label in runs:
        code, out = snforge(cwd, "cmpcheck_")
        (log / f"{name}-{label}-check.txt").write_text(out)
        passed = re.findall(r"\[PASS\]\s+[\w:]+::(cmpcheck_\w+)", out)
        failed = re.findall(r"\[FAIL\]\s+[\w:]+::(cmpcheck_\w+)", out)
        for t in passed:
            result["checks"][t] = "pass"
        for t in failed:
            result["checks"][t] = "FAIL"
        if code != 0 and not failed:
            result["errors"].append(f"{label}: check run failed to build (see compare/.work/logs)")

        _, gas_out = snforge(cwd, "cmp_")
        _, steps_out = snforge(cwd, "cmp_", ["--tracked-resource", "cairo-steps"])
        (log / f"{name}-{label}-gas.txt").write_text(gas_out)
        (log / f"{name}-{label}-steps.txt").write_text(steps_out)
        gas, steps = parse(gas_out), parse(steps_out)
        for test in gas:
            if not test.startswith("cmp_") or test.endswith("_base"):
                continue
            key, base = test[len("cmp_"):], test + "_base"
            if base not in gas or "sierra_gas" not in gas[test]:
                result["errors"].append(f"{test}: missing measurement or baseline")
                continue
            entry = {"l2_gas": gas[test]["sierra_gas"] - gas[base]["sierra_gas"]}
            if test in steps and base in steps and "steps" in steps[test]:
                entry["steps"] = steps[test]["steps"] - steps[base]["steps"]
            result["costs"][key] = entry
        for test in re.findall(r"\[FAIL\]\s+[\w:]+::(cmp_\w+)", gas_out):
            result["errors"].append(f"{test}: failed")
    for key, (croot, stem) in classes.items():
        result["classes"][key] = class_size(croot, stem)
    return result


# --- Report ---------------------------------------------------------------------------

ROWS = [
    ("ntt", "Forward NTT-512 (deployable)", "shared"),
    ("ntt_unrolled", "Forward NTT-512, fully unrolled (not deployable)", "shared"),
    ("core_hint_typed", "Lattice core, hint, native coefficient type", "shared"),
    ("core_hint", "Lattice core, hint, public API from felts", "shared"),
    ("core_direct_typed", "Lattice core, direct, native coefficient type", "shared"),
    ("core_direct", "Lattice core, direct, public API from felts", "shared"),
    ("h2p", "Hash-to-point", "own"),
    ("verify_hint", "Full verify, hint", "own"),
    ("verify_direct", "Full verify, direct", "own"),
    ("verify_from_pk", "Full verify, hashing the raw public key on-chain", "own"),
    ("validate_hint", "`__validate__`, hint account", "own"),
    ("validate_direct", "`__validate__`, direct account", "own"),
]

HASH = {
    "ours": "SHAKE-256, Falcon round-3 framing",
    "oz": "SHAKE-256, Falcon round-3 framing",
    "s2morrow": "Poseidon (non-standard)",
    "falcon_starknet": "SHAKE-256, FN-DSA draft framing",
}


def fmt_cost(c):
    if not c:
        return "—"
    gas = f"{c['l2_gas'] / 1e6:,.2f}M"
    return f"{gas} / {c['steps']:,}" if "steps" in c else gas


def render(results, meta):
    names = list(results)
    lines = [
        "| Measurement | Inputs | " + " | ".join(results[n]["title"] for n in names) + " |",
        "|---|---|" + "--:|" * len(names),
    ]
    for key, label, inputs in ROWS:
        cells = [fmt_cost(results[n]["costs"].get(key)) for n in names]
        if all(c == "—" for c in cells):
            continue
        lines.append(f"| {label} | {inputs} | " + " | ".join(cells) + " |")
    lines.append("| Hash-to-point construction | | " + " | ".join(HASH[n] for n in names) + " |")

    class_lines = ["| Contract | Implementation | CASM felts | Sierra bytes | Fits class cap |", "|---|---|--:|--:|---|"]
    for n in names:
        for key, c in results[n]["classes"].items():
            if "casm_felts" in c:
                fits = c["casm_felts"] <= 81_920 and c["sierra_bytes"] <= 4_089_446
                class_lines.append(f"| {key} | {results[n]['title']} | {c['casm_felts']:,} | {c['sierra_bytes']:,} | {'yes' if fits else '**no**'} |")
            else:
                class_lines.append(f"| {key} | {results[n]['title']} | build failed | | |")

    revs = "\n".join(f"- {results[n]['title']}: `{results[n]['rev']}`" for n in names)
    checks = "\n".join(
        f"- {results[n]['title']}: {sum(v == 'pass' for v in results[n]['checks'].values())} passed"
        + (f", **{sum(v != 'pass' for v in results[n]['checks'].values())} failed**" if any(v != 'pass' for v in results[n]['checks'].values()) else "")
        for n in names
    )
    return "\n".join(lines), "\n".join(class_lines), revs, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true", help="reuse existing checkouts")
    parser.add_argument("--only", nargs="*", help="measure only these implementations")
    args = parser.parse_args()

    fx = shared_fixture()
    log = WORK / "logs"
    log.mkdir(parents=True, exist_ok=True)
    out_json = HERE / "results.json"
    previous = json.loads(out_json.read_text())["implementations"] if out_json.exists() and args.only else {}

    results = {}
    for name, impl in IMPLS.items():
        if args.only and name not in args.only:
            if name in previous:
                results[name] = previous[name]
            continue
        print(f"measuring {name} ...", flush=True)
        results[name] = measure(name, impl, fx, args.keep, log)
        for err in results[name]["errors"]:
            print(f"  ! {err}")

    tools = dict(line.split() for line in (REPO / ".tool-versions").read_text().splitlines() if line.strip())
    meta = {
        "generated": datetime.date.today().isoformat(),
        "toolchain": {"scarb": tools.get("scarb"), "snforge": tools.get("starknet-foundry")},
        "caps": CAPS,
        "method": "paired-test subtraction: cmp_K - cmp_K_base",
    }
    out_json.write_text(json.dumps({"metadata": meta, "implementations": results}, indent=2) + "\n")
    table, classes, revs, checks = render(results, meta)
    (HERE / "RESULTS.md").write_text(
        f"# Measured results\n\nGenerated by `python3 compare/compare.py` on {meta['generated']} with "
        f"Scarb {meta['toolchain']['scarb']} and Starknet Foundry {meta['toolchain']['snforge']}. "
        "Cells are L2 gas / Cairo steps. See README.md for the method and caveats.\n\n"
        f"## Cost\n\n{table}\n\n## Contract class size\n\n{classes}\n\n"
        f"## Pinned commits\n\n{revs}\n\n## Correctness checks\n\n{checks}\n"
    )
    print(table)
    print()
    print(classes)
    bad = [n for n in results if results[n]["errors"] or any(v != "pass" for v in results[n]["checks"].values())]
    if bad:
        sys.exit(f"errors or failed checks in: {', '.join(bad)} (logs in compare/.work/logs)")


if __name__ == "__main__":
    main()
