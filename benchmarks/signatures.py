#!/usr/bin/env python3
"""Measure verification cost across many independent Falcon-512 signatures.

The ratchet fixture is a single signature, but the cost of a signature depends on its
salt: the SHAKE-256 hash-to-point squeezes 136-byte blocks, one Keccak-f[1600]
permutation each, until 512 coefficients are accepted, which takes 8 blocks for some
salts and 9 for the rest (10 or more with probability below 1e-18). This script signs
random messages with one fresh falcon.py keypair, then measures every signature under
both verifiers and both accounts, plus the cost of the ways a signature can be rejected.

Every measured verification asserts acceptance, and a `cmpcheck_` test per signature
asserts that the same signature over a different message is rejected by both variants.
Costs use paired-test subtraction in a clean checkout of HEAD (`benchmarks/.work`), with
`--max-n-steps` raised so whole-batch runs are not cut short.

Usage:
    # New keypair and signatures (needs a falcon.py clone and numpy, pycryptodome, beartype):
    python3 benchmarks/signatures.py --generate --falcon-py /path/to/falcon.py [--count 64]
    # Measure the committed signatures in benchmarks/data/signatures.json:
    python3 benchmarks/signatures.py
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
from math import comb
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
WORK = HERE / ".work"
DATA = HERE / "data" / "signatures.json"
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "compare"))

import compare  # noqa: E402
import gen_falcon_fixture  # noqa: E402
import gen_shake_h2p_kat  # noqa: E402

Q = 12289
STARK_PRIME = 2**251 + 17 * 2**192 + 1
RATE_BYTES = 136
ACCEPT = 5 * Q


def blocks_needed(message_hash: int, salt_a: int, salt_b: int) -> int:
    """SHAKE-256 output blocks (Keccak permutations) the hash-to-point consumes."""
    data = gen_shake_h2p_kat.salt_bytes(salt_a, salt_b) + message_hash.to_bytes(32, "little")
    stream = hashlib.shake_256(data).digest(RATE_BYTES * 16)
    accepted = 0
    for i in range(0, len(stream), 2):
        if (stream[i] << 8) | stream[i + 1] < ACCEPT:
            accepted += 1
            if accepted == 512:
                return (i + 2 + RATE_BYTES - 1) // RATE_BYTES
    raise AssertionError("more than 16 blocks")


def block_probabilities() -> dict[int, float]:
    """Exact P(k blocks): at least 512 of the 68k words accepted, but not of 68(k-1)."""
    p = ACCEPT / 65536

    def more_than(blocks: int) -> float:
        """P(fewer than 512 of the first 68 * blocks words are accepted), from the small tail."""
        words = 68 * blocks
        return sum(comb(words, j) * p**j * (1 - p) ** (words - j) for j in range(512))

    tail = {k: more_than(k) for k in range(7, 11)}
    return {k: tail[k - 1] - tail[k] for k in range(8, 11)}


# --- Generation (falcon.py) -----------------------------------------------------------


def generate(falcon_py: Path, count: int) -> None:
    sys.path.insert(0, str(falcon_py))
    import falcon as fpy  # noqa: E402
    from ntt import div_zq, mul_zq, ntt  # noqa: E402

    scheme = fpy.Falcon(512)
    print("keygen (NTRU solve, may take a while)...")
    sk, _ = scheme.keygen()
    f, g = sk[0], sk[1]
    h = div_zq(g, f)
    h_ntt = ntt(h)
    mods = (scheme, mul_zq, ntt)

    signatures = []
    public_key = None
    for i in range(count):
        message_hash = int.from_bytes(os.urandom(32), "big") % STARK_PRIME
        salt = os.urandom(40)
        salt_a = int.from_bytes(salt[:20], "little")
        salt_b = int.from_bytes(salt[20:], "little")
        point = gen_shake_h2p_kat.hash_to_point(message_hash, salt_a, salt_b)
        assert point == scheme.__hash_to_point__(message_hash.to_bytes(32, "little"), salt)
        signature, public_key, norm = gen_falcon_fixture.sign_point(mods, sk, h, h_ntt, point, salt)
        signatures.append({
            "message_hash": hex(message_hash),
            "signature": [hex(v) for v in signature],
            "blocks": blocks_needed(message_hash, salt_a, salt_b),
            "norm": norm,
        })
        print(f"signature {i + 1}/{count}: {signatures[-1]['blocks']} blocks")

    DATA.parent.mkdir(parents=True, exist_ok=True)
    DATA.write_text(json.dumps({
        "generator": "benchmarks/signatures.py --generate (tprest/falcon.py keygen and sampler)",
        "public_key": [hex(v) for v in public_key],
        "signatures": signatures,
    }, indent=1) + "\n")
    print(f"wrote {DATA.relative_to(REPO)}")


# --- Adapter tests --------------------------------------------------------------------

VERIFY_TESTS = """use pqbench_falcon_512::{{Falcon512ShakeDirectVerifier, Falcon512ShakeVerifier}};
use pqbench_interface::PqSignatureVerifier;

{fixtures}
fn replaced(src: Span<felt252>, index: u32, value: felt252) -> Array<felt252> {{
    let mut out = array![];
    let mut i = 0;
    for f in src {{
        out.append(if i == index {{
            value
        }} else {{
            *f
        }});
        i += 1;
    }}
    out
}}

#[test]
fn cmp_sig_base() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
}}
{per_signature}
#[test]
fn cmp_reject_length_base() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
    let short = sig.span().slice(0, 59);
    assert!(short.len() == 59);
}}

#[test]
fn cmp_reject_length() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
    let short = sig.span().slice(0, 59);
    assert!(short.len() == 59);
    assert!(!Falcon512ShakeVerifier::verify(message_0(), pk.span(), short));
}}

#[test]
fn cmp_reject_packing_base() {{
    let (pk, sig) = (public_key(), signature_0());
    let bad = replaced(sig.span(), 31, -1);
    assert!(pk.len() + bad.len() == 89);
}}

#[test]
fn cmp_reject_packing() {{
    let (pk, sig) = (public_key(), signature_0());
    let bad = replaced(sig.span(), 31, -1);
    assert!(pk.len() + bad.len() == 89);
    assert!(!Falcon512ShakeVerifier::verify(message_0(), pk.span(), bad.span()));
}}

#[test]
fn cmp_reject_hint_base() {{
    let (pk, sig) = (public_key(), signature_0());
    let bad = replaced(sig.span(), 31, *sig.at(32));
    assert!(pk.len() + bad.len() == 89);
}}

#[test]
fn cmp_reject_hint() {{
    let (pk, sig) = (public_key(), signature_0());
    let bad = replaced(sig.span(), 31, *sig.at(32));
    assert!(pk.len() + bad.len() == 89);
    assert!(!Falcon512ShakeVerifier::verify(message_0(), pk.span(), bad.span()));
}}

#[test]
fn cmp_reject_message_hint_base() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
}}

#[test]
fn cmp_reject_message_hint() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
    assert!(!Falcon512ShakeVerifier::verify(message_0() + 1, pk.span(), sig.span()));
}}

#[test]
fn cmp_reject_message_direct_base() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
}}

#[test]
fn cmp_reject_message_direct() {{
    let (pk, sig) = (public_key(), signature_0());
    assert!(pk.len() + sig.len() == 89);
    assert!(!Falcon512ShakeDirectVerifier::verify(message_0() + 1, pk.span(), sig.span().slice(0, 31)));
}}
"""

PER_SIGNATURE = """
#[test]
fn cmp_hint_{i}() {{
    let (pk, sig) = (public_key(), signature_{i}());
    assert!(pk.len() + sig.len() == 89);
    assert!(Falcon512ShakeVerifier::verify(message_{i}(), pk.span(), sig.span()));
}}

#[test]
fn cmp_direct_{i}() {{
    let (pk, sig) = (public_key(), signature_{i}());
    assert!(pk.len() + sig.len() == 89);
    assert!(Falcon512ShakeDirectVerifier::verify(message_{i}(), pk.span(), sig.span().slice(0, 31)));
}}

#[test]
fn cmpcheck_other_message_{i}() {{
    let (pk, sig) = (public_key(), signature_{i}());
    assert!(!Falcon512ShakeVerifier::verify(message_{i}() + 1, pk.span(), sig.span()));
    assert!(!Falcon512ShakeDirectVerifier::verify(message_{i}() + 1, pk.span(), sig.span().slice(0, 31)));
}}
"""

VALIDATE_TESTS = """use snforge_std::{{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_signature_global,
    start_cheat_transaction_hash_global,
}};
use starknet::ContractAddress;
use starknet::account::Call;

#[starknet::interface]
trait IAccountValidate<T> {{
    fn __validate__(self: @T, calls: Array<Call>) -> felt252;
}}

{fixtures}
fn setup(name: ByteArray, message: felt252, signature: Span<felt252>) -> ContractAddress {{
    let mut calldata = array![];
    public_key().serialize(ref calldata);
    let (address, _) = declare(name).unwrap().contract_class().deploy(@calldata).unwrap();
    start_cheat_transaction_hash_global(message);
    start_cheat_signature_global(signature);
    address
}}

{cases}
#[test]
fn cmp_validate_rejected_base() {{
    let sig = signature_{low}();
    let _address = setup("Falcon512ShakeAccount", message_{low}() + 1, sig.span());
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
}}

#[test]
#[feature("safe_dispatcher")]
fn cmp_validate_rejected() {{
    let sig = signature_{low}();
    let address = setup("Falcon512ShakeAccount", message_{low}() + 1, sig.span());
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
    let account = IAccountValidateSafeDispatcher {{ contract_address: address }};
    assert!(account.__validate__(calls).is_err());
}}
"""

VALIDATE_CASE = """
#[test]
fn cmp_validate_{variant}_{blocks}_base() {{
    let sig = signature_{i}();
    let _address = setup("{contract}", message_{i}(), sig.span().slice(0, {length}));
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
}}

#[test]
fn cmp_validate_{variant}_{blocks}() {{
    let sig = signature_{i}();
    let address = setup("{contract}", message_{i}(), sig.span().slice(0, {length}));
    let calls: Array<Call> = array![];
    assert!(calls.len() == 0);
    let account = IAccountValidateDispatcher {{ contract_address: address }};
    assert!(account.__validate__(calls) == starknet::VALIDATED);
}}
"""


def fixtures_cairo(data) -> str:
    parts = [compare.cairo_array_fn("public_key", "felt252", data["public_key"], 4)]
    for i, s in enumerate(data["signatures"]):
        parts.append(f"fn message_{i}() -> felt252 {{\n    {s['message_hash']}\n}}\n")
        parts.append(compare.cairo_array_fn(f"signature_{i}", "felt252", s["signature"], 4))
    return "\n".join(parts)


def prepare(root: Path, data) -> None:
    sigs = data["signatures"]
    fixtures = fixtures_cairo(data)
    per_signature = "".join(PER_SIGNATURE.format(i=i) for i in range(len(sigs)))
    compare.write(root / "crates/falcon_512/tests/sweep.cairo",
                  VERIFY_TESTS.format(fixtures=fixtures, per_signature=per_signature))

    by_blocks = {}
    for i, s in enumerate(sigs):
        by_blocks.setdefault(s["blocks"], i)
    low = by_blocks[min(by_blocks)]
    cases = "".join(
        VALIDATE_CASE.format(variant=variant, blocks=blocks, i=i, contract=contract, length=length)
        for blocks, i in sorted(by_blocks.items())
        for variant, contract, length in (("hint", "Falcon512ShakeAccount", 60),
                                          ("direct", "Falcon512ShakeDirectAccount", 31))
    )
    accounts = root / "pq-accounts/contracts"
    compare.write(accounts / "tests/sweep_validate.cairo",
                  VALIDATE_TESTS.format(fixtures=fixtures, low=low, cases=cases))
    compare.patch(accounts / "tests/lib.cairo", "mod accounts;\n", "mod accounts;\nmod sweep_validate;\n")


def checkout(keep: bool) -> tuple[Path, str]:
    root = WORK / "ours"
    rev = compare.git("rev-parse", "HEAD")
    if not (keep and root.exists()):
        if root.exists():
            shutil.rmtree(root)
        WORK.mkdir(exist_ok=True)
        compare.git("clone", "--quiet", str(REPO), str(root))
        compare.git("checkout", "--quiet", rev, cwd=root)
    return root, compare.git("rev-parse", "HEAD", cwd=root)


def run(cwd: Path, log: Path, label: str) -> dict:
    code, out = compare.snforge(cwd, "cmpcheck_")
    (log / f"{label}-check.txt").write_text(out)
    failed = re.findall(r"\[FAIL\]\s+[\w:]+::(cmpcheck_\w+)", out)
    if failed or (code != 0 and "cmpcheck_" in out):
        sys.exit(f"{label}: checks failed: {failed or 'build error'} (see {log})")
    _, gas_out = compare.snforge(cwd, "cmp_")
    _, steps_out = compare.snforge(cwd, "cmp_", ["--tracked-resource", "cairo-steps"])
    (log / f"{label}-gas.txt").write_text(gas_out)
    (log / f"{label}-steps.txt").write_text(steps_out)
    failed = re.findall(r"\[FAIL\]\s+[\w:]+::(cmp_\w+)", gas_out)
    if failed:
        sys.exit(f"{label}: measured tests failed: {failed} (see {log})")
    gas, steps = compare.parse(gas_out), compare.parse(steps_out)

    def cost(test, base):
        return {"l2_gas": gas[test]["sierra_gas"] - gas[base]["sierra_gas"],
                "steps": steps[test]["steps"] - steps[base]["steps"]}

    return {"gas": gas, "steps": steps, "cost": cost}


def summarize(values):
    return {"n": len(values), "min": min(values), "median": statistics.median(values), "max": max(values)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generate", action="store_true", help="create a new keypair and signatures")
    parser.add_argument("--falcon-py", type=Path, help="path to a tprest/falcon.py clone (with --generate)")
    parser.add_argument("--count", type=int, default=64)
    parser.add_argument("--keep", action="store_true", help="reuse benchmarks/.work/ours")
    args = parser.parse_args()

    if args.generate:
        if not args.falcon_py:
            sys.exit("--generate needs --falcon-py")
        generate(args.falcon_py, args.count)
        return

    data = json.loads(DATA.read_text())
    for s in data["signatures"]:
        msg, sig = int(s["message_hash"], 16), [int(v, 16) for v in s["signature"]]
        assert blocks_needed(msg, sig[29], sig[30]) == s["blocks"]

    root, rev = checkout(args.keep)
    prepare(root, data)
    log = WORK / "logs"
    log.mkdir(parents=True, exist_ok=True)
    print("measuring verification ...", flush=True)
    verify = run(root / "crates/falcon_512", log, "verify")
    print("measuring __validate__ ...", flush=True)
    validate = run(root / "pq-accounts/contracts", log, "validate")

    per_signature = []
    for i, s in enumerate(data["signatures"]):
        per_signature.append({
            "blocks": s["blocks"],
            "hint": verify["cost"](f"cmp_hint_{i}", "cmp_sig_base"),
            "direct": verify["cost"](f"cmp_direct_{i}", "cmp_sig_base"),
        })
    groups = {}
    for variant in ("hint", "direct"):
        for blocks in sorted({p["blocks"] for p in per_signature}):
            rows = [p[variant] for p in per_signature if p["blocks"] == blocks]
            groups[f"{variant}_{blocks}"] = {
                "l2_gas": summarize([r["l2_gas"] for r in rows]),
                "steps": summarize([r["steps"] for r in rows]),
            }
    validate_costs = {
        t[len("cmp_validate_"):]: validate["cost"](t, t + "_base")
        for t in validate["gas"] if t.startswith("cmp_validate_") and not t.endswith("_base")
    }
    rejection = {
        key: verify["cost"](f"cmp_reject_{key}", f"cmp_reject_{key}_base")
        for key in ("length", "packing", "hint", "message_hint", "message_direct")
    }
    probabilities = block_probabilities()
    result = {
        "metadata": {
            "generated": datetime.date.today().isoformat(),
            "rev": rev,
            "signatures": len(per_signature),
            "block_probabilities": probabilities,
            "method": "paired-test subtraction (cmp_X - base), Scarb/snforge from .tool-versions",
        },
        "per_signature": per_signature,
        "groups": groups,
        "validate": validate_costs,
        "rejection": rejection,
    }
    (HERE / "signatures-results.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"groups": groups, "validate": validate_costs, "rejection": rejection,
                      "probabilities": probabilities}, indent=1))


if __name__ == "__main__":
    main()
