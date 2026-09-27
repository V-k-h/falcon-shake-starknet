#!/usr/bin/env python3
"""Generate the account-contract test fixture for pq-accounts.

Writes pq-accounts/contracts/tests/fixtures.cairo: a second genuine Falcon-512 keypair
(tprest/falcon.py NTRU keygen) together with two standards-compliant SHAKE-256
signatures by it, each re-checked against the exact on-chain verification equation:

- a signature of the bench message hash, used to validate transactions after a key
  rotation;
- a signature of the account's public-key rotation hash for rotating from the bench key
  (crates/falcon_512/src/fixtures/shake.cairo) to the new key, at the fixed chain id and
  account address the tests use.

The rotation hash is computed here with a vendored Starknet Poseidon (checked against
core::poseidon's known-answer vector at run time); the Cairo tests assert it equals the
account's own `get_public_key_rotation_hash`.

Usage:
    python3 scripts/gen_account_fixture.py --falcon-py /path/to/falcon.py-clone
Dependencies (for falcon.py): numpy, pycryptodome, beartype.
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_falcon_fixture import MSG_LABEL, sign_point  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BENCH_FIXTURE = REPO / "crates/falcon_512/src/fixtures/shake.cairo"
OUT = REPO / "pq-accounts/contracts/tests/fixtures.cairo"

STARK_PRIME = 2**251 + 17 * 2**192 + 1
CHAIN_ID = int.from_bytes(b"SN_MAIN", "big")
ACCOUNT_ADDRESS = 0x0501_5a1c_0ffe_e5a1_7ed0
ROTATION_DOMAIN = int.from_bytes(b"PQ_ACCOUNT_SET_PUBLIC_KEY", "big")

# Starknet Poseidon (hades_permutation over the STARK field), vendored to match
# core::poseidon: round constants are sha256("Hades" + idx), the MDS is the small matrix,
# and the schedule is 4 full + 83 partial + 4 full rounds.
POSEIDON_MDS = ((3, 1, 1), (1, -1, 1), (1, 1, -2))
POSEIDON_R_F, POSEIDON_R_P = 8, 83
POSEIDON_KAT = 0xFA8C9B6742B6176139365833D001E30E932A9BF7456D009B1B174F36D558C5


def _hades_ark(idx: int) -> int:
    return int(hashlib.sha256(f"Hades{idx}".encode()).hexdigest(), 16) % STARK_PRIME


def hades_permutation(s0: int, s1: int, s2: int) -> tuple[int, int, int]:
    st = [s0 % STARK_PRIME, s1 % STARK_PRIME, s2 % STARK_PRIME]
    ridx = 0
    for rounds, full in ((POSEIDON_R_F // 2, True), (POSEIDON_R_P, False), (POSEIDON_R_F // 2, True)):
        for _ in range(rounds):
            st = [(st[j] + _hades_ark(3 * ridx + j)) % STARK_PRIME for j in range(3)]
            if full:
                st = [pow(x, 3, STARK_PRIME) for x in st]
            else:
                st[2] = pow(st[2], 3, STARK_PRIME)
            st = [sum(POSEIDON_MDS[i][k] * st[k] for k in range(3)) % STARK_PRIME for i in range(3)]
            ridx += 1
    return st[0], st[1], st[2]


def poseidon_hash_span(values: list[int]) -> int:
    """core::poseidon::poseidon_hash_span: absorb pairs into (s0, s1), then pad with a 1."""
    s0, s1, s2 = 0, 0, 0
    i = 0
    while i + 1 < len(values):
        s0, s1, s2 = hades_permutation(s0 + values[i], s1 + values[i + 1], s2)
        i += 2
    if i < len(values):
        return hades_permutation(s0 + values[i], s1 + 1, s2)[0]
    return hades_permutation(s0 + 1, s1, s2)[0]


def bench_public_key() -> list[int]:
    src = BENCH_FIXTURE.read_text()
    block = src[src.index("pub fn public_key"):src.index("pub fn signature")]
    felts = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", block)]
    assert len(felts) == 29
    return felts


def felt_lines(felts: list[int]) -> str:
    return "\n".join(f"        {hex(v)}," for v in felts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--falcon-py", type=Path, required=True,
                        help="path to a github.com/tprest/falcon.py clone")
    args = parser.parse_args()

    assert hades_permutation(1, 2, 3)[0] == POSEIDON_KAT, "Poseidon does not match core"

    sys.path.insert(0, str(args.falcon_py))
    import falcon as fpy  # noqa: E402
    from ntt import div_zq, mul_zq, ntt  # noqa: E402

    scheme = fpy.Falcon(512)
    print("keygen (NTRU solve, may take a while)...")
    sk, _vk = scheme.keygen()
    f, g, _F, _G, _B0, _T = sk
    h = div_zq(g, f)
    h_ntt = ntt(h)
    mods = (scheme, mul_zq, ntt)

    old_key = bench_public_key()
    message_hash = int.from_bytes(MSG_LABEL.encode(), "big")

    def sign(message: int) -> tuple[list[int], list[int]]:
        salt = os.urandom(40)
        point = scheme.__hash_to_point__(message.to_bytes(32, "little"), salt)
        signature, pk_felts, _norm = sign_point(mods, sk, h, h_ntt, point, salt)
        return signature, pk_felts

    msg_signature, new_key = sign(message_hash)
    rotation_hash = poseidon_hash_span([
        ROTATION_DOMAIN, CHAIN_ID, ACCOUNT_ADDRESS,
        poseidon_hash_span(old_key), poseidon_hash_span(new_key),
    ])
    rotation_proof, again = sign(rotation_hash)
    assert again == new_key

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(f'''//! GENERATED by `scripts/gen_account_fixture.py` — do not edit by hand.
//!
//! A second genuine Falcon-512 keypair (tprest/falcon.py) for the account tests, with
//! standards-compliant SHAKE-256 signatures by it of the bench message hash and of the
//! rotation hash from the bench key to this key at [`CHAIN_ID`] and [`ACCOUNT_ADDRESS`].
//! Signatures use the 60-felt hint layout; the first 31 felts are the direct layout.

/// Chain id the rotation hash binds ('SN_MAIN').
pub const CHAIN_ID: felt252 = {hex(CHAIN_ID)};

/// Address the tests deploy the account at; the rotation hash binds it.
pub const ACCOUNT_ADDRESS: felt252 = {hex(ACCOUNT_ADDRESS)};

/// Rotation hash from the bench key to [`new_public_key`] at [`CHAIN_ID`] and
/// [`ACCOUNT_ADDRESS`], computed off-chain with Starknet Poseidon.
pub const ROTATION_HASH: felt252 = {hex(rotation_hash)};

/// Packed NTT-domain public key of the second keypair (29 felts).
pub fn new_public_key() -> Array<felt252> {{
    array![
{felt_lines(new_key)}
    ]
}}

/// Signature by the second key of the bench message hash ('{MSG_LABEL}').
pub fn new_key_signature() -> Array<felt252> {{
    array![
{felt_lines(msg_signature)}
    ]
}}

/// Signature by the second key of [`ROTATION_HASH`].
pub fn rotation_proof() -> Array<felt252> {{
    array![
{felt_lines(rotation_proof)}
    ]
}}
''')
    subprocess.run(["scarb", "fmt", str(OUT)], cwd=REPO, check=True)
    print(f"wrote {OUT.relative_to(REPO)}")


if __name__ == "__main__":
    main()
