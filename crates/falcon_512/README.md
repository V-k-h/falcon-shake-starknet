# Falcon-512 verifier

**Scheme:** Falcon-512 (FN-DSA), lattice-based (NTRU); NIST-selected, FIPS 206 pending.
Two verifier variants over the standard SHAKE-256 hash-to-point: hint and direct.
**Status:** measured.

Verification is integer-only and runs fully on-chain: the standard SHAKE-256
hash-to-point binds the message, the product `s1*h` over q = 12289 is checked or computed
with the shared [`ntt`](../ntt) crate, and a centered norm bound decides acceptance.
Canonical base-Q packing is validated while decoding directly to the verifier's `u16`
representation. Both variants share the 29-felt NTT-domain public key:

- **hint** (`Falcon512ShakeVerifier`): two generated forward transforms check a
  signer-supplied `s1*h` pointwise, then a fused pass accumulates the centered norm. The
  signature is 60 felts (`s1 || salt || mul_hint`).
- **direct** (`Falcon512ShakeDirectVerifier`): `s1*h` is computed on-chain from `s1` and
  the NTT-domain key alone, with one generated forward transform of `s1` and the
  forward-graph inverse `intt_product_falcon512_fast_u16`. The signature is the 31-felt
  `s1 || salt` prefix of the hint signature, so it carries nothing beyond a bare Falcon
  signature.

The SHAKE-256 hash-to-point is interoperable with any standards-compliant Falcon signer
(e.g. falcon.py). Its pure-Cairo Keccak-f[1600] (flat unrolled rounds over u128 lanes,
lazy block squeezing; see `src/hashing/shake256.cairo`) dominates the verification cost.
The hint/direct distinction is explained in [`HINT_VS_DIRECT.md`](HINT_VS_DIRECT.md).

The bench fixture is a genuine signature from the reference falcon.py sampler
(`scripts/gen_falcon_fixture.py`); tampered messages, salts, signatures, and lengths are
rejected in tests.

Implements `PqSignatureVerifier`.
References: [Falcon spec](https://falcon-sign.info/falcon.pdf) ·
[falcon.py](https://github.com/tprest/falcon.py).

## Current efficiency

| Measurement | L2 gas | Steps |
|---|--:|--:|
| verify, SHAKE-256 hint variant | 50,163,668 | 312,892 |
| verify, SHAKE-256 direct variant | 50,696,138 | 318,500 |
