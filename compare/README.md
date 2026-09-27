# Comparison with other Cairo Falcon-512 verifiers

`compare/compare.py` (or `make compare`) measures this repository against three other
Cairo Falcon-512 verifiers, each pinned to an exact commit:

| Implementation | What it is |
|---|---|
| this repository | SHAKE-256 hint and direct verifiers with deployable accounts |
| [OpenZeppelin/cairo-pq-verifiers](https://github.com/OpenZeppelin/cairo-pq-verifiers) | the upstream this repository was trimmed from (its SHAKE-256 variants) |
| [feltroidprime/s2morrow](https://github.com/feltroidprime/s2morrow) | a Falcon-512 wallet with a Poseidon hash-to-point and an account preset |
| [V-k-h/falcon-starknet](https://github.com/V-k-h/falcon-starknet) | a standalone verifier with FN-DSA (FIPS 206 draft) message framing |

Measured numbers: [`RESULTS.md`](RESULTS.md). Raw data: [`results.json`](results.json).

## Findings

- **The hash decides the cost.** The SHAKE-256 hash-to-point is 39.0M of this
  repository's 48.6M L2 gas for a hint verify; s2morrow's Poseidon hash-to-point is 0.8M.
  Inside `__validate__` that is 49.3% of the gas cap here against 10.8% for s2morrow,
  which pays for it with a hash that no standard Falcon signer produces.
- **The lattice arithmetic is close across the deployable implementations.** On the same
  signature, the typed hint core (two forward NTTs, the hint check and the norm) costs
  7.34M in s2morrow, 7.69M here and 8.19M upstream. The forward NTTs are within 3% of
  each other; s2morrow's single fused check-and-norm pass is about 0.4M cheaper than the
  separate passes here.
- **The direct variant is where this repository differs most from upstream.** Computing
  the inverse NTT with the generated forward graph halves the typed direct core (9.36M
  against 19.02M), so direct `__validate__` costs 50.3M here against 62.0M upstream, within
  2% of the hint account instead of 20% above it.
- **falcon-starknet cannot run inside `__validate__`.** Its looped NTT costs 32.6M per
  transform (15 times the generated transform here) and its SHAKE-256 hash-to-point 503M
  (13 times), so a full verify needs 581M L2 gas and 4.95M steps, about six times the
  validate gas cap and five times the step cap. It is the only implementation that follows
  the FN-DSA draft's message framing.
- **The public coefficient API pays for its input checks.** `verify_512_with_hint` from
  felt coefficients costs 13.0M here against 11.5M upstream, because it checks all 2048
  inputs are canonical where upstream only documents the precondition. The account path
  does not use this API: it unpacks the packed key and signature, which validates them
  on the way.
- **Every account fits the class-size cap** and builds against Starknet's audited libfunc
  list; only this repository fails its build on a violation.

## Method

1. Each implementation is cloned into `compare/.work/<name>` (git-ignored) at its pinned
   commit. The script adds adapter tests and the smallest changes that let snforge run
   them:
   - the accounts package upstream gets a `[lib]` target and an `snforge_std`
     dev-dependency;
   - s2morrow moves from Scarb 2.15.1 and snforge 0.55.0 to the versions here;
   - in this repository and upstream, the internal `u16` verification cores become `pub`
     so the typed core can be called from a test. That is a visibility change only.

   No other source line changes.
2. Every implementation is built and measured with this repository's `.tool-versions`
   (Scarb 2.18.0, Starknet Foundry 0.59.0), so compiler differences do not leak into the
   comparison.
3. Costs come from paired-test subtraction, as in `scripts/run_bench.py`:
   `cost(K) = cmp_K - cmp_K_base`, where the base test builds the identical inputs and
   skips only the measured call. L2 gas is from a sierra-gas run, steps from a
   cairo-steps run.
4. Every measured test asserts that the signature is accepted. Each adapter also carries
   `cmpcheck_*` tests that tampered inputs are rejected. For this repository and upstream,
   further checks confirm that the shared message point equals the implementation's own
   hash and that the forward NTT matches the Python model. The script exits non-zero if
   any check fails.

## Which rows are like for like

- **Shared inputs** (NTT and lattice-core rows): every implementation verifies the same
  Falcon-512 signature, this repository's SHAKE fixture unpacked to coefficients. Each one
  receives the public key in its own NTT domain, computed in both the measured and the base
  test so it cancels.
  - The *native coefficient type* rows call each implementation's core with the type it
    computes in: `u16` here and upstream, the bounded `Zq` in s2morrow, `felt252` in
    falcon-starknet.
  - The *public API from felts* rows add whatever conversion and validation each public
    entry point performs on felt coefficients. s2morrow has no such entry point.
- **Own inputs** (hash-to-point, full verify, `__validate__`): each implementation uses its
  own hash and its own valid fixture, because the constructions differ:
  - Falcon round-3 framing here and upstream;
  - Poseidon in s2morrow;
  - FN-DSA framing in falcon-starknet. Its input is 135 bytes against 72 here, so its hash
    absorbs two blocks instead of one.
- **`__validate__`** deploys each project's real account contract and calls its
  `__validate__` entry point, with the transaction hash and signature set by cheatcodes.
  falcon-starknet ships a verifier contract, not an account, so it has no row.

## Feature and security comparison

From reading each implementation at its pinned commit, plus the class-size and libfunc
builds above.

| | this repository | upstream | s2morrow | falcon-starknet |
|---|---|---|---|---|
| Hash-to-point | SHAKE-256, round-3 framing | SHAKE-256, round-3 framing | Poseidon, custom | SHAKE-256, FN-DSA framing |
| Off-the-shelf signers | falcon.py, PQClean, liboqs | same | none (its own falcon-rs) | rust-fn-dsa |
| Fits the validate caps | yes | yes | yes | no |
| Verifier variants | hint and direct | hint and direct | hint | hint |
| Public verify API on malformed input | returns `false` | panics on length; `< q` is a documented precondition | panics | panics |
| Public key validated at deploy | yes | no | no | n/a |
| Key rotation | yes, with proof of possession | no | no | n/a |
| Class upgrade | yes, self-call only | no | no | n/a |
| Public key storage | 30 consecutive raw slots | `Vec`, one hashed slot per felt | 29 named slots | n/a |
| Libfunc list in the build | audited, violations fail the build | experimental, warnings only | experimental, warnings only | audited (default), warnings only |

## Caveats

- The s2morrow numbers are for its code compiled with Scarb 2.18.0. Its own pinned
  toolchain is 2.15.1, so its published figures may differ.
- A Poseidon hash-to-point is not interoperable with standard Falcon signers and needs its
  own security argument. Its row shows what a native hash costs; it is not a drop-in
  alternative.
- The FN-DSA framing in falcon-starknet matches the FIPS 206 draft, which this repository
  does not implement. If the final standard keeps that framing, this repository's hash
  needs the same change, at the cost of hashing more input.
- Fully unrolled NTTs are faster but can exceed the contract class-size cap; the
  class-size table in `RESULTS.md` covers the contracts each project actually deploys.
