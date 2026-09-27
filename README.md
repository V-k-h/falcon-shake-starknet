# Falcon-512 (SHAKE-256) verifier for Starknet accounts

_A Falcon-512 signature verifier for Starknet account abstraction, using the SHAKE-256
hash-to-point of the Falcon round-3 specification, with deployable SNIP-6 accounts and an
efficiency harness that measures every cost inside a real `__validate__`._

> [!WARNING]
> **Experimental and unaudited.** The verifiers and account contracts have not undergone
> an independent security audit. This software is provided on an “as is” and “as
> available” basis, without warranties or liability for any losses incurred through its
> use.

## Why

Starknet's STARK proofs rely only on hash functions. The ECDSA signatures that authorize
account transactions rely on elliptic-curve discrete logarithms, which Shor's algorithm
breaks. Because Starknet accounts are smart contracts, a post-quantum account can replace
the signature check inside `__validate__`, provided verification fits Starknet's
validation limits. This repository implements that check for Falcon-512 with the SHAKE-256
hash-to-point of the Falcon round-3 specification, so signatures from round-3 Falcon
signers (falcon.py, PQClean, liboqs) verify on-chain once re-encoded into the packed
layout. FN-DSA, the FIPS 206 draft, frames the message differently (it hashes the public
key and a domain separator in with it), so FN-DSA signers such as rust-fn-dsa are not
compatible.

## What is measured

For each verifier, the cost of verifying one signature, both alone and inside a real
`__validate__`: L2 gas, Cairo steps, signature and key size, and contract class size.

Validation is capped at 1,000,000 steps and 100,000,000 L2 gas (blockifier versioned
constants, unchanged from v0.13.4 through Starknet 0.14.4), so a verifier has to fit
under both. The L2 gas figures are Starknet Foundry's Sierra-gas measurements of the
measured call, with a baseline test subtracted. A transaction receipt on a network also
includes protocol overhead and the executed calls, so it is higher than the validate
figure.

## Snapshot

Current efficiency of every measured entry, per crate (the values pinned in
[`efficiency_baseline.json`](efficiency_baseline.json)):

| Crate | Measurement | L2 gas | Steps |
|---|---|--:|--:|
| [`ecdsa_stark`](crates/ecdsa_stark) | verify (classical control) | 30,855 | 152 |
| [`falcon_512`](crates/falcon_512) | verify, SHAKE-256 hint variant | 48,562,818 | 300,277 |
| [`falcon_512`](crates/falcon_512) | verify, SHAKE-256 direct variant | 49,597,508 | 309,496 |
| [`bench_targets`](crates/bench_targets) | ECDSA-STARK account, inside `__validate__` | 160,795 | 1,437 |
| [`bench_targets`](crates/bench_targets) | Falcon-512 SHAKE-256 hint account, inside `__validate__` | 49,288,728 | 307,478 |
| [`bench_targets`](crates/bench_targets) | Falcon-512 SHAKE-256 direct account, inside `__validate__` | 50,272,508 | 316,211 |
| [`ntt`](crates/ntt) | forward 512-point transform | 8,895,740 | 81,826 |
| [`ntt`](crates/ntt) | forward transform, unreduced output | 7,832,270 | 73,587 |
| [`ntt`](crates/ntt) | generated Falcon-512 transform, felt input | 2,137,010 | 15,635 |
| [`ntt`](crates/ntt) | generated Falcon-512 transform, `u16` input | 2,137,010 | 15,635 |
| [`ntt`](crates/ntt) | Falcon-512 inverse via the generated graph | 4,538,050 | 36,641 |
| [`ntt`](crates/ntt) | Falcon-512 product inverse via the generated graph | 4,990,090 | 40,803 |
| [`ntt`](crates/ntt) | forward + inverse roundtrip | 22,725,980 | 211,044 |

ECDSA-STARK is the classical scheme in use today, a cost reference rather than a
post-quantum candidate. The pure-Cairo Keccak-f[1600] behind the SHAKE-256
hash-to-point dominates both Falcon variants. The two variants differ only in how the
polynomial product `s1 * h` is obtained, and both run on the generated Falcon-512
forward graph, so they cost within about 2% of each other; the direct variant needs no
signer-supplied hint and a 31-felt signature instead of 60. See
[`HINT_VS_DIRECT.md`](crates/falcon_512/HINT_VS_DIRECT.md).

## Layout

```
crates/
  bench_interface/   # the PqSignatureVerifier interface plus validation-cap constants
  ecdsa_stark/       # classical control verifier
  falcon_512/        # Falcon-512 verifier: SHAKE-256 hash-to-point, hint and direct variants
  ntt/               # lazy-reduction NTT engine + generated Falcon-512 transform
  bench_targets/     # one benchmark account per verifier, embedding the production account component
pq-accounts/
  contracts/         # deployable SNIP-6 accounts (ECDSA control, Falcon hint, Falcon direct)
scripts/             # benchmarks, efficiency ratchet, NTT model and generator, fixtures
schemes.json         # the scheme registry
efficiency_baseline.json  # the efficiency ratchet (CI-enforced)
results/             # generated benchmark snapshot
```

Crates: [`bench_interface`](crates/bench_interface), [`ecdsa_stark`](crates/ecdsa_stark),
[`falcon_512`](crates/falcon_512), [`ntt`](crates/ntt),
[`bench_targets`](crates/bench_targets). Accounts: [`pq-accounts`](pq-accounts).

## Run

The toolchain is pinned in `.tool-versions` (Scarb 2.18.0, Starknet Foundry 0.59.0,
cairo-profiler 0.16.0). Install it with [asdf](https://asdf-vm.com) or
[starkup](https://github.com/software-mansion/starkup).

```bash
make test       # run the test suite
make check-eff  # efficiency ratchet: fail if any tracked cost regressed
make ratchet    # lock measured improvements into efficiency_baseline.json
make all        # measure, profile, then render results/
python3 scripts/gen_ntt_tables.py && python3 scripts/verify_ntt_constants.py
```

Efficiency is a one-way ratchet: `efficiency_baseline.json` pins the cost of every
tracked benchmark pair (L2 gas and steps), CI fails any change that raises a number,
and improvements are committed via `make ratchet`.

## Method

Every verifier implements the one interface in
[`crates/bench_interface`](crates/bench_interface); each cost is the measured test minus
a baseline test that builds the same inputs but omits the measured call. Bare verify
covers the function alone. The validate scenario deploys an account from
[`crates/bench_targets`](crates/bench_targets), which embeds the deployable accounts'
component and runs its validation path, and calls it, which adds dispatch,
signature deserialization, and a storage read. Numbers come from Starknet Foundry (Sierra
gas from the default run, steps and builtins from a `cairo-steps` run), a release build
(class size), and cairo-profiler (attribution by function).

## References

- Falcon / FN-DSA: [specification](https://falcon-sign.info/falcon.pdf) ·
  [falcon.py](https://github.com/tprest/falcon.py) ·
  [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
- Starknet [fees](https://docs.starknet.io/learn/protocol/fees) ·
  [accounts](https://docs.starknet.io/learn/protocol/accounts)

## License

MIT. See [LICENSE](LICENSE). Derived from OpenZeppelin's
[cairo-pq-verifiers](https://github.com/OpenZeppelin/cairo-pq-verifiers) (MIT).
