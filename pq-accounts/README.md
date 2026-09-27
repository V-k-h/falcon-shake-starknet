# pq-accounts

Deployable Starknet account contracts backed by the verifiers in this repository.

`contracts/src/accounts/` holds one account per verifier scheme: `EcdsaStarkAccount`
(classical control), `Falcon512ShakeAccount` (60-felt hint signature), and
`Falcon512ShakeDirectAccount` (31-felt direct signature). Each implements the account
entrypoints used by Starknet (`__execute__`, `__validate__`, `__validate_declare__`,
`__validate_deploy__`, `is_valid_signature`, `supports_interface`). `contracts/src/utils/`
holds the shared account interfaces, the execution/validation helpers, and the
verifier-generic account component (`PqAccountComponent`) that the Falcon accounts embed:
a concrete account is the component instantiated with its verifier.

The Falcon accounts store the packed NTT-domain public key (29 felts) passed to the
constructor and validate `tx_info.signature` against `tx_info.transaction_hash` with the
standard SHAKE-256 hash-to-point, so any standards-compliant Falcon-512 signer can produce
their signatures. Signing is off-chain; this repository ships no key material.

The benchmark accounts under `crates/bench_targets` remain measurement harnesses. The
contracts here are the accounts intended for on-chain interaction.
