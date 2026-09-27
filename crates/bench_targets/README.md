# Benchmark accounts

**Component:** the account harness for the in-`__validate__` scenario: one deployable
account contract per verifier.
**Status:** measured (ECDSA-STARK control and both Falcon-512 SHAKE-256 variants).

Unlike the verifier crates (one scheme each), this crate collects **one account contract
per verifier**, each in its own module. An account wraps its scheme the way a Starknet
account would: `validate()` reads the transaction hash and signature from the transaction
info, loads the stored public key, and runs the scheme's `verify`. Measuring a
deploy-and-call of it (minus a deploy-only baseline) captures the realistic validation
cost (dispatch, signature deserialization, and the key's storage read) on top of bare
verification, and building the contracts yields each scheme's contract-class size.

All accounts expose the same `IValidateBench` interface, defined at the crate root.

```
src/
  lib.cairo          # IValidateBench + one module per verifier account
  ecdsa_stark.cairo  # EcdsaStarkAccount (classical control)
  falcon_512.cairo   # Falcon512ShakeAccount (hint) + Falcon512ShakeDirectAccount (direct)
```

## Current efficiency

One row per verifier account. The 100M-L2-gas / 1M-step validation cap is the
deployability threshold. These are Starknet Foundry Sierra-gas measurements of the
validate call; whole-transaction receipts on a network also include protocol overhead
and the executed calls.

| Account | Measurement | L2 gas | Steps |
|---|---|--:|--:|
| `EcdsaStarkAccount` | inside `__validate__` | 160,795 | 1,437 |
| `Falcon512ShakeAccount` (hint) | inside `__validate__` | 51,733,728 | 327,157 |
| `Falcon512ShakeDirectAccount` (direct) | inside `__validate__` | 52,215,288 | 332,279 |
