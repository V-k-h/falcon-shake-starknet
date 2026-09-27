# Benchmark interface

**Component:** the common verifier interface and the validation-cap constants.
**Status:** no measurable code (trait and constants only).

Defines `PqSignatureVerifier`, the one surface every scheme implements so the harness
can swap and measure them identically:

```cairo
fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool;
fn is_valid_public_key(public_key: Span<felt252>) -> bool;
```

`verify` returns `false`, never panics, for malformed keys or signatures.
`is_valid_public_key` reports whether a key has the exact layout `verify` expects with every
component canonical; accounts call it before storing a key.

It also carries the Starknet validation limits every verifier is judged against
(1,000,000 Cairo steps, 100,000,000 L2 gas) and the per-felt calldata cost constant.

## Current efficiency

Nothing to measure: the crate contains no executable logic, so it has no ratchet entries.
