# Benchmarks beyond the ratchet

The efficiency ratchet measures one fixed signature in isolation. The two scripts here
measure what that leaves out: how cost varies from one signature to the next, and what
a real transaction costs when it goes through the sequencer's execution engine.

| Script | Make target | Output |
|---|---|---|
| `signatures.py` | `make sweep` | `signatures-results.json` |
| `devnet.py` | `make devnet FALCON_PY=/path/to/falcon.py PYTHON=<python with its deps>` | `devnet-stock.json`; `devnet-fixed.json` with `--devnet` pointing at a patched build |

Both clone or build against this repository's HEAD and use the toolchain in
`.tool-versions`; checkouts and logs go to `benchmarks/.work/` (git-ignored).

## Signature sweep

`signatures.py --generate` makes one fresh keypair with falcon.py and signs 64 random
message hashes with random salts; the public key and signatures are committed in
`data/signatures.json`, so `make sweep` reruns without falcon.py. Every signature is
measured by paired-test subtraction under both verifiers, and a check per signature
confirms that the same signature over a different message is rejected by both.

### Cost depends on the salt, in two clusters

The SHAKE-256 hash-to-point squeezes 136-byte blocks, one Keccak-f[1600] permutation
each, until 512 words below 5q have been accepted. With an acceptance rate of
61445/65536, that takes 8 blocks or 9; 10 or more has probability 7.8e-19, so 9 blocks is
the practical worst case. The probabilities below are exact binomial values.

| Blocks | Probability | Signatures in the sweep | Hint verify | Direct verify | Hint `__validate__` | Direct `__validate__` |
|--:|--:|--:|--:|--:|--:|--:|
| 8 | 40.7% | 28 | 44.51M | 45.55M | 45.26M / 285,352 steps | 46.29M / 294,580 steps |
| 9 | 59.3% | 36 | 48.58M | 49.62M | 49.34M / 307,918 steps | 50.37M / 317,146 steps |
| Expected | | | 46.92M | 47.96M | 47.67M | 48.71M |

Verify cells are medians in L2 gas. Within a cluster the spread is under 0.08M, so one
extra permutation, 4.07M L2 gas and about 22,500 steps, is the whole difference. The
ratchet fixture is a 9-block signature, so the numbers tracked in
`efficiency_baseline.json` are the practical worst case, about 1.7M above the average.

### What a rejected signature costs

Measured on the hint verifier with the same signature, altered:

| Rejection | L2 gas | Steps |
|---|--:|--:|
| Wrong signature length | 0.01M | 97 |
| Non-canonical packed hint | 1.31M | 10,777 |
| Hint that is not `s1 * h` | 41.10M | 247,027 |
| Valid signature over another message (hint) | 48.63M | 300,881 |
| Valid signature over another message (direct) | 49.67M | 310,116 |
| `__validate__` reverting on another message (hint) | 49.37M | 308,265 |

Malformed input is rejected almost for free. Anything well formed has to be hashed and
transformed before it can be rejected, so a failing `__validate__` costs the sequencer
about as much as a passing one; that is the cost the protocol's validation caps bound.

## End-to-end transactions on starknet-devnet

`devnet.py` starts a fresh devnet, declares and deploys both accounts with a new falcon.py
key, then submits a real INVOKE v3 transaction from each: one STRK transfer, its hash
computed in Python and checked against a transaction sncast sent, signed with falcon.py,
and executed by blockifier with the protocol's validation limits in force. It also submits
the same transaction signed over a different hash, which must be rejected, and sends the
same transfer from devnet's predeployed ECDSA account as a baseline.

Run on two devnets: the released starknet-devnet 0.9.0 (the version in `.tool-versions`)
and the same version with `devnet-sierra-version.patch` applied.

### Every transaction validates under the real limits

All eight Falcon transactions succeeded (two accounts, 8- and 9-block salts, two
devnets), every signature over a different hash was rejected with
`Account validation failed`, and the account nonce did not move on rejection. The
Python transaction hash matched the protocol's on every transaction.

### Cost of a real transaction

Whole-transaction L2 gas from the receipt, on the patched devnet, and its price at the
mainnet L2 gas price read on 2026-10-16 (12.44 gwei-fri per L2 gas; the L1 data gas, 192
units per Falcon transaction, adds under 0.00001 STRK):

| Transaction | 8-block salt | 9-block salt |
|---|--:|--:|
| Falcon hint account, one STRK transfer | 46.78M L2 gas, 0.582 STRK | 50.89M L2 gas, 0.633 STRK |
| Falcon direct account, one STRK transfer | 47.70M L2 gas, 0.594 STRK | 51.75M L2 gas, 0.644 STRK |
| Predeployed ECDSA account, same transfer | 1.41M L2 gas, 0.018 STRK | |

A Falcon transaction costs 1.4M to 1.6M L2 gas more than its `__validate__` measured in
snforge: execution, the fee transfer, and the signature itself, at 5,120 L2 gas per felt
(0.31M for the 60-felt hint signature, 0.16M for the 31-felt direct one). The direct
account's shorter signature does not make up for its costlier verification.

### starknet-devnet 0.9.0 bills every declared class in the legacy model

On the released devnet, the same transactions cost 124.5M (8 blocks) and 140.0M
(9 blocks) L2 gas, the same for both accounts. Those are exact multiples of 40,000, and
140.0M is 21,816 bitwise builtins at 0.16 L1 gas each, rounded up to whole L1 gas and
converted at 40,000 L2 gas per L1 gas. That is the legacy Cairo-steps model, which bills
only the most expensive resource under the `vm_resource_fee_cost` weights (0.0025 L1 gas
per step, 0.04 per range check, 0.16 per bitwise); here it is the bitwise builtin used by
Keccak, which is also why hint and direct cost the same there.

The cause is in devnet, not the account. Blockifier bills a class in Sierra gas when its
Sierra version is at least `min_sierra_version_for_sierra_gas` (1.7.0 in every Starknet
0.13.4 to 0.14.5 versioned-constants file). Devnet 0.9.0 takes that version from
`contract_class_version`, the class format version "0.1.0", instead of the Sierra
program header (1.8.0 for these accounts), so every declared class falls back to the
legacy model; the code is unchanged on devnet's main branch. `devnet-sierra-version.patch`
reads the version from the program header with `SierraVersion::extract_from_program`.
With it, the receipts match snforge's Sierra-gas measurements.

Read from blockifier's source, a live network applies the same rule with the correct
version, so these accounts' own `__validate__` should be billed in Sierra gas, as on the
patched devnet; a transaction on Sepolia would confirm it. Under the legacy model the
binding validation limit would be the 1,000,000-step cap, at 31% here, rather than the
100M gas cap, and the fee would be about 2.7 times higher.

### A separately deployed verifier can still be billed the legacy way

Blockifier keeps a nested call in the legacy model once any caller up the stack runs in
it. On Sepolia, falcon-starknet's verifier contract (Sierra 1.8.0) was billed 695.8M L2
gas in exactly that way, a multiple of 40,000, because the account that called it is a
Sierra 1.5.0 class. These accounts verify inside their own `__validate__`, a top-level
call, so they are not exposed to this. A verifier deployed as a library contract and
called from an older account would be.
