#!/usr/bin/env python3
"""End-to-end benchmark: real Falcon-signed transactions on a local starknet-devnet.

snforge measures `__validate__` in isolation. This script runs the whole path through
the sequencer's execution engine (blockifier, inside starknet-devnet), where the
protocol's validation limits are enforced:

1. Start a fresh devnet and import its predeployed account into a private accounts
   file under `benchmarks/.work` (never the user's sncast accounts file).
2. Declare and deploy both Falcon accounts with a fresh falcon.py public key, and mint
   them STRK.
3. Build an INVOKE v3 transaction (one STRK transfer) from each Falcon account, compute
   its hash, sign it with falcon.py, and submit it over JSON-RPC.
4. Record the receipt and the trace: fee, the transaction's L2 gas and L1 data gas, and
   the resources of the `__validate__` and `__execute__` invocations.
5. Submit the same transaction with a signature over a different hash, which must be
   rejected, and send the same transfer from the predeployed ECDSA account as a baseline.

The transaction-hash code is checked against a transaction that sncast itself sent, so a
hash bug cannot pass silently.

Usage (needs the toolchain in .tool-versions, including starknet-devnet, and a falcon.py
clone with numpy, pycryptodome and beartype):
    python3 benchmarks/devnet.py --falcon-py /path/to/falcon.py
    # With a devnet built from source with devnet-sierra-version.patch applied:
    python3 benchmarks/devnet.py --falcon-py /path/to/falcon.py \
        --devnet /path/to/patched/starknet-devnet --out benchmarks/devnet-fixed.json
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
WORK = HERE / ".work" / "devnet"
sys.path.insert(0, str(REPO / "scripts"))

import gen_account_fixture  # noqa: E402
import gen_falcon_fixture  # noqa: E402
import gen_shake_h2p_kat  # noqa: E402

PORT = 5055
URL = f"http://127.0.0.1:{PORT}"
STRK = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D
STARK_PRIME = 2**251 + 17 * 2**192 + 1
INVOKE_PREFIX = int.from_bytes(b"invoke", "big")
poseidon = gen_account_fixture.poseidon_hash_span

ACCOUNTS = [
    ("hint", "Falcon512ShakeAccount", 60),
    ("direct", "Falcon512ShakeDirectAccount", 31),
]


def rpc(method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(URL, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        out = json.loads(resp.read())
    if "error" in out:
        raise RuntimeError(json.dumps(out["error"]))
    return out["result"]


def sn_keccak(name: str) -> int:
    from Crypto.Hash import keccak

    digest = keccak.new(digest_bits=256, data=name.encode()).digest()
    return int.from_bytes(digest, "big") & ((1 << 250) - 1)


def resource_bound(name: bytes, bound: dict) -> int:
    return (int.from_bytes(name, "big") << 192) | (int(bound["max_amount"], 16) << 128) | int(bound["max_price_per_unit"], 16)


def da_mode(mode: str) -> int:
    return {"L1": 0, "L2": 1}[mode]


def invoke_v3_hash(tx: dict, chain_id: int) -> int:
    """Transaction hash of an INVOKE v3 transaction, as the protocol computes it."""
    rb = tx["resource_bounds"]
    fee_fields = poseidon([
        int(tx["tip"], 16),
        resource_bound(b"L1_GAS", rb["l1_gas"]),
        resource_bound(b"L2_GAS", rb["l2_gas"]),
        resource_bound(b"L1_DATA", rb["l1_data_gas"]),
    ])
    modes = (da_mode(tx["nonce_data_availability_mode"]) << 32) | da_mode(tx["fee_data_availability_mode"])
    return poseidon([
        INVOKE_PREFIX,
        int(tx["version"], 16),
        int(tx["sender_address"], 16),
        fee_fields,
        poseidon([int(x, 16) for x in tx["paymaster_data"]]),
        chain_id,
        int(tx["nonce"], 16),
        modes,
        poseidon([int(x, 16) for x in tx["account_deployment_data"]]),
        poseidon([int(x, 16) for x in tx["calldata"]]),
    ])


def sncast(*args, cwd=REPO):
    cmd = ["sncast", "--accounts-file", str(WORK / "accounts.json"), "--account", "devnet", "--json", *args, "--url", URL]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:2])} failed:\n{out}")
    return out


def field(output: str, name: str) -> str:
    m = re.search(rf'"{name}"\s*:\s*"(0x[0-9a-fA-F]+)"', output)
    if not m:
        raise RuntimeError(f"no {name} in sncast output:\n{output}")
    return m.group(1)


def start_devnet(binary: str):
    log = open(WORK / "devnet.log", "w")
    proc = subprocess.Popen(
        [binary, "--seed", "0", "--port", str(PORT), "--accounts", "1"],
        cwd=REPO, stdout=log, stderr=subprocess.STDOUT,
    )
    for _ in range(120):
        try:
            rpc("starknet_chainId")
            return proc
        except Exception:
            time.sleep(0.5)
    proc.kill()
    sys.exit("devnet did not start (see benchmarks/.work/devnet/devnet.log)")


def wait_receipt(tx_hash: str) -> dict:
    for _ in range(120):
        try:
            return rpc("starknet_getTransactionReceipt", {"transaction_hash": tx_hash})
        except RuntimeError:
            time.sleep(0.5)
    raise RuntimeError(f"no receipt for {tx_hash}")


def gas_bounds() -> dict:
    block = rpc("starknet_getBlockWithTxHashes", {"block_id": "latest"})

    def bound(amount, price_field):
        return {"max_amount": hex(amount), "max_price_per_unit": hex(2 * int(block[price_field]["price_in_fri"], 16))}

    return {
        "l1_gas": bound(0, "l1_gas_price"),
        "l1_data_gas": bound(4096, "l1_data_gas_price"),
        "l2_gas": bound(400_000_000, "l2_gas_price"),
    }


def transfer_calldata(recipient: int, amount: int) -> list[str]:
    # __execute__(calls: Array<Call>): one call to STRK.transfer(recipient, amount: u256).
    return [hex(v) for v in (1, STRK, sn_keccak("transfer"), 3, recipient, amount, 0)]


def summarize_trace(trace: dict) -> dict:
    out = {}
    for key in ("validate_invocation", "execute_invocation", "fee_transfer_invocation"):
        inv = trace.get(key) or {}
        if "execution_resources" in inv:
            out[key] = inv["execution_resources"]
    out["total"] = trace.get("execution_resources")
    # The legacy (Cairo-steps) model bills VM resources in whole L1 gas units, 40,000 L2 gas
    # each, so a call billed that way reports a non-zero multiple of 40,000. (Devnet reports
    # 0 for calls billed in Sierra gas; only the transaction total is meaningful for those.)
    out["legacy_billing"] = {
        key: res["l2_gas"] > 0 and res["l2_gas"] % 40_000 == 0
        for key, res in out.items() if key != "total" and res
    }
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--falcon-py", type=Path, required=True)
    parser.add_argument("--devnet", default="starknet-devnet", help="starknet-devnet binary to run")
    parser.add_argument("--out", type=Path, default=HERE / "devnet-stock.json")
    args = parser.parse_args()
    if shutil.which(args.devnet) is None:
        sys.exit(f"{args.devnet} not found; install the starknet-devnet version in .tool-versions")

    sys.path.insert(0, str(args.falcon_py))
    import falcon as fpy  # noqa: E402
    from ntt import div_zq, mul_zq, ntt  # noqa: E402

    scheme = fpy.Falcon(512)
    sk, _ = scheme.keygen()
    h = div_zq(sk[1], sk[0])
    h_ntt = ntt(h)
    mods = (scheme, mul_zq, ntt)
    public_key = gen_falcon_fixture.pack_512(h_ntt)

    from signatures import blocks_needed  # noqa: E402

    def sign(message_hash: int, blocks: int | None = None) -> list[int]:
        """Sign `message_hash`, drawing salts until the hash-to-point needs `blocks` blocks."""
        while True:
            salt = os.urandom(40)
            salt_a, salt_b = int.from_bytes(salt[:20], "little"), int.from_bytes(salt[20:], "little")
            if blocks is None or blocks_needed(message_hash, salt_a, salt_b) == blocks:
                break
        point = gen_shake_h2p_kat.hash_to_point(message_hash, salt_a, salt_b)
        signature, pk, _ = gen_falcon_fixture.sign_point(mods, sk, h, h_ntt, point, salt)
        assert pk == public_key
        return signature

    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    devnet = start_devnet(args.devnet)
    try:
        result = run(public_key, sign, args.devnet)
    finally:
        devnet.terminate()
        devnet.wait(timeout=30)
    args.out.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(result, indent=1))


def run(public_key, sign, binary) -> dict:
    chain_id = int(rpc("starknet_chainId"), 16)
    predeployed = rpc("devnet_getPredeployedAccounts")[0]
    subprocess.run(
        ["sncast", "--accounts-file", str(WORK / "accounts.json"), "account", "import", "--name", "devnet",
         "--address", predeployed["address"], "--private-key", predeployed["private_key"], "--type", "oz",
         "--url", URL, "--silent"],
        cwd=REPO, check=True, capture_output=True, text=True,
    )
    recipient = int(predeployed["address"], 16)
    result = {
        "metadata": {
            "generated": datetime.date.today().isoformat(),
            "rev": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip(),
            "devnet": subprocess.run([binary, "--version"], capture_output=True, text=True).stdout.strip(),
            "chain_id": hex(chain_id),
            "gas_prices_fri": {k: v["price_in_fri"] for k, v in rpc("starknet_getBlockWithTxHashes", {"block_id": "latest"}).items()
                               if k.endswith("gas_price")},
        },
        "accounts": {},
    }

    # Baseline: the same transfer from the predeployed ECDSA account, sent by sncast. Its
    # transaction also proves invoke_v3_hash against the protocol's own hash.
    out = sncast("invoke", "--contract-address", hex(STRK), "--function", "transfer",
                 "--calldata", hex(recipient), "1", "0")
    baseline_hash = field(out, "transaction_hash")
    receipt = wait_receipt(baseline_hash)
    tx = rpc("starknet_getTransactionByHash", {"transaction_hash": baseline_hash})
    assert invoke_v3_hash(tx, chain_id) == int(baseline_hash, 16), "invoke_v3_hash disagrees with the protocol"
    result["ecdsa_baseline"] = {
        "transaction_hash": baseline_hash,
        "actual_fee": receipt["actual_fee"],
        "execution_resources": receipt["execution_resources"],
        "trace": summarize_trace(rpc("starknet_traceTransaction", {"transaction_hash": baseline_hash})),
    }

    for variant, contract, sig_len in ACCOUNTS:
        declared = sncast("declare", "--contract-name", contract, "--package", "pq_accounts")
        class_hash = field(declared, "class_hash")
        wait_receipt(field(declared, "transaction_hash"))
        deployed = sncast("deploy", "--class-hash", class_hash, "--constructor-calldata",
                          str(len(public_key)), *[hex(v) for v in public_key])
        address = field(deployed, "contract_address")
        wait_receipt(field(deployed, "transaction_hash"))
        rpc("devnet_mint", {"address": address, "amount": 10**24, "unit": "FRI"})

        def build(nonce):
            return {
                "type": "INVOKE", "version": "0x3", "sender_address": address,
                "calldata": transfer_calldata(recipient, 1), "nonce": nonce,
                "resource_bounds": gas_bounds(), "tip": "0x0", "paymaster_data": [],
                "account_deployment_data": [], "nonce_data_availability_mode": "L1",
                "fee_data_availability_mode": "L1",
            }

        entry = {"class_hash": class_hash, "address": address, "signature_felts": sig_len}

        # A signature over a different hash must be rejected before inclusion.
        nonce = rpc("starknet_getNonce", {"block_id": "latest", "contract_address": address})
        tx = build(nonce)
        tx_hash = invoke_v3_hash(tx, chain_id)
        tx["signature"] = [hex(v) for v in sign((tx_hash + 1) % STARK_PRIME)[:sig_len]]
        try:
            rpc("starknet_addInvokeTransaction", {"invoke_transaction": tx})
            entry["bad_signature"] = "ACCEPTED (unexpected)"
        except RuntimeError as err:
            entry["bad_signature"] = f"rejected: {err}"[:300]
        assert rpc("starknet_getNonce", {"block_id": "latest", "contract_address": address}) == nonce

        # Real transactions, one whose hash-to-point needs 8 blocks and one that needs 9.
        entry["transactions"] = {}
        for blocks in (8, 9):
            nonce = rpc("starknet_getNonce", {"block_id": "latest", "contract_address": address})
            tx = build(nonce)
            tx_hash = invoke_v3_hash(tx, chain_id)
            tx["signature"] = [hex(v) for v in sign(tx_hash, blocks)[:sig_len]]
            sent = rpc("starknet_addInvokeTransaction", {"invoke_transaction": tx})["transaction_hash"]
            assert int(sent, 16) == tx_hash, "devnet hashed the transaction differently"
            receipt = wait_receipt(sent)
            entry["transactions"][str(blocks)] = {
                "transaction_hash": sent,
                "execution_status": receipt["execution_status"],
                "finality_status": receipt["finality_status"],
                "actual_fee": receipt["actual_fee"],
                "execution_resources": receipt["execution_resources"],
                "trace": summarize_trace(rpc("starknet_traceTransaction", {"transaction_hash": sent})),
            }
        result["accounts"][variant] = entry
    return result


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    main()
