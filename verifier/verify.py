#!/usr/bin/env python3
"""
Independent verifier for the dapr-history-anchor worked example.

It trusts NOTHING we say. It:
  1. reads the raw persisted HistorySignature bytes (artifacts/history_signature.bin),
  2. recomputes the chain head = SHA-256(rawSig) itself,
  3. queries a Base mainnet RPC for the AnchorRegistry `Anchored` event whose
     indexed `ref` topic equals that recomputed digest,
  4. PASSES only if an on-chain anchor for exactly that digest exists.

No third-party Python packages: stdlib only (hashlib + urllib). The block hint
in anchor.json only tells the verifier *where* to look — the cryptographic bind
(recomputed digest == on-chain ref) is what proves the claim.

Usage:
    python3 verify.py [--rpc URL] [--artifacts DIR]
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request

ANCHOR_REGISTRY = "0x49fEcA52bC634a9Ab773226D16619deC547794aa"
# keccak256("Anchored(bytes32,address,uint256)")
ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"
DEFAULT_RPC = "https://mainnet.base.org"


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "dapr-history-anchor-verifier/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(f"RPC {method} error: {out['error']}")
    return out["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.environ.get("BASE_RPC", DEFAULT_RPC))
    ap.add_argument("--artifacts", default=os.path.join(os.path.dirname(__file__), "..", "artifacts"))
    args = ap.parse_args()

    art = os.path.abspath(args.artifacts)

    # 1 + 2. recompute the chain head ourselves from the raw persisted bytes.
    with open(os.path.join(art, "history_signature.bin"), "rb") as f:
        raw_sig = f.read()
    digest = hashlib.sha256(raw_sig).hexdigest()
    ref = "0x" + digest
    print(f"raw HistorySignature : {len(raw_sig)} bytes")
    print(f"recomputed head      : {ref}   (SHA-256 of rawSig)")

    # cross-check against the manifest the producer wrote (optional, informational).
    try:
        with open(os.path.join(art, "manifest.json")) as f:
            man = json.load(f)
        if man.get("chain_head_digest_hex") != digest:
            print("WARN: manifest digest disagrees with recomputed digest")
    except FileNotFoundError:
        pass

    # 3. find the on-chain anchor for exactly this ref.
    with open(os.path.join(art, "anchor.json")) as f:
        anchor = json.load(f)
    hint = int(anchor["block"])
    head = int(rpc(args.rpc, "eth_blockNumber", []), 16)
    from_block = hex(max(0, hint - 25))
    to_block = hex(min(hint + 25, head))  # public RPCs reject toBlock beyond head

    # topics = [Anchored, ref]  -> only anchors of *our* recomputed digest match.
    logs = rpc(args.rpc, "eth_getLogs", [{
        "address": ANCHOR_REGISTRY,
        "fromBlock": from_block,
        "toBlock": to_block,
        "topics": [ANCHORED_TOPIC0, ref],
    }])

    if not logs:
        print(f"\nFAIL: no Anchored event for {ref} on AnchorRegistry near block {hint}")
        sys.exit(1)

    log = logs[0]
    ts = int(log["data"], 16)  # single non-indexed arg: uint256 timestamp
    anchored_by = "0x" + log["topics"][2][-40:]
    print(f"\non-chain match       : AnchorRegistry {ANCHOR_REGISTRY} (Base 8453)")
    print(f"  tx                 : {log['transactionHash']}")
    print(f"  block              : {int(log['blockNumber'], 16)}")
    print(f"  anchoredBy         : {anchored_by}")
    print(f"  block timestamp    : {ts}")
    print("\nPASS: the recomputed Dapr history-signature head is anchored on-chain.")


if __name__ == "__main__":
    main()
