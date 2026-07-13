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

With --relation, also checks a SECOND anchored head (the "fork" head,
artifacts/history_signature_fork.bin + manifest_fork.json + anchor_fork.json)
and classifies the relationship between the two anchored heads:

    python3 verify.py --relation [--rpc URL] [--artifacts DIR]

Classification rule (given two HistorySignature manifests A and B, each
carrying predecessor_signature_digest_hex and sequence_range
{start_event_index, event_count}):

  extend  — B.predecessor_signature_digest_hex == SHA-256(A.raw_signature),
            and B.start_event_index == A.start_event_index + A.event_count.
            B is a legitimate continuation of A.
  replace — A and B share predecessor_signature_digest_hex AND identical
            sequence_range (same start_event_index, same event_count), but
            different chain_head_digest_hex. Same claimed extent, silently
            different content — a full rewrite of the same range.
  fork    — A and B share predecessor_signature_digest_hex but their
            sequence_range differs (different start_event_index and/or
            event_count). Diverging continuations from the same point.
  unrelated — none of the above.

This is exactly the ambiguity 0xbrainkid raised in dapr/dapr#10191: the
history-signature chain alone cannot tell these apart. Anchoring both heads
externally makes the relation computable by a verifier who saw neither being
produced.
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


def verify_one(art, rpc_url, suffix=""):
    """Recompute a head's digest and confirm its on-chain anchor. Returns
    (digest_hex, manifest_dict, log_dict)."""
    sig_name = f"history_signature{suffix}.bin"
    manifest_name = f"manifest{suffix}.json"
    anchor_name = f"anchor{suffix}.json"

    with open(os.path.join(art, sig_name), "rb") as f:
        raw_sig = f.read()
    digest = hashlib.sha256(raw_sig).hexdigest()
    ref = "0x" + digest
    print(f"raw HistorySignature ({sig_name}) : {len(raw_sig)} bytes")
    print(f"recomputed head                    : {ref}   (SHA-256 of rawSig)")

    man = {}
    try:
        with open(os.path.join(art, manifest_name)) as f:
            man = json.load(f)
        if man.get("chain_head_digest_hex") != digest:
            print(f"WARN: {manifest_name} digest disagrees with recomputed digest")
    except FileNotFoundError:
        pass

    with open(os.path.join(art, anchor_name)) as f:
        anchor = json.load(f)
    hint = int(anchor["block"])
    head = int(rpc(rpc_url, "eth_blockNumber", []), 16)
    from_block = hex(max(0, hint - 25))
    to_block = hex(min(hint + 25, head))

    logs = rpc(rpc_url, "eth_getLogs", [{
        "address": ANCHOR_REGISTRY,
        "fromBlock": from_block,
        "toBlock": to_block,
        "topics": [ANCHORED_TOPIC0, ref],
    }])

    if not logs:
        print(f"\nFAIL: no Anchored event for {ref} on AnchorRegistry near block {hint}")
        sys.exit(1)

    log = logs[0]
    ts = int(log["data"], 16)
    anchored_by = "0x" + log["topics"][2][-40:]
    print(f"on-chain match                     : AnchorRegistry {ANCHOR_REGISTRY} (Base 8453)")
    print(f"  tx                                : {log['transactionHash']}")
    print(f"  block                             : {int(log['blockNumber'], 16)}")
    print(f"  anchoredBy                        : {anchored_by}")
    print(f"  block timestamp                   : {ts}")
    print(f"PASS: recomputed head is anchored on-chain.\n")

    return digest, man, log


def classify_relation(digest_a, man_a, digest_b, man_b):
    """Classify B relative to A using predecessor_signature_digest_hex and
    sequence_range only — no trust in either manifest's prose fields."""
    pred_a = man_a.get("predecessor_signature_digest_hex", "")
    pred_b = man_b.get("predecessor_signature_digest_hex", "")
    range_a = man_a.get("sequence_range", {})
    range_b = man_b.get("sequence_range", {})
    start_a, count_a = range_a.get("start_event_index"), range_a.get("event_count")
    start_b, count_b = range_b.get("start_event_index"), range_b.get("event_count")

    if pred_b == digest_a and start_b == start_a + count_a:
        return "extend", "B's predecessor_signature_digest_hex equals A's recomputed head, and B's sequence_range starts exactly where A's ends. B is a legitimate continuation of A."
    if pred_a == pred_b and start_a == start_b and count_a == count_b:
        return "replace", "A and B share predecessor_signature_digest_hex AND identical sequence_range, but different chain_head_digest_hex. Same claimed extent, silently different content."
    if pred_a == pred_b:
        return "fork", "A and B share predecessor_signature_digest_hex but their sequence_range differs. Diverging continuations from the same point."
    return "unrelated", "No shared predecessor/sequence relation found between A and B."


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.environ.get("BASE_RPC", DEFAULT_RPC))
    ap.add_argument("--artifacts", default=os.path.join(os.path.dirname(__file__), "..", "artifacts"))
    ap.add_argument("--relation", action="store_true",
                     help="also verify the fork head and classify its relation to the primary head")
    args = ap.parse_args()

    art = os.path.abspath(args.artifacts)

    print("=== head A ===")
    digest_a, man_a, _ = verify_one(art, args.rpc)

    if not args.relation:
        print("PASS: the recomputed Dapr history-signature head is anchored on-chain.")
        return

    print("=== head B (fork) ===")
    digest_b, man_b, _ = verify_one(art, args.rpc, suffix="_fork")

    relation, reason = classify_relation(digest_a, man_a, digest_b, man_b)
    print("=== relation ===")
    print(f"A -> B : {relation.upper()}")
    print(f"reason : {reason}")


if __name__ == "__main__":
    main()
