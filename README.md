# dapr-history-anchor

A worked example that anchors the head of a **Dapr Verifiable Execution**
signed history-chain into a permissionless on-chain registry — giving it a
property the design does not have on its own: **external, operator-independent
finality** (rewind-proof, timestamped outside the operator's control).

The timestamp of the anchor is the point. This is not outreach and not a claim
of adoption — it is a worked example, byte-exact against Dapr's public format.

> **Provenance, up front (read `PROVENANCE.md` for the full statement).**
> The `HistorySignature` here is produced by **Dapr's own signing library**
> (`durabletask-go` v0.12.1 `historysigning` + `dapr/kit` signer) — so its wire
> format and digest are byte-exact to what Dapr produces. But it was **NOT
> produced by a running Dapr runtime**: no SPIRE control plane, no state store,
> no workflow engine. The SPIFFE identity is minted locally (not SPIRE-issued)
> and the workflow events are synthetic. Nothing here — on-chain or in this
> repo — implies that Dapr, Diagrid, or anyone else integrated, endorsed, or
> participated. It is our worked example anchoring their public format.
> (`durabletask-go` v0.12.1 is the version this example builds against; we do
> not assert which Dapr release ships it.)

## The seam

Dapr's workflow history signing (`durabletask-go/backend/historysigning`,
v0.12.1) produces a hash-chain of `HistorySignature` messages. Each links to the previous
via `previousSignatureDigest = SHA-256(previous raw HistorySignature)`. This is
strong **internal** tamper-evidence: you cannot alter a past event without
breaking every subsequent link.

What it does **not** give you: external finality. The chain head lives entirely
inside the operator's state store. A compromised or coerced operator can rewind
to an earlier head and re-sign a shorter or alternate history — with valid
signatures the whole way — and nothing *outside* Dapr attests that the original
head ever existed at a given time.

Anchoring the head closes that seam. We take the chain head
(`SignatureDigest` of the latest `HistorySignature`) and place it, as a
`bytes32`, into a permissionless registry on a public chain the operator does
not control. Now "this history head existed at time T" is a fact anyone can
check, and a silent rewind becomes externally detectable.

```
   Dapr operator's state store                 public chain (Base)
   ┌───────────────────────────┐               ┌────────────────────────┐
   │ HistorySignature chain     │  SHA-256      │ AnchorRegistry         │
   │  sig0 ← sig1 ← sig2 (head) │ ─────────────▶│  anchor(bytes32 head)  │
   │  internal tamper-evidence  │   the head    │  Anchored(ref,by,time) │
   └───────────────────────────┘               └────────────────────────┘
        no external finality                     operator-independent
                                                 timestamp / finality
```

## Fork / rewind detection

`dapr/dapr#10191` raised a real gap: if an operator exports two signed heads
for the same workflow instance, a verifier needs more than the head digest to
decide whether the second head **extends**, **forks from**, or **replaces**
the first (the rewind / continue-as-new / compaction case). The
`previousSignatureDigest` Dapr already embeds in every `HistorySignature`
answers this — but this repo didn't expose it as a first-class, checkable
field, and didn't demonstrate the scenario.

Both are fixed now:

- `manifest.json` and `manifest_fork.json` expose
  `predecessor_signature_digest_hex` (empty string for a root/genesis
  signature) and `sequence_range` (`start_event_index`, `event_count`) as
  top-level fields, taken directly from the persisted `HistorySignature`.
- `manifest_fork.json` is a **second, sibling head**: same predecessor claim
  as `manifest.json` (genesis — no predecessor) and the same `sequence_range`
  (start 0, 2 events), same genesis event (`ExecutionStarted`), but a
  rewritten terminal event — `COMPLETED`/"shipped" (head A) vs.
  `FAILED`/"payment declined" (head B). Both are independently valid,
  self-verifying Dapr `HistorySignature`s (see `cmd/verifyformat`). A
  verifier who only has the two heads cannot tell which is the "true" outcome
  from the signature chain alone.
- `verifier/verify.py --relation` recomputes both heads from the raw
  persisted bytes, confirms each is anchored on-chain, and classifies the
  relation between them using only `predecessor_signature_digest_hex` +
  `sequence_range`:
  - **extend** — B's predecessor equals A's head and B's range starts where
    A's ends (legitimate continuation).
  - **replace** — same predecessor and identical range, different head
    (silent full rewrite of the same extent).
  - **fork** — same predecessor, different range (diverging continuations
    from the same point).

  For this repo's committed pair, the classification is **replace**.
- `scripts/anchor.sh fork` anchors head B the same way head A was anchored
  (same `AnchorRegistry`, same `anchor(bytes32)`, second real transaction).

## Doctrine: format-agnostic anchoring

We anchor Dapr's digest **bytes32 as-is**. We do **not** ask Dapr to adopt any
of our formats (no `action_ref`, no envelope, no schema change). The integration
lives entirely in the anchoring layer. Dapr's format is the input; the anchor is
the added property.

## What's here

| Path | What it is |
|------|-----------|
| `cmd/produce/` | Produces a `HistorySignature` using **Dapr's own** `historysigning.Sign()` and emits the chain head to anchor. |
| `cmd/verifyformat/` | Re-runs Dapr's `historysigning.VerifySignature()` — proves the anchored ref is the head of a *valid* Dapr signature, not arbitrary bytes. |
| `verifier/verify.py` | Independent (stdlib-only) verifier: recomputes `SHA-256(rawSig)` and confirms the matching `Anchored` event on Base mainnet. |
| `artifacts/` | The canonical instance: persisted `HistorySignature`, event bytes, signing cert, `manifest.json`, and `anchor.json` (tx/block). |
| `scripts/anchor.sh` | The exact `cast` command used to anchor the head. |
| `PROVENANCE.md` | Exactly what is and isn't real about this artifact. Read it. |

## Reproduce

```bash
# 1. produce head A (loaded as-is if artifacts/ already has a committed
#    instance — never re-minted, to stay byte-identical to what's anchored)
#    and head B, the fork (always freshly minted)
go run ./cmd/produce ./artifacts

# 2. prove each artifact is a valid Dapr history signature
go run ./cmd/verifyformat ./artifacts        # head A
go run ./cmd/verifyformat ./artifacts fork   # head B

# 3. anchor each head on Base mainnet (see scripts/anchor.sh)
scripts/anchor.sh        # head A
scripts/anchor.sh fork   # head B

# 4. independently verify both on-chain anchors and their relation
python3 verifier/verify.py --relation
```

Each `produce` run mints a fresh Ed25519 signing key and current timestamps, so
the raw bytes and head digest differ per run — exactly as they would with real
SPIRE-issued SVIDs. The committed `artifacts/` are the specific instance that is
anchored on-chain; the verifiers check *that* instance.

## The anchor

- **Registry:** `0x49fEcA52bC634a9Ab773226D16619deC547794aa` (same CREATE2
  address on Base 8453, Arbitrum One 42161, Ink 57073).
- **Function:** `anchor(bytes32 ref)` — permissionless, no owner/roles/funds.
- **Event:** `Anchored(bytes32 indexed ref, address indexed anchoredBy, uint256 timestamp)`.
- The anchored `ref` for this instance and its tx/block are in
  `artifacts/anchor.json`. Head B's (the fork) are in `artifacts/anchor_fork.json`.

## Licenses

This repo is MIT. It depends on `github.com/dapr/durabletask-go` and
`github.com/dapr/kit` (both Apache-2.0) as unmodified upstream modules.
