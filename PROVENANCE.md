# Provenance — read this before drawing any conclusion

This document states exactly what is real and what is synthetic in this worked
example. Hard honesty is the point: the artifact is worthless if its provenance
is fuzzy.

## What is byte-exact and real

- The `HistorySignature` in `artifacts/history_signature.bin` is produced by
  **Dapr's own code**: `github.com/dapr/durabletask-go@v0.12.1`
  `backend/historysigning.Sign()`, with events marshaled by that package's
  `MarshalEvent` and serialized by its deterministic protobuf marshaler.
- The chain head we anchor is computed by Dapr's own
  `historysigning.SignatureDigest(rawSig) = SHA-256(rawSig)`, over the exact
  persisted bytes — never re-marshaled (as Dapr's code explicitly warns).
- The signature is a real Ed25519 signature over the real
  `SHA-256(previousSignatureDigest || eventsDigest)` input, and it re-verifies
  with Dapr's own `historysigning.VerifySignature()` (see `cmd/verifyformat`).
- The on-chain anchor is a real transaction on Base mainnet; the tx hash and
  block in `artifacts/anchor.json` are independently checkable by anyone.

## What is synthetic — declared

- **The SPIFFE identity is ours, minted locally.** The signing SVID is a
  self-issued X.509 leaf in trust domain `spiffe://mycelium.demo`, generated
  inside `cmd/produce`. It is **not** issued by a Dapr SPIRE control plane.
- **The workflow events are synthetic.** A two-event `OrderWorkflow`
  (ExecutionStarted → ExecutionCompleted) constructed in-process, not emitted
  by a running Dapr workflow.
- **Nothing was captured from a live Dapr cluster.** This is a worked example
  exercising Dapr's signing library directly, not a recording of production
  Dapr output.

## What this therefore does and does not show

- **Does show:** the anchoring layer works against Dapr's *actual public
  format*. Given any real Dapr `HistorySignature` (from a real SPIRE-issued
  identity, from a real workflow), the exact same path — `SHA-256(rawSig)` →
  `anchor(bytes32)` — applies unchanged. The integration is format-level and
  format-agnostic.
- **Does not show:** that Dapr, Diagrid, or anyone else has integrated,
  endorsed, or adopted this. It is our worked example anchoring their public
  format. No claim of "Dapr integrated us", no "on-chain adoption", no cited
  quote. If someone reads it as adoption, that reading is wrong.
