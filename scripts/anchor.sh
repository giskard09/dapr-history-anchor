#!/usr/bin/env bash
# Anchor a produced Dapr history-chain head into AnchorRegistry on Base mainnet.
# Permissionless anchor(bytes32). Reads the head from artifacts/manifest<suffix>.json.
#
# Usage: anchor.sh [suffix]
#   anchor.sh          -> anchors artifacts/manifest.json      (head A)
#   anchor.sh fork     -> anchors artifacts/manifest_fork.json (head B)
#
# Requires: foundry (cast), and OWNER_PRIVATE_KEY in the environment (never
# committed). The signer address is the anchoredBy recorded on-chain.
set -euo pipefail

REGISTRY="0x49fEcA52bC634a9Ab773226D16619deC547794aa"
RPC="${BASE_RPC:-https://mainnet.base.org}"
ART="$(cd "$(dirname "$0")/.." && pwd)/artifacts"
SUFFIX="${1:+_$1}"
MANIFEST="$ART/manifest${SUFFIX}.json"

REF="$(python3 -c 'import json;print(json.load(open("'"$MANIFEST"'"))["anchor_ref_bytes32"])')"
echo "Manifest:      $MANIFEST"
echo "Anchoring ref: $REF"
echo "Registry:      $REGISTRY (Base mainnet 8453)"

: "${OWNER_PRIVATE_KEY:?set OWNER_PRIVATE_KEY in env}"

cast send "$REGISTRY" "anchor(bytes32)" "$REF" \
  --rpc-url "$RPC" \
  --private-key "$OWNER_PRIVATE_KEY" \
  --json
