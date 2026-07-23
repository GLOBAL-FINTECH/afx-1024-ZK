#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for C in secret-knowledge authorization; do
  D="$ROOT/artifacts/$C"
  npx snarkjs zkey verify "$D/$C.r1cs" "${PTAU_FILE:-$ROOT/artifacts/powersOfTau28_hez_final_14.ptau}" "$D/$C.zkey"
done
