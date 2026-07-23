#!/usr/bin/env bash
set -euo pipefail
command -v circom >/dev/null || { echo 'circom 2.2.3+ is required' >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for C in afx-1024 secret-knowledge authorization; do
  OUT="$ROOT/artifacts/$C"; mkdir -p "$OUT"
  circom "$ROOT/circuits/$C.circom" --r1cs --wasm --sym --O2 -l "$ROOT/node_modules" -o "$OUT"
  npx snarkjs r1cs info "$OUT/$C.r1cs"
done
