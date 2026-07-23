#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PTAU="${PTAU_FILE:-$ROOT/artifacts/powersOfTau28_hez_final_14.ptau}"
[ -f "$PTAU" ] || { echo "Missing Powers of Tau file: $PTAU" >&2; exit 1; }
mkdir -p "$ROOT/contracts"
for C in afx-1024 secret-knowledge authorization; do
  D="$ROOT/artifacts/$C"
  npx snarkjs groth16 setup "$D/$C.r1cs" "$PTAU" "$D/${C}_0000.zkey"
  npx snarkjs zkey contribute "$D/${C}_0000.zkey" "$D/$C.zkey" --name='AFX-1024 development contribution' -v -e="$(openssl rand -hex 32)"
  npx snarkjs zkey export verificationkey "$D/$C.zkey" "$D/verification_key.json"
  npx snarkjs zkey export solidityverifier "$D/$C.zkey" "$ROOT/contracts/${C//-/_}Verifier.sol"
done
