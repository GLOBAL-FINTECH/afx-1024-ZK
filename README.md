# AFX-1024 ZK

AFX-1024 is a Node.js zero-knowledge package providing:

- Groth16 zk-SNARK proving and verification adapters for Circom circuits
- An authorization circuit with private secret and salt witnesses
- A secret-knowledge circuit with public commitment and replay-resistant nullifier outputs
- Schnorr/secp256k1 non-interactive proof-of-key-knowledge support
- A CLI for secret generation, proof generation, and verification
- Strict fail-closed artifact handling

## Status

The Node.js package, CLI, Sigma proof engine, circuit source, validation, and tests are implemented. Groth16 proof generation requires compiled circuit artifacts:

```text
artifacts/authorization/authorization_js/authorization.wasm
artifacts/authorization/authorization.r1cs
artifacts/authorization/authorization.zkey
artifacts/authorization/verification_key.json
```

The package never substitutes a fake proof when those files are unavailable.

## Requirements

- Node.js 20 or newer
- npm
- Circom 2.2.3 or newer for circuit compilation
- A verified Powers of Tau transcript for Groth16 setup

## Install

```bash
npm install
npm run check
npm test
```

## CLI

```bash
npx afx1024 secret
```

```bash
npx afx1024 prove-auth \
  --secret "123456789" \
  --salt "987654321" \
  --message "transfer 25 SBQ" \
  --domain "sibaq:chain-1990" \
  --artifacts ./artifacts \
  --out ./proof.json
```

```bash
npx afx1024 verify --proof ./proof.json --artifacts ./artifacts
```

## Compile circuits

```bash
npm run circuit:compile
```

## Groth16 setup

```bash
PTAU_FILE=/secure/path/powersOfTau28_hez_final_14.ptau npm run circuit:setup
PTAU_FILE=/secure/path/powersOfTau28_hez_final_14.ptau npm run circuit:verify
```

A single-party setup is suitable only for development and testnet use. Production use requires a documented multi-party ceremony and independent circuit review.

## Security classification

AFX-1024 is a production-oriented release candidate, not an independently audited custody-grade cryptographic system. Review `SECURITY.md` and `PROTOCOL.md` before integration.
