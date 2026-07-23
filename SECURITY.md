# Security

## Status
AFX-1024 v2 contains real zero-knowledge circuit definitions and strict Node.js proof/verification adapters. It is not independently audited. Do not describe it as custody-grade or consensus-critical until the circuits, ceremony, dependencies, and integration have been audited.

## Mandatory production controls
- Pin and verify Circom, circomlib, and snarkjs versions and checksums.
- Conduct a public multi-party phase-2 ceremony for every Groth16 circuit.
- Publish R1CS, zkey, verification key, Solidity verifier, and SHA-256 manifest.
- Reject unknown circuit IDs, protocols, malformed public signals, and artifact fingerprints.
- Store nullifiers atomically to prevent replay and race conditions.
- Keep witnesses out of logs, telemetry, crash reports, shell history, and analytics.
- Use isolated proving workers with resource limits and zeroize secret buffers where practical.
- Audit application semantics: a mathematically valid proof can still prove the wrong business statement.

Report vulnerabilities privately to the repository security contact once configured.
