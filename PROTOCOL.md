# AFX-1024 v2 Protocol

AFX-1024 supports two cryptographically distinct proof systems.

1. **Groth16/BN254**: succinct non-interactive zero-knowledge arguments for Circom R1CS circuits. Private witness values never appear in public signals. The verifier checks only the proof, verification key, and public signals.
2. **Schnorr/secp256k1 NIZK**: proof of knowledge of a discrete logarithm in the random-oracle model. This proves key possession but does not hide the statement or public key.

## Authorization circuit
Private witness: `secret`, `salt`.
Public inputs: `messageHash`, `domain`, `nonce`.
Public outputs: `commitment`, `authorizationTag`, `nullifier`.

The circuit constrains all outputs using Poseidon hashes. The nullifier permits replay prevention without revealing the secret. A verifier must persist consumed `(domain, nullifier)` pairs.

## Trusted setup
Groth16 requires a circuit-specific phase-2 ceremony. The included setup script can produce development keys, but production keys must come from a documented multi-party ceremony. Replacing a zkey changes the verification key and deployed verifier contract.
