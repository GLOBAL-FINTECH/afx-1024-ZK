import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FIELD_PRIME,
  assertField,
  hashToField,
  randomField,
  canonicalJSONString,
  buildAuthorizationInput,
  buildSecretKnowledgeInput,
  proveGroth16,
  proofDigest,
  generateKeyPair,
  getPublicKey,
  proveSigma,
  verifySigma
} from '../src/index.js';

test('field hashing is deterministic and domain separated', () => {
  assert.equal(hashToField('hello', 'domain-a'), hashToField('hello', 'domain-a'));
  assert.notEqual(hashToField('hello', 'domain-a'), hashToField('hello', 'domain-b'));
});

test('authorization input hashes message and domain', () => {
  const input = buildAuthorizationInput({
    secret: 123n,
    salt: 456n,
    message: 'transfer 25 SBQ',
    domain: 'sibaq:chain-1990',
    nonce: 789n
  });

  assert.equal(input.secret, '123');
  assert.equal(input.salt, '456');
  assert.equal(input.nonce, '789');
  assert.notEqual(input.messageHash, 'transfer 25 SBQ');
  assert.notEqual(input.domain, 'sibaq:chain-1990');
});

test('secret-knowledge input validates field bounds', () => {
  assert.deepEqual(buildSecretKnowledgeInput({ secret: 1n, salt: 2n, scope: 3n }), {
    secret: '1',
    salt: '2',
    scope: '3'
  });
  assert.throws(() => assertField(FIELD_PRIME), error => error.code === 'INVALID_FIELD');
  assert.throws(() => assertField(-1n), error => error.code === 'INVALID_FIELD');
});

test('random field is valid', () => {
  const value = randomField();
  assert.ok(value > 0n);
  assert.ok(value < FIELD_PRIME);
});

test('canonical JSON sorts object keys', () => {
  assert.equal(canonicalJSONString({ z: 1, a: 2 }), '{"a":2,"z":1}');
});

test('Groth16 refuses missing artifacts instead of fabricating proof', async () => {
  await assert.rejects(
    proveGroth16({
      circuit: 'authorization',
      input: buildAuthorizationInput({
        secret: 1n,
        salt: 2n,
        message: 'test',
        domain: 'test',
        nonce: 3n
      }),
      artifactsDir: './definitely-missing-artifacts'
    }),
    error => error.code === 'ARTIFACT_MISSING'
  );
});

test('proof digest is canonical', () => {
  const bundleA = {
    protocol: 'AFX-1024-GROTH16-BN254-v2',
    circuit: 'authorization',
    proof: { pi_b: ['b'], pi_a: ['a'] },
    publicSignals: ['1', '2']
  };
  const bundleB = {
    publicSignals: ['1', '2'],
    proof: { pi_a: ['a'], pi_b: ['b'] },
    circuit: 'authorization',
    protocol: 'AFX-1024-GROTH16-BN254-v2'
  };
  assert.equal(proofDigest(bundleA), proofDigest(bundleB));
});

test('Sigma key generation and public derivation agree', () => {
  const keyPair = generateKeyPair();
  assert.equal(getPublicKey(keyPair.privateKey), keyPair.publicKey);
});

test('valid Sigma proof verifies', () => {
  const keyPair = generateKeyPair();
  const proof = proveSigma('authorize transfer', keyPair.privateKey, { context: 'sibaq:chain-1990' });
  const result = verifySigma('authorize transfer', proof, { context: 'sibaq:chain-1990' });
  assert.equal(result.ok, true);
  assert.equal(result.code, 'VALID');
});

test('Sigma message tampering fails', () => {
  const keyPair = generateKeyPair();
  const proof = proveSigma('authorize transfer', keyPair.privateKey, { context: 'sibaq:chain-1990' });
  const result = verifySigma('authorize 999 SBQ', proof, { context: 'sibaq:chain-1990' });
  assert.equal(result.ok, false);
});

test('Sigma context tampering fails', () => {
  const keyPair = generateKeyPair();
  const proof = proveSigma('authorize transfer', keyPair.privateKey, { context: 'sibaq:chain-1990' });
  const result = verifySigma('authorize transfer', proof, { context: 'sibaq:chain-1991' });
  assert.deepEqual(result, { ok: false, code: 'CONTEXT_MISMATCH' });
});
