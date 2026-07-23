import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, getPublicKey, prove, verify, proofId } from '../src/sigma.js';

const context = 'chain:1990|contract:0xabc|action:transfer';

test('key generation and public derivation', () => {
  const kp = generateKeyPair();
  assert.equal(kp.privateKey.length, 64);
  assert.equal(getPublicKey(kp.privateKey), kp.publicKey);
});

test('valid proof verifies', () => {
  const kp = generateKeyPair();
  const now = Date.now();
  const p = prove('pay 25 SBQ', kp.privateKey, { context, createdAt: now, ttlMs: 60_000 });
  assert.deepEqual(verify('pay 25 SBQ', p, { context, now }), { ok: true, code: 'VALID', publicKey: p.publicKey, nonce: p.nonce });
  assert.equal(proofId(p).length, 64);
});

test('message tampering fails', () => {
  const kp = generateKeyPair(); const p = prove('A', kp.privateKey, { context });
  assert.equal(verify('B', p, { context }).ok, false);
});

test('context tampering fails', () => {
  const kp = generateKeyPair(); const p = prove('A', kp.privateKey, { context });
  assert.equal(verify('A', p, { context: 'different' }).code, 'CONTEXT_MISMATCH');
});

test('proof field tampering fails', () => {
  const kp = generateKeyPair(); const p = prove('A', kp.privateKey, { context });
  const t = { ...p, response: Buffer.alloc(32, 1).toString('base64url') };
  assert.equal(verify('A', t, { context }).ok, false);
});

test('expired proof fails', () => {
  const kp = generateKeyPair(); const p = prove('A', kp.privateKey, { context, createdAt: 1000, ttlMs: 1000 });
  assert.equal(verify('A', p, { context, now: 500_000, maxClockSkewMs: 0 }).code, 'EXPIRED');
});

test('100 randomized proofs verify', () => {
  for (let i = 0; i < 100; i++) {
    const kp = generateKeyPair(); const msg = `message-${i}-${Math.random()}`;
    const p = prove(msg, kp.privateKey, { context: `ctx-${i}` });
    assert.equal(verify(msg, p, { context: `ctx-${i}` }).ok, true);
  }
});
