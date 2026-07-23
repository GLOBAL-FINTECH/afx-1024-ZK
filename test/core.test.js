import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthorizationInput, buildSecretKnowledgeInput, hashToField, proofDigest, randomField, proveGroth16 } from '../src/index.js';

test('field hashing is deterministic and domain separated', () => {
  assert.equal(hashToField('x','a'), hashToField('x','a'));
  assert.notEqual(hashToField('x','a'), hashToField('x','b'));
});
test('authorization inputs hide raw message and domain', () => {
  const i = buildAuthorizationInput({secret:1n,salt:2n,message:'hello',domain:'chain'});
  assert.equal(i.secret,'1'); assert.equal(i.salt,'2');
  assert.ok(!Object.values(i).includes('hello')); assert.ok(!Object.values(i).includes('chain'));
});
test('knowledge input validates field bounds', () => {
  assert.deepEqual(buildSecretKnowledgeInput({secret:1n,salt:2n,scope:3n}), {secret:'1',salt:'2',scope:'3'});
  assert.throws(() => buildSecretKnowledgeInput({secret:-1n,salt:2n}), /outside/);
});
test('random field is valid', () => assert.ok(randomField() > 0n));
test('Groth16 refuses missing artifacts instead of fabricating proof', async () => {
  await assert.rejects(() => proveGroth16({circuit:'authorization',input:{},artifactsDir:'/definitely/missing'}), e => e.code === 'ARTIFACT_MISSING');
});
test('proof digest is canonical', () => {
 const b={protocol:'AFX-1024-GROTH16-BN254-v2',circuit:'authorization',proof:{b:2,a:1},publicSignals:['1']};
 assert.equal(proofDigest(b), proofDigest({circuit:'authorization',publicSignals:['1'],proof:{a:1,b:2},protocol:'AFX-1024-GROTH16-BN254-v2'}));
});
