import { access, readFile } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { AFXError } from './errors.js';
import { assertField, canonicalJSONString, hashToField, randomField } from './encoding.js';

const CIRCUITS = new Set(['secret-knowledge', 'authorization']);

export function buildSecretKnowledgeInput({ secret, salt, scope = 0n }) {
  return {
    secret: assertField(secret, 'secret').toString(),
    salt: assertField(salt, 'salt').toString(),
    scope: assertField(scope, 'scope').toString()
  };
}

export function buildAuthorizationInput({ secret, salt, message, domain, nonce = randomField() }) {
  return {
    secret: assertField(secret, 'secret').toString(),
    salt: assertField(salt, 'salt').toString(),
    messageHash: hashToField(message, 'AFX-1024/MESSAGE/v2').toString(),
    domain: hashToField(domain, 'AFX-1024/DOMAIN/v2').toString(),
    nonce: assertField(nonce, 'nonce').toString()
  };
}

export async function proveGroth16({ circuit, input, artifactsDir = './artifacts' }) {
  validateCircuit(circuit);
  const paths = artifactPaths(circuit, artifactsDir);
  await requireFiles(paths.wasm, paths.zkey);
  const snarkjs = await loadSnarkjs();
  let result;
  try {
    result = await snarkjs.groth16.fullProve(stringifyBigInts(input), paths.wasm, paths.zkey);
  } catch (cause) {
    throw new AFXError('PROOF_GENERATION_FAILED', `Groth16 proof generation failed for ${circuit}`, cause);
  }
  return {
    protocol: 'AFX-1024-GROTH16-BN254-v2',
    circuit,
    proof: result.proof,
    publicSignals: result.publicSignals.map(String),
    artifactFingerprint: await fingerprintFiles(paths.wasm, paths.zkey)
  };
}

export async function verifyGroth16(bundle, { artifactsDir = './artifacts', expectedPublicSignals } = {}) {
  validateBundle(bundle);
  const vkeyPath = artifactPaths(bundle.circuit, artifactsDir).vkey;
  await requireFiles(vkeyPath);
  const vkey = JSON.parse(await readFile(vkeyPath, 'utf8'));
  if (expectedPublicSignals && !sameStrings(bundle.publicSignals, expectedPublicSignals)) {
    return { ok: false, code: 'PUBLIC_SIGNAL_MISMATCH' };
  }
  const snarkjs = await loadSnarkjs();
  try {
    const ok = await snarkjs.groth16.verify(vkey, bundle.publicSignals, bundle.proof);
    return { ok, code: ok ? 'VALID' : 'INVALID_PROOF', circuit: bundle.circuit };
  } catch (cause) {
    throw new AFXError('VERIFICATION_FAILED', 'Groth16 verification failed', cause);
  }
}

export function proofDigest(bundle) {
  validateBundle(bundle);
  return createHash('sha256').update(canonicalJSONString(bundle)).digest('hex');
}

function validateCircuit(circuit) {
  if (!CIRCUITS.has(circuit)) throw new AFXError('UNKNOWN_CIRCUIT', `Unsupported circuit: ${circuit}`);
}
function validateBundle(bundle) {
  if (!bundle || typeof bundle !== 'object') throw new AFXError('INVALID_BUNDLE', 'Proof bundle must be an object');
  if (bundle.protocol !== 'AFX-1024-GROTH16-BN254-v2') throw new AFXError('INVALID_PROTOCOL', 'Unsupported proof protocol');
  validateCircuit(bundle.circuit);
  if (!bundle.proof || !Array.isArray(bundle.publicSignals)) throw new AFXError('INVALID_BUNDLE', 'Missing proof or public signals');
}
function artifactPaths(circuit, artifactsDir) {
  const base = resolve(artifactsDir, circuit);
  return { wasm: resolve(base, `${circuit}_js`, `${circuit}.wasm`), zkey: resolve(base, `${circuit}.zkey`), vkey: resolve(base, 'verification_key.json') };
}
async function requireFiles(...files) {
  for (const file of files) {
    try { await access(file, fsConstants.R_OK); }
    catch { throw new AFXError('ARTIFACT_MISSING', `Required proving artifact is missing: ${file}`); }
  }
}
async function loadSnarkjs() {
  try { return await import('snarkjs'); }
  catch (cause) { throw new AFXError('SNARKJS_MISSING', 'Install dependencies with npm install before using Groth16', cause); }
}
function stringifyBigInts(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(stringifyBigInts);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,stringifyBigInts(v)]));
  return value;
}
function sameStrings(a, b) { return a.length === b.length && a.every((x,i) => String(x) === String(b[i])); }
async function fingerprintFiles(...files) {
  const h = createHash('sha256');
  for (const file of files) h.update(await readFile(file));
  return h.digest('hex');
}
