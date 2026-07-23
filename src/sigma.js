import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { CURVE, G, add, multiply, randomScalar, encodePoint, decodePoint, bigIntToBytes, bytesToBigInt } from './secp256k1.js';

const VERSION = '2.0.0';
const SUITE = 'AFX-1024-SCHNORR-SECP256K1-SHA256-v2';
const DOMAIN = Buffer.from('AFX-1024/SIGMA/v2', 'utf8');
const MAX_CLOCK_SKEW_MS = 30_000;

export function generateKeyPair() {
  const x = randomScalar();
  return { privateKey: x.toString(16).padStart(64, '0'), publicKey: toBase64url(encodePoint(multiply(G, x))) };
}

export function getPublicKey(privateKey) {
  return toBase64url(encodePoint(multiply(G, parsePrivateKey(privateKey))));
}

export function prove(message, privateKey, options = {}) {
  const x = parsePrivateKey(privateKey);
  const publicKey = encodePoint(multiply(G, x));
  const context = normalizeContext(options.context ?? '');
  const createdAt = Number.isSafeInteger(options.createdAt) ? options.createdAt : Date.now();
  const ttlMs = Number.isSafeInteger(options.ttlMs) ? options.ttlMs : 300_000;
  if (ttlMs <= 0) throw new Error('ttlMs must be positive');
  const expiresAt = createdAt + ttlMs;
  const nonce = options.nonce ? Buffer.from(options.nonce) : randomBytes(16);
  if (nonce.length !== 16) throw new Error('nonce must be exactly 16 bytes');
  const msg = normalizeMessage(message);
  const k = randomScalar();
  const commitment = encodePoint(multiply(G, k));
  const e = challenge({ publicKey, commitment, message: msg, context, nonce, createdAt, expiresAt });
  const response = (k + e * x) % CURVE.n;
  return {
    v: VERSION,
    suite: SUITE,
    publicKey: toBase64url(publicKey),
    commitment: toBase64url(commitment),
    response: toBase64url(bigIntToBytes(response, 32)),
    nonce: toBase64url(nonce),
    createdAt,
    expiresAt,
    context: toBase64url(context)
  };
}

export function verify(message, proof, options = {}) {
  try {
    if (!proof || proof.v !== VERSION || proof.suite !== SUITE) return { ok: false, code: 'UNSUPPORTED_SUITE' };
    const msg = normalizeMessage(message);
    const context = normalizeContext(options.context ?? Buffer.from(proof.context ?? '', 'base64url').toString('utf8'));
    const proofContext = Uint8Array.from(Buffer.from(proof.context ?? '', 'base64url'));
    if (context.length !== proofContext.length || !timingSafeEqual(Buffer.from(context), Buffer.from(proofContext))) return { ok: false, code: 'CONTEXT_MISMATCH' };
    const publicKey = fromBase64url(proof.publicKey, 33, 'publicKey');
    const commitment = fromBase64url(proof.commitment, 33, 'commitment');
    const response = fromBase64url(proof.response, 32, 'response');
    const nonce = fromBase64url(proof.nonce, 16, 'nonce');
    if (!Number.isSafeInteger(proof.createdAt) || !Number.isSafeInteger(proof.expiresAt) || proof.expiresAt <= proof.createdAt) return { ok: false, code: 'INVALID_TIME' };
    const now = Number.isSafeInteger(options.now) ? options.now : Date.now();
    const skew = Number.isSafeInteger(options.maxClockSkewMs) ? options.maxClockSkewMs : MAX_CLOCK_SKEW_MS;
    if (proof.createdAt > now + skew) return { ok: false, code: 'NOT_YET_VALID' };
    if (proof.expiresAt < now - skew) return { ok: false, code: 'EXPIRED' };
    const s = bytesToBigInt(response);
    if (s <= 0n || s >= CURVE.n) return { ok: false, code: 'INVALID_RESPONSE' };
    const P = decodePoint(publicKey);
    const R = decodePoint(commitment);
    const e = challenge({ publicKey, commitment, message: msg, context, nonce, createdAt: proof.createdAt, expiresAt: proof.expiresAt });
    const left = multiply(G, s);
    const right = add(R, multiply(P, e));
    const ok = !left.inf && !right.inf && timingSafeEqual(Buffer.from(encodePoint(left)), Buffer.from(encodePoint(right)));
    return ok ? { ok: true, code: 'VALID', publicKey: proof.publicKey, nonce: proof.nonce } : { ok: false, code: 'INVALID_PROOF' };
  } catch (error) {
    return { ok: false, code: 'MALFORMED_PROOF', error: error instanceof Error ? error.message : String(error) };
  }
}

export function proofId(proof) {
  const canonical = JSON.stringify({ v: proof.v, suite: proof.suite, publicKey: proof.publicKey, commitment: proof.commitment, response: proof.response, nonce: proof.nonce, createdAt: proof.createdAt, expiresAt: proof.expiresAt, context: proof.context });
  return Buffer.from(sha256(DOMAIN, Buffer.from(canonical))).toString('hex');
}

function challenge({ publicKey, commitment, message, context, nonce, createdAt, expiresAt }) {
  const digest = sha256(DOMAIN, frame(publicKey), frame(commitment), frame(context), frame(message), frame(nonce), u64(createdAt), u64(expiresAt));
  const e = BigInt(`0x${digest.toString('hex')}`) % CURVE.n;
  return e === 0n ? 1n : e;
}
function parsePrivateKey(value) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) throw new Error('private key must be 32-byte hexadecimal');
  const n = BigInt(`0x${value}`);
  if (n <= 0n || n >= CURVE.n) throw new Error('invalid secp256k1 private key');
  return n;
}
function normalizeMessage(message) { return Buffer.isBuffer(message) ? message : Buffer.from(String(message), 'utf8'); }
function normalizeContext(context) {
  const b = Buffer.isBuffer(context) ? context : Buffer.from(String(context), 'utf8');
  if (b.length > 1024) throw new Error('context exceeds 1024 bytes');
  return b;
}
function frame(bytes) { const b = Buffer.from(bytes); return Buffer.concat([u32(b.length), b]); }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }
function u64(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
function sha256(...parts) { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); }
function toBase64url(bytes) { return Buffer.from(bytes).toString('base64url'); }
function fromBase64url(value, length, name) {
  if (typeof value !== 'string') throw new Error(`${name} must be base64url`);
  const b = Buffer.from(value, 'base64url');
  if (b.length !== length) throw new Error(`${name} has invalid length`);
  return b;
}

export const AFX1024 = Object.freeze({ VERSION, SUITE, generateKeyPair, getPublicKey, prove, verify, proofId });
