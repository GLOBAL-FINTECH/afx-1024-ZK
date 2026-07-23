import { createHash, randomBytes } from 'node:crypto';
import { AFXError } from './errors.js';

export const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export function assertField(value, name = 'value') {
  let n;
  try { n = BigInt(value); } catch { throw new AFXError('INVALID_FIELD', `${name} must be an integer field element`); }
  if (n < 0n || n >= FIELD_PRIME) throw new AFXError('INVALID_FIELD', `${name} is outside the BN254 scalar field`);
  return n;
}

export function sha256(data) {
  return createHash('sha256').update(data).digest();
}

export function hashToField(data, domain = 'AFX-1024/FIELD/v2') {
  const d = Buffer.from(String(domain), 'utf8');
  const m = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  const framed = Buffer.concat([u32(d.length), d, u32(m.length), m]);
  return BigInt(`0x${sha256(framed).toString('hex')}`) % FIELD_PRIME;
}

export function randomField() {
  while (true) {
    const n = BigInt(`0x${randomBytes(32).toString('hex')}`);
    if (n > 0n && n < FIELD_PRIME) return n;
  }
}

export function canonicalJSONString(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSONString).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJSONString(value[k])}`).join(',')}}`;
}

function u32(n) {
  const b = Buffer.alloc(4); b.writeUInt32BE(n); return b;
}
