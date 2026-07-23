import { randomBytes } from 'node:crypto';

export const CURVE = Object.freeze({
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
});

export const G = Object.freeze({ x: CURVE.Gx, y: CURVE.Gy, inf: false });
export const INF = Object.freeze({ x: 0n, y: 0n, inf: true });

export function mod(a, m = CURVE.p) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

export function invert(a, m = CURVE.p) {
  let x = mod(a, m);
  if (x === 0n) throw new Error('inverse does not exist');
  let b = m;
  let u = 1n;
  let v = 0n;
  while (x !== 0n) {
    const q = b / x;
    [b, x] = [x, b - q * x];
    [v, u] = [u, v - q * u];
  }
  if (b !== 1n) throw new Error('inverse does not exist');
  return mod(v, m);
}

export function add(a, b) {
  if (a.inf) return b;
  if (b.inf) return a;
  if (a.x === b.x && mod(a.y + b.y) === 0n) return INF;
  const slope = a.x === b.x && a.y === b.y
    ? mod((3n * a.x * a.x) * invert(2n * a.y))
    : mod((b.y - a.y) * invert(b.x - a.x));
  const x = mod(slope * slope - a.x - b.x);
  const y = mod(slope * (a.x - x) - a.y);
  return { x, y, inf: false };
}

export function multiply(point, scalar) {
  let n = mod(BigInt(scalar), CURVE.n);
  if (n === 0n || point.inf) return INF;
  let p = point;
  let result = INF;
  while (n > 0n) {
    if (n & 1n) result = add(result, p);
    p = add(p, p);
    n >>= 1n;
  }
  return result;
}

export function randomScalar() {
  while (true) {
    const n = BigInt(`0x${randomBytes(32).toString('hex')}`);
    if (n > 0n && n < CURVE.n) return n;
  }
}

export function encodePoint(point) {
  if (point.inf) throw new Error('cannot encode point at infinity');
  const out = Buffer.alloc(33);
  out[0] = point.y & 1n ? 3 : 2;
  bigIntToBytes(point.x, 32).copy(out, 1);
  return out;
}

export function decodePoint(bytes) {
  const input = Buffer.from(bytes);
  if (input.length !== 33 || (input[0] !== 2 && input[0] !== 3)) throw new Error('invalid compressed secp256k1 point');
  const x = bytesToBigInt(input.subarray(1));
  if (x >= CURVE.p) throw new Error('point x is outside field');
  const y2 = mod(x * x * x + 7n);
  let y = modPow(y2, (CURVE.p + 1n) >> 2n, CURVE.p);
  if (mod(y * y) !== y2) throw new Error('point is not on secp256k1');
  const odd = Boolean(input[0] & 1);
  if (Boolean(y & 1n) !== odd) y = CURVE.p - y;
  return { x, y, inf: false };
}

export function bigIntToBytes(value, length = 32) {
  const hex = BigInt(value).toString(16).padStart(length * 2, '0');
  if (hex.length > length * 2) throw new Error('integer does not fit');
  return Buffer.from(hex, 'hex');
}

export function bytesToBigInt(bytes) {
  const hex = Buffer.from(bytes).toString('hex');
  return hex ? BigInt(`0x${hex}`) : 0n;
}

function modPow(base, exponent, modulus) {
  let b = mod(base, modulus);
  let e = exponent;
  let out = 1n;
  while (e > 0n) {
    if (e & 1n) out = (out * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return out;
}
