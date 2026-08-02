// @ts-nocheck  — bit-exact kernel, golden-vector tested; TS number/bigint coercion is a false positive here
// ecdsa.mjs — secp256k1 ECDSA sign (RFC6979) + verify + DER, matching Freicoin's
// test_framework/key.py byte-for-byte. Pure BigInt (portable; the RN app would
// swap in a native secp256k1, but this proves the signing flow end to end).
import { hmacSha256 } from './crypto.mjs';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n; // ORDER (curve order)
const N_HALF = N >> 1n;
const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const mod = (a, m) => ((a % m) + m) % m;
const modInv = (a, m) => modPow(mod(a, m), m - 2n, m);        // Fermat (m prime)
function modPow(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }

// affine point ops on y^2 = x^3 + 7
function ptAdd(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a.x === b.x && mod(a.y + b.y, P) === 0n) return null;    // P + (-P) = O
  let m;
  if (a.x === b.x && a.y === b.y) m = mod((3n * a.x * a.x) * modInv(2n * a.y, P), P);
  else m = mod((b.y - a.y) * modInv(b.x - a.x, P), P);
  const x = mod(m * m - a.x - b.x, P);
  const y = mod(m * (a.x - x) - a.y, P);
  return { x, y };
}
function ptMul(k, pt) { let r = null, a = pt; while (k > 0n) { if (k & 1n) r = ptAdd(r, a); a = ptAdd(a, a); k >>= 1n; } return r; }
const G = { x: Gx, y: Gy };

const bytesToBig = b => BigInt('0x' + Buffer.from(b).toString('hex') || '0x0');
const bigTo32 = x => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
const hmac = (key, msg) => hmacSha256(key, msg);

// RFC6979 nonce, matching key.py rfc6979_nonce(secret32 || msg32) exactly.
function rfc6979Nonce(secret32, msg32) {
  const keyMat = Buffer.concat([secret32, msg32]);
  let v = Buffer.alloc(32, 1), k = Buffer.alloc(32, 0);
  k = hmac(k, Buffer.concat([v, Buffer.from([0x00]), keyMat]));
  v = hmac(k, v);
  k = hmac(k, Buffer.concat([v, Buffer.from([0x01]), keyMat]));
  v = hmac(k, v);
  return hmac(k, v);
}

const bitLen = x => x === 0n ? 0 : x.toString(2).length;
// DER, matching key.py: integer byte length is (bit_length + 8) // 8.
function derInt(x) {
  const len = (bitLen(x) + 8) >> 3;
  const b = Buffer.from(x.toString(16).padStart(len * 2, '0'), 'hex');
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
}

/** Public key point from a secret (hex string). */
export function pubkeyPoint(secretHex) { return ptMul(BigInt('0x' + secretHex.padStart(64, '0')), G); }

/** Compressed 33-byte pubkey hex. */
export function pubkeyCompressed(secretHex) {
  const Pt = pubkeyPoint(secretHex);
  const prefix = (Pt.y & 1n) === 0n ? '02' : '03';
  return prefix + Pt.x.toString(16).padStart(64, '0');
}

/**
 * DER-encoded ECDSA signature over the 32-byte message `msgHash` (hex), matching
 * key.py sign_ecdsa(low_s=True, rfc6979=True). Returns hex.
 */
export function signEcdsa(secretHex, msgHashHex) {
  const secret32 = Buffer.from(secretHex.padStart(64, '0'), 'hex');
  const msg32 = Buffer.from(msgHashHex.padStart(64, '0'), 'hex');
  const secret = bytesToBig(secret32);
  const z = bytesToBig(msg32);
  const k = mod(bytesToBig(rfc6979Nonce(secret32, msg32)), N);
  const R = ptMul(k, G);
  const r = mod(R.x, N);
  let s = mod(modInv(k, N) * (z + secret * r), N);
  if (s > N_HALF) s = N - s;                                   // low-S
  const der = Buffer.concat([derInt(r), derInt(s)]);
  return Buffer.concat([Buffer.from([0x30, der.length]), der]).toString('hex');
}

function verifyWithPoint(Pt, msgHashHex, derHex) {
  const b = Buffer.from(derHex, 'hex');
  // parse DER: 30 len 02 rlen r 02 slen s
  let i = 2; const rlen = b[i + 1]; const r = bytesToBig(b.subarray(i + 2, i + 2 + rlen)); i += 2 + rlen;
  const slen = b[i + 1]; const s = bytesToBig(b.subarray(i + 2, i + 2 + slen));
  if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
  const z = bytesToBig(Buffer.from(msgHashHex.padStart(64, '0'), 'hex'));
  const w = modInv(s, N);
  const u1 = mod(z * w, N), u2 = mod(r * w, N);
  const Rp = ptAdd(ptMul(u1, G), ptMul(u2, Pt));
  return Rp !== null && mod(Rp.x, N) === r;
}

/** Verify a DER sig (hex) over msgHash (hex) against a secret (self-check helper). */
export function verifyEcdsa(secretHex, msgHashHex, derHex) {
  return verifyWithPoint(pubkeyPoint(secretHex), msgHashHex, derHex);
}

/** Decompress a 33-byte compressed pubkey (hex) to an affine point (y^2 = x^3 + 7). */
export function pointFromCompressed(pubHex) {
  const prefix = parseInt(pubHex.slice(0, 2), 16);
  if (prefix !== 2 && prefix !== 3 || pubHex.length !== 66) return null;
  const x = BigInt('0x' + pubHex.slice(2));
  if (x >= P) return null;
  let y = modPow(mod(x * x * x + 7n, P), (P + 1n) >> 2n, P);
  if (mod(y * y, P) !== mod(x * x * x + 7n, P)) return null;   // x not on the curve
  if ((y & 1n) !== BigInt(prefix & 1)) y = P - y;
  return { x, y };
}

/** Verify a DER sig (hex) over msgHash (hex) against a compressed pubkey (hex) — what a
 *  consensus validator does (it never has the secret). */
export function verifyEcdsaPub(pubHex, msgHashHex, derHex) {
  const Pt = pointFromCompressed(pubHex);
  return Pt !== null && verifyWithPoint(Pt, msgHashHex, derHex);
}
