// crypto.mjs — hash/HMAC primitives for both Node and the browser, backed
// by @noble/hashes (audited, sync, tiny). Selected in place of crypto.mjs by the
// "browser" field of core/package.json (and the Vite alias). Identical signatures
// to crypto.mjs; returns Buffer (the web app provides a Buffer polyfill). The
// @noble outputs are byte-for-byte identical to Node's crypto (verified), so the
// whole wallet core behaves the same in the browser.
import { Buffer } from 'buffer';
import { sha256 as _s256, sha512 as _s512 } from '@noble/hashes/sha2.js';
import { ripemd160 as _rmd } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';

const u8 = b => (b instanceof Uint8Array ? b : Uint8Array.from(b));
const B = a => Buffer.from(a);

export const sha256 = b => B(_s256(u8(b)));
export const ripemd160 = b => B(_rmd(u8(b)));
export const sha256d = b => sha256(sha256(b));
export const hash160 = b => ripemd160(sha256(b));
export const hmacSha256 = (key, msg) => B(hmac(_s256, u8(key), u8(msg)));
export const hmacSha512 = (key, msg) => B(hmac(_s512, u8(key), u8(msg)));
