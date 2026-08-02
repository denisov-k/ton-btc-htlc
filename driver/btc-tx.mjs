// btc-tx.mjs — pure Bitcoin transaction primitives: the HTLC script, bech32, BIP143 signing,
// serialization. No node, no filesystem — this same file runs in the daemon and in the browser
// (crypto backend chosen by the bundler: core/crypto.mjs in Node, core/crypto.web.mjs on the web).
import { Buffer } from 'buffer';
import { sha256, sha256d, hash160 } from '../core/crypto.mjs';
import { pubkeyCompressed, signEcdsa } from '../core/ecdsa.mjs';

const rev = h => h.match(/../g).reverse().join('');
export const le = (n, w) => { let v = BigInt(n); const b = Buffer.alloc(w); for (let i = 0; i < w; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
export const varint = n => n < 0xfd ? Buffer.from([n]) : n <= 0xffff ? Buffer.concat([Buffer.from([0xfd]), le(n, 2)]) : Buffer.concat([Buffer.from([0xfe]), le(n, 4)]);
const push = b => { if (b.length < 0x4c) return Buffer.concat([Buffer.from([b.length]), b]); if (b.length < 0x100) return Buffer.concat([Buffer.from([0x4c, b.length]), b]); throw new Error('push too big'); };

// ---- bech32 (BIP173), v0 addresses -------------------------------------------------------------
const CS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const polymod = vs => { let chk = 1; for (const v of vs) { const b = chk >> 25; chk = (chk & 0x1ffffff) << 5 ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; } return chk; };
const hrpExpand = h => [...[...h].map(c => c.charCodeAt(0) >> 5), 0, ...[...h].map(c => c.charCodeAt(0) & 31)];
const toWords = bytes => { let acc = 0, bits = 0; const out = []; for (const b of bytes) { acc = acc << 8 | b; bits += 8; while (bits >= 5) { bits -= 5; out.push(acc >> bits & 31); } } if (bits) out.push(acc << (5 - bits) & 31); return out; };
const fromWords = words => { let acc = 0, bits = 0; const out = []; for (const w of words) { acc = acc << 5 | w; bits += 5; while (bits >= 8) { bits -= 8; out.push(acc >> bits & 0xff); } } if (bits >= 5 || (acc << (8 - bits)) & 0xff) throw new Error('bad padding'); return Buffer.from(out); };
export function bech32Encode(hrp, version, program) {
  const words = [version, ...toWords(program)];
  const pm = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ 1;
  const chk = [0, 1, 2, 3, 4, 5].map(i => pm >> 5 * (5 - i) & 31);
  return hrp + '1' + [...words, ...chk].map(v => CS[v]).join('');
}
export function bech32Decode(addr) {
  const s = addr.toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) throw new Error('bad address');
  const hrp = s.slice(0, pos);
  const words = [...s.slice(pos + 1)].map(c => { const v = CS.indexOf(c); if (v < 0) throw new Error('bad address'); return v; });
  if (polymod([...hrpExpand(hrp), ...words]) !== 1) throw new Error('bad checksum');   // bech32 (v0)
  const version = words[0];
  const program = fromWords(words.slice(1, -6));
  if (version !== 0 || (program.length !== 20 && program.length !== 32)) throw new Error('only v0 addresses');
  return { hrp, version, program };
}
export const spkOfAddress = addr => { const { version, program } = bech32Decode(addr); return Buffer.concat([Buffer.from([version, program.length]), program]); };

// ---- the lock ----------------------------------------------------------------------------------
export function btcHtlcScript({ paymentHash, claimPub, refundPub, cltv }) {
  const cltvNum = (() => { // minimal script number, as OP_CLTV wants it
    let n = BigInt(cltv); const out = [];
    while (n > 0n) { out.push(Number(n & 0xffn)); n >>= 8n; }
    if (out.length && out[out.length - 1] & 0x80) out.push(0);
    return Buffer.from(out);
  })();
  return Buffer.concat([
    Buffer.from([0x63, 0xa8]),                        // OP_IF OP_SHA256
    push(Buffer.from(paymentHash, 'hex')),
    Buffer.from([0x88]),                              // OP_EQUALVERIFY
    push(Buffer.from(claimPub, 'hex')),
    Buffer.from([0xac, 0x67]),                        // OP_CHECKSIG OP_ELSE
    push(cltvNum),
    Buffer.from([0xb1, 0x75]),                        // OP_CLTV OP_DROP
    push(Buffer.from(refundPub, 'hex')),
    Buffer.from([0xac, 0x68]),                        // OP_CHECKSIG OP_ENDIF
  ]);
}
export const btcHtlcSpk = script => Buffer.concat([Buffer.from([0x00, 0x20]), sha256(script)]);
export const btcHtlcAddress = (script, hrp = 'bc') => bech32Encode(hrp, 0, sha256(script));
export const btcWpkSpk = pubHex => Buffer.concat([Buffer.from([0x00, 0x14]), hash160(Buffer.from(pubHex, 'hex'))]);
export const btcAddress = (keyHex, hrp = 'bc') => bech32Encode(hrp, 0, hash160(Buffer.from(pubkeyCompressed(keyHex), 'hex')));

// ---- transactions ------------------------------------------------------------------------------
export function serialize({ version = 2, ins, outs, locktime = 0 }, withWitness = true) {
  const hasW = withWitness && ins.some(i => i.witness?.length);
  return Buffer.concat([
    le(version, 4),
    hasW ? Buffer.from([0x00, 0x01]) : Buffer.alloc(0),
    varint(ins.length),
    ...ins.map(i => Buffer.concat([Buffer.from(rev(i.txid), 'hex'), le(i.vout, 4), varint(0), le(i.sequence ?? 0xfffffffd, 4)])),
    varint(outs.length),
    ...outs.map(o => Buffer.concat([le(o.sats, 8), varint(o.spk.length), o.spk])),
    hasW ? Buffer.concat(ins.map(i => Buffer.concat([varint(i.witness?.length ?? 0), ...(i.witness ?? []).map(w => Buffer.concat([varint(w.length), w]))]))) : Buffer.alloc(0),
    le(locktime, 4),
  ]);
}
export const txidOf = tx => rev(sha256d(serialize(tx, false)).toString('hex'));

// BIP143 sighash for one input (SIGHASH_ALL)
export function sighash143(tx, idx, scriptCode, sats) {
  const prevouts = sha256d(Buffer.concat(tx.ins.map(i => Buffer.concat([Buffer.from(rev(i.txid), 'hex'), le(i.vout, 4)]))));
  const seqs = sha256d(Buffer.concat(tx.ins.map(i => le(i.sequence ?? 0xfffffffd, 4))));
  const outs = sha256d(Buffer.concat(tx.outs.map(o => Buffer.concat([le(o.sats, 8), varint(o.spk.length), o.spk]))));
  const i = tx.ins[idx];
  return sha256d(Buffer.concat([
    le(tx.version ?? 2, 4), prevouts, seqs,
    Buffer.from(rev(i.txid), 'hex'), le(i.vout, 4),
    varint(scriptCode.length), scriptCode,
    le(sats, 8), le(i.sequence ?? 0xfffffffd, 4),
    outs, le(tx.locktime ?? 0, 4), le(1, 4),
  ])).toString('hex');
}
export const derSig = (keyHex, digestHex) => Buffer.from(signEcdsa(keyHex, digestHex) + '01', 'hex');
// p2wpkh scriptCode is the classic p2pkh script over the key hash
export const wpkScriptCode = pubHex => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), hash160(Buffer.from(pubHex, 'hex')), Buffer.from([0x88, 0xac])]);

/** A signed claim of the HTLC with the preimage → raw hex. Runs anywhere, broadcasts nowhere. */
export function buildClaim({ script, funding, preimage, claimKey, toSpk, fee = 300n }) {
  const tx = {
    version: 2, locktime: 0,
    ins: [{ txid: funding.txid, vout: funding.vout, sequence: 0xfffffffd }],
    outs: [{ sats: BigInt(funding.sats) - fee, spk: toSpk }],
  };
  const digest = sighash143(tx, 0, script, BigInt(funding.sats));
  tx.ins[0].witness = [derSig(claimKey, digest), Buffer.from(preimage, 'hex'), Buffer.from([0x01]), script];
  return { raw: serialize(tx).toString('hex'), txid: txidOf(tx) };
}

/** A signed refund of the HTLC after its locktime → raw hex. */
export function buildRefund({ script, funding, cltv, refundKey, toSpk, fee = 300n }) {
  const tx = {
    version: 2, locktime: Number(cltv),
    ins: [{ txid: funding.txid, vout: funding.vout, sequence: 0xfffffffd }],
    outs: [{ sats: BigInt(funding.sats) - fee, spk: toSpk }],
  };
  const digest = sighash143(tx, 0, script, BigInt(funding.sats));
  tx.ins[0].witness = [derSig(refundKey, digest), Buffer.alloc(0), script];
  return { raw: serialize(tx).toString('hex'), txid: txidOf(tx) };
}
