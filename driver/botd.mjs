// botd.mjs — the house side of a POK↔BTC swap desk, an HTTP service the page talks to.
//
// Forward (POK → BTC): the visitor's browser invents the secret and an ephemeral claim key.
// They lock jettons; we verify and lock BTC into a P2WSH HTLC claimable by their key; their
// browser signs the claim (revealing the secret on Bitcoin); we broadcast it and take the
// jettons with that secret.
//
// Reverse (BTC → POK): the visitor invents the secret, pays BTC into an HTLC claimable by US
// (their refund key is ephemeral in their browser); we verify the deposit and lock jettons for
// them; they claim via Tonkeeper (revealing the secret on TON); we claim the BTC.
//
// As everywhere in this repo: the party that reveals the secret works against the SHORTER clock.
//
// State machines:
//   forward: open → jetton-locked → btc-locked → claimed → done      (↘ expired / btc-refunded)
//   reverse: awaiting-btc → jettons-locked → done                    (↘ expired / reverse-stuck / jettons-refunded)
import { createServer } from 'node:http';
import { createHash } from 'crypto';
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'fs';
import { btcNode, btcHtlcScript, btcHtlcAddress, btcHtlcSpk, btcFund, btcClaim, btcRefund, btcWpkSpk } from './btc-leg.mjs';
import { tonClient, tonWallet, tonLock, tonState, jetton, Address, Cell } from './ton-leg.mjs';
import { pubkeyCompressed } from '../core/ecdsa.mjs';

const CFG = JSON.parse(readFileSync(process.env.BOTD_CONFIG || 'driver/botd.json', 'utf8'));
const DIR = CFG.journalDir;
mkdirSync(DIR, { recursive: true });
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const sha256hex = b => createHash('sha256').update(b).digest('hex');

const KEY = readFileSync(CFG.btc.keyFile, 'utf8').trim();
const PUB = pubkeyCompressed(KEY);
const node = btcNode({ bin: CFG.btc.cli, args: CFG.btc.args });
const HRP = CFG.btc.hrp;                                       // 'bc' mainnet, 'tb' signet/testnet
const HTLC_CODE = Cell.fromBase64(readFileSync(CFG.ton.codeFile, 'utf8'));

const swaps = new Map();
for (const f of readdirSync(DIR)) if (f.endsWith('.json')) {
  const s = JSON.parse(readFileSync(`${DIR}/${f}`, 'utf8')); swaps.set(s.id, s);
}
const store = s => { writeFileSync(`${DIR}/${s.id}.json`, JSON.stringify(s, null, 2)); swaps.set(s.id, s); return s; };

const MIN_GAS = 300000000n;                                    // 0.3 TON — one answered swap of headroom
let tctx = null;
async function gasOk() {
  try { return (await tctx.client.getBalance(tctx.wallet.address)) >= MIN_GAS; }
  catch { return true; }                                       // don't block on a transient RPC error
}
async function ton() {
  if (!tctx) {
    const client = await tonClient(CFG.ton);
    tctx = { client, wallet: await tonWallet(client, CFG.ton.mnemonicFile),
             j: await jetton(client, Address.parse(CFG.ton.jettonMaster)) };
  }
  return tctx;
}

// fee for a ~vbytes transaction at the current market rate, clamped to sane bounds
function marketFee(vbytes) {
  let satVb = 1.5;
  try {
    const r = node.json('estimatesmartfee', '2');
    if (r.feerate) satVb = r.feerate * 1e8 / 1000;
  } catch {}
  const fee = Math.ceil(satVb * vbytes);
  return BigInt(Math.min(Math.max(fee, Math.ceil(vbytes * 1.1)), CFG.btc.maxFee ?? 2000));
}

const jettonLockOf = s => tonLock({
  codeCell: HTLC_CODE, paymentHash: s.hash, deadline: s.tonDeadline,
  master: Address.parse(CFG.ton.jettonMaster), walletCode: tctx.j.walletCode,
  governed: CFG.ton.governed, sender: Address.parse(s.tonGiver ?? tctx.wallet.address.toString()),
  recipient: Address.parse(s.tonTaker ?? s.tonRecipient),
});
const scriptOf = s => btcHtlcScript(s.dir === 'reverse'
  ? { paymentHash: s.hash, claimPub: PUB, refundPub: s.btcRefundPub, cltv: s.btcCltv }
  : { paymentHash: s.hash, claimPub: s.claimPub, refundPub: PUB, cltv: s.btcCltv });

// ---- API ---------------------------------------------------------------------------------------
const api = {
  async quote() {
    return { rateSatsPerJetton: CFG.rateSatsPerJetton, minJettons: CFG.minJettons, maxJettons: CFG.maxJettons,
      symbol: CFG.ton.symbol, decimals: CFG.ton.decimals, master: CFG.ton.jettonMaster,
      governed: CFG.ton.governed, chain: CFG.ton.chain, btcNet: CFG.btc.net,
      tonTaker: (await ton()).wallet.address.toString({ bounceable: false, testOnly: CFG.ton.chain === 'testnet' }) };
  },

  async offer(b) {
    if (!await gasOk()) throw new Error('обменник временно недоступен — пополняется, попробуйте позже');
    const jettons = BigInt(b.jettons ?? 0);
    if (jettons < BigInt(CFG.minJettons) || jettons > BigInt(CFG.maxJettons)) throw new Error('сумма вне лимитов');
    if (!/^[0-9a-f]{64}$/.test(b.hash ?? '')) throw new Error('bad hash');
    if (!/^[0-9a-f]{66}$/.test(b.claimPub ?? '')) throw new Error('bad claimPub');
    Address.parse(b.tonGiver);
    // the price is ours to quote; sats follow from it, not from the visitor
    const sats = BigInt(Math.floor(Number(jettons) * CFG.rateSatsPerJetton));
    if (sats < BigInt(CFG.minSats ?? 10000)) throw new Error('слишком мелко — комиссии съедят обмен');
    if (marketFee(170) * 3n > sats) throw new Error('комиссии сети сейчас велики для такой суммы — увеличь сумму');
    const t = await ton();
    const s = store({
      id: b.hash.slice(0, 16), hash: b.hash, dir: 'forward', state: 'open', createdAt: Date.now(),
      jettons: String(jettons), sats: String(sats),
      claimPub: b.claimPub, btcPayout: String(b.btcPayout ?? ''), tonGiver: b.tonGiver,
      tonTaker: t.wallet.address.toString(),
      tonDeadline: Math.floor(Date.now() / 1000) + CFG.tonSeconds,
    });
    log(s.id, 'offer:', s.jettons, 'jettons →', s.sats, 'sats →', s.btcPayout || '(their claim tx)');
    return { id: s.id, tonDeadline: s.tonDeadline, tonTaker: s.tonTaker, sats: s.sats,
      master: CFG.ton.jettonMaster, governed: CFG.ton.governed, chain: CFG.ton.chain };
  },

  async status(b) {
    const s = swaps.get(String(b.id ?? '')); if (!s || s.dir !== 'forward') throw new Error('no such swap');
    let btcConfirmations = 0;
    if (s.btcLockInfo) { const o = node.outAt(s.btcLockInfo.txid, s.btcLockInfo.vout); btcConfirmations = o ? o.confirmations : 0; }
    return { id: s.id, state: s.state, btcLock: s.btcLockInfo ?? null, btcClaimTxid: s.btcClaimTxid ?? null,
      btcRefunded: !!s.btcRefunded, tonDeadline: s.tonDeadline, jettons: s.jettons, sats: s.sats,
      btcConfirmations, btcCltv: s.btcCltv ?? null, housePub: PUB, btcRawTx: s.btcRawTx ?? null,
      claimFee: String(marketFee(160)), tip: node.tip(), btcNet: CFG.btc.net };
  },

  async claim(b) {
    const s = swaps.get(String(b.id ?? '')); if (!s) throw new Error('no such swap');
    if (s.state !== 'btc-locked') throw new Error('нечего забирать: состояние ' + s.state);
    const raw = String(b.rawtx ?? '');
    if (!/^[0-9a-f]{100,20000}$/.test(raw)) throw new Error('bad rawtx');
    const txid = node.send(raw);                                // the node is the real validator
    s.state = 'claimed'; s.btcClaimTxid = txid; store(s);
    log(s.id, 'BTC claim broadcast', txid);
    return { txid };
  },

  async offerReverse(b) {
    if (!await gasOk()) throw new Error('обменник временно недоступен — пополняется, попробуйте позже');
    const jettons = BigInt(b.jettons ?? 0);
    if (jettons < BigInt(CFG.minJettons) || jettons > BigInt(CFG.maxJettons)) throw new Error('сумма вне лимитов');
    if (!/^[0-9a-f]{64}$/.test(b.hash ?? '')) throw new Error('bad hash');
    if (!/^[0-9a-f]{66}$/.test(b.btcRefundPub ?? '')) throw new Error('bad btcRefundPub');
    Address.parse(b.tonRecipient);
    if (BigInt(CFG.reserveJettons ?? 0) < jettons) throw new Error('в резерве недостаточно токенов');
    const sats = BigInt(Math.floor(Number(jettons) * CFG.rateSatsPerJetton));
    if (sats < BigInt(CFG.minSats ?? 10000)) throw new Error('слишком мелко — комиссии съедят обмен');
    if (marketFee(170) * 3n > sats) throw new Error('комиссии сети сейчас велики для такой суммы — увеличь сумму');
    // the BTC lock the visitor must fund: we claim with the secret, they refund after a short clock
    const btcCltv = node.tip() + (CFG.reverseBtcBlocks ?? 12);
    const s = store({
      id: b.hash.slice(0, 16), hash: b.hash, dir: 'reverse', state: 'awaiting-btc', createdAt: Date.now(),
      jettons: String(jettons), sats: String(sats),
      btcRefundPub: b.btcRefundPub, tonRecipient: b.tonRecipient, btcCltv,
      tonDeadline: Math.floor(Date.now() / 1000) + CFG.tonSeconds,
    });
    s.btcLockAddress = btcHtlcAddress(scriptOf(s), HRP); store(s);
    log(s.id, 'reverse offer:', s.sats, 'sats →', s.jettons, 'jettons; visitor funds', s.btcLockAddress);
    return { id: s.id, btcClaimPub: PUB, btcCltv, btcAddress: s.btcLockAddress, sats: s.sats,
      tonDeadline: s.tonDeadline, master: CFG.ton.jettonMaster, governed: CFG.ton.governed,
      chain: CFG.ton.chain, tonSender: (await ton()).wallet.address.toString() };
  },

  // relay a visitor-signed transaction (their BTC refund); the node is the validator
  async broadcast(b) {
    const raw = String(b.rawtx ?? '');
    if (!/^[0-9a-f]{100,20000}$/.test(raw)) throw new Error('bad rawtx');
    return { txid: node.send(raw) };
  },

  async statusReverse(b) {
    const s = swaps.get(String(b.id ?? '')); if (!s || s.dir !== 'reverse') throw new Error('no such swap');
    // where the visitor's deposit sits, for their refund tooling
    const btcLockUtxo = s.btcLockInfo ?? (s.btcLockAddress ? (() => { const u = btcLockFunded(s); return u ? { txid: u.txid, vout: u.vout, sats: String(u.sats) } : null; })() : null);
    return { id: s.id, state: s.state, btcLockUtxo, tonAddress: s.tonAddress ?? null, tonDeadline: s.tonDeadline,
      jettons: s.jettons, sats: s.sats, btcClaimTxid: s.btcClaimTxid ?? null, tip: node.tip(),
      hash: s.hash, btcClaimPub: PUB, btcRefundPub: s.btcRefundPub, btcCltv: s.btcCltv,
      btcAddress: s.btcLockAddress, tonRecipient: s.tonRecipient, symbol: CFG.ton.symbol,
      decimals: CFG.ton.decimals, btcNet: CFG.btc.net };
  },
};

// ---- the machine -------------------------------------------------------------------------------
async function tick() {
  const t = await ton();
  for (const s of [...swaps.values()]) {
    try {
      const secsLeft = s.tonDeadline - Math.floor(Date.now() / 1000);
      if (s.dir === 'reverse') { await tickReverse(s, t, secsLeft); continue; }

      if (s.state === 'open') {
        if (secsLeft <= 0) { s.state = 'expired'; store(s); continue; }
        const tl = jettonLockOf(s);
        const st = await tonState(t.client, tl);
        if (!st.deployed || !st.funded) continue;
        if (st.hash !== s.hash || st.amount < BigInt(s.jettons)) { log(s.id, 'lock mismatch — ignoring'); continue; }
        const code = (await t.client.getContractState(tl.address)).code;
        if (Buffer.compare(Cell.fromBoc(code)[0].hash(), HTLC_CODE.hash()) !== 0) { log(s.id, 'alien code — ignoring'); continue; }
        if (secsLeft < CFG.minSeconds) { log(s.id, 'funded too late — will let it refund'); continue; }
        s.state = 'jetton-locked'; s.tonAddress = tl.address.toString(); store(s);
        log(s.id, 'jetton lock verified:', st.amount.toString(), 'units at', s.tonAddress);
      }

      if (s.state === 'jetton-locked') {
        s.btcCltv = node.tip() + (CFG.btcBlocks ?? 18);
        const script = scriptOf(s);
        const funding = btcFund({ node, key: KEY, script, sats: BigInt(s.sats), fee: marketFee(170), hrp: HRP });
        s.state = 'btc-locked'; s.btcRawTx = funding.raw;
        s.btcLockInfo = { txid: funding.txid, vout: 0, sats: s.sats, cltv: s.btcCltv,
          address: btcHtlcAddress(script, HRP) };
        store(s);
        log(s.id, 'BTC locked:', funding.txid, 'until block', s.btcCltv);
      }

      if (s.state === 'claimed') {
        const spent = !node.outAt(s.btcLockInfo.txid, 0);
        if (!spent) continue;
        const preimage = preimageFromClaim(s);
        if (!preimage) { log(s.id, 'lock spent but no preimage found — inspect by hand'); s.state = 'inspect'; store(s); continue; }
        log(s.id, 'preimage recovered from Bitcoin, taking the jettons');
        const { tonClaim } = await import('./ton-leg.mjs');
        await tonClaim(t.wallet, jettonLockOf(s), preimage, CFG.ton.claimGas ?? '0.15');
        s.state = 'done'; s.preimage = preimage; store(s);
        log(s.id, 'done: jettons claimed');
      }

      if (s.state === 'btc-locked') {
        if (node.tip() >= s.btcCltv && node.outAt(s.btcLockInfo.txid, 0)) {
          log(s.id, 'no claim came — refunding our sats');
          btcRefund({ node, script: scriptOf(s),
            funding: { txid: s.btcLockInfo.txid, vout: 0, sats: BigInt(s.sats) },
            cltv: s.btcCltv, refundKey: KEY, toSpk: btcWpkSpk(PUB), fee: marketFee(200) });
          s.state = 'btc-refunded'; s.btcRefunded = true; store(s);
        }
        else if (!node.outAt(s.btcLockInfo.txid, 0)) { s.state = 'claimed'; store(s); }
      }
    } catch (e) { log(s.id, 'tick error:', e.message?.slice(0, 200)); }
  }
}

// reverse: BTC in, jettons out
async function tickReverse(s, t, secsLeft) {
  if (s.state === 'awaiting-btc') {
    if (node.tip() >= s.btcCltv) { s.state = 'expired'; store(s); return; }
    const u = btcLockFunded(s);
    if (!u) return;
    if (secsLeft < CFG.minSeconds) { log(s.id, 'BTC funded too late — leaving it to the visitor to refund'); return; }
    s.btcLockInfo = { txid: u.txid, vout: u.vout, sats: String(u.sats) };
    const tl = tonLock({ codeCell: HTLC_CODE, paymentHash: s.hash, deadline: s.tonDeadline,
      master: Address.parse(CFG.ton.jettonMaster), walletCode: t.j.walletCode, governed: CFG.ton.governed,
      sender: t.wallet.address, recipient: Address.parse(s.tonRecipient) });
    s.tonAddress = tl.address.toString();
    if (!(await tonState(t.client, tl)).deployed) { log(s.id, 'deploying jetton lock', s.tonAddress); await (await import('./ton-leg.mjs')).tonDeploy(t.wallet, t.client, tl); }
    const mine = await t.j.walletOf(t.wallet.address);
    log(s.id, 'BTC lock verified — locking', s.jettons, 'jettons for the visitor');
    await (await import('./ton-leg.mjs')).tonFund(t.wallet, mine, tl, BigInt(s.jettons), t.wallet.address, '0.13', '0.05');
    s.state = 'jettons-locked'; store(s);
  }

  if (s.state === 'jettons-locked') {
    if (node.tip() >= s.btcCltv) {
      log(s.id, 'BTC claim window closed without a secret — will refund jettons after their deadline');
      s.state = 'reverse-stuck'; store(s); return;
    }
    const preimage = await revealedOnTon(s, t);
    if (!preimage) return;
    claimTheirBtc(s, preimage, 'done: BTC claimed');
  }

  // Stuck: our BTC window closed unclaimed. If the secret still appears on TON, finishing beats
  // forfeiting (the visitor's refund needs their ephemeral key and manual tooling — race is theoretical).
  if (s.state === 'reverse-stuck' && secsLeft > 0) {
    const preimage = await revealedOnTon(s, t);
    if (preimage) {
      log(s.id, 'secret appeared after our window — attempting the BTC claim anyway');
      try { claimTheirBtc(s, preimage, 'late finish: BTC claimed'); }
      catch (e) { log(s.id, 'late claim failed:', e.message?.slice(0, 120)); }
    }
    return;
  }

  if (s.state === 'reverse-stuck' && secsLeft <= 0) {
    const tl = tonLock({ codeCell: HTLC_CODE, paymentHash: s.hash, deadline: s.tonDeadline,
      master: Address.parse(CFG.ton.jettonMaster), walletCode: t.j.walletCode, governed: CFG.ton.governed,
      sender: t.wallet.address, recipient: Address.parse(s.tonRecipient) });
    log(s.id, 'refunding our jettons');
    await (await import('./ton-leg.mjs')).tonRefund(t.wallet, tl, '0.15');
    s.state = 'jettons-refunded'; store(s);
  }
}

async function revealedOnTon(s, t) {
  const tl = tonLock({ codeCell: HTLC_CODE, paymentHash: s.hash, deadline: s.tonDeadline,
    master: Address.parse(CFG.ton.jettonMaster), walletCode: t.j.walletCode, governed: CFG.ton.governed,
    sender: t.wallet.address, recipient: Address.parse(s.tonRecipient) });
  const preimage = await (await import('./ton-leg.mjs')).tonRevealedPreimage(t.client, tl);
  return preimage && sha256hex(Buffer.from(preimage, 'hex')) === s.hash ? preimage : null;
}
function claimTheirBtc(s, preimage, doneMsg) {
  const claim = btcClaim({ node, script: scriptOf(s), preimage, claimKey: KEY, toSpk: btcWpkSpk(PUB),
    funding: { txid: s.btcLockInfo.txid, vout: s.btcLockInfo.vout, sats: BigInt(s.btcLockInfo.sats) },
    fee: marketFee(200) });
  s.state = 'done'; s.preimage = preimage; s.btcClaimTxid = claim.txid; store(s);
  log(s.id, doneMsg, claim.txid);
}

// the visitor's BTC deposit at the lock address, confirmed and big enough — or null
function btcLockFunded(s) {
  try {
    const scan = node.json('scantxoutset', 'start', JSON.stringify([`addr(${s.btcLockAddress})`]));
    const u = (scan.unspents || []).find(x => BigInt(Math.round(x.amount * 1e8)) >= BigInt(s.sats));
    if (!u) return null;
    const o = node.outAt(u.txid, u.vout);
    if (!o || o.confirmations < (CFG.btc.confirmations ?? 1)) return null;
    return { txid: u.txid, vout: u.vout, sats: BigInt(Math.round(u.amount * 1e8)) };
  } catch { return null; }
}

// dig the 32-byte preimage out of the claim's witness
function preimageFromClaim(s) {
  try {
    let raw;
    if (s.btcClaimTxid) raw = node.cli('getrawtransaction', s.btcClaimTxid);
    else {
      for (let h = node.tip(); h > node.tip() - 20; h--) {
        const blk = node.json('getblock', node.cli('getblockhash', String(h)), 2);
        for (const tx of blk.tx) for (const vin of tx.vin ?? []) {
          if (vin.txid === s.btcLockInfo.txid && vin.vout === 0) { raw = node.cli('getrawtransaction', tx.txid); break; }
        }
        if (raw) break;
      }
    }
    if (!raw) return null;
    const d = node.json('decoderawtransaction', raw);
    for (const w of d.vin?.[0]?.txinwitness ?? []) {
      if (w.length === 64 && sha256hex(Buffer.from(w, 'hex')) === s.hash) return w;
    }
  } catch {}
  return null;
}

// ---- serve -------------------------------------------------------------------------------------
const MAX_BODY = 64 * 1024;
const server = createServer(async (req, res) => {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'content-type', 'Content-Type': 'application/json; charset=utf-8' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  try {
    const m = /^\/api\/(\w+)$/.exec(req.url ?? '');
    if (!m || !(m[1] in api)) { res.writeHead(404, cors); return res.end('{"error":"not found"}'); }
    let body = {};
    if (req.method === 'POST') body = await new Promise((ok, bad) => {
      let d = '', n = 0;
      req.on('data', c => { n += c.length; if (n > MAX_BODY) { bad(new Error('body too large')); req.destroy(); } else d += c; });
      req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch { bad(new Error('malformed JSON')); } });
      req.on('error', () => bad(new Error('stream error')));
    });
    const out = await api[m[1]](body);
    res.writeHead(200, cors);
    res.end(JSON.stringify(out, (k, v) => typeof v === 'bigint' ? String(v) : v));
  } catch (e) { res.writeHead(400, cors); res.end(JSON.stringify({ error: e.message })); }
});

await ton();                                                    // fail fast if TON is unreachable
server.listen(CFG.port, '127.0.0.1', () => log(`btcswap daemon on :${CFG.port}, BTC ${CFG.btc.net}, jetton ${CFG.ton.jettonMaster}`));
setInterval(() => tick().catch(e => log('tick failed:', e.message?.slice(0, 200))), (CFG.tickSeconds ?? 20) * 1000);
