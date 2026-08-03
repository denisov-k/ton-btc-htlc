import './shim.mjs';
// swap-page.mjs — the whole visitor side of a POK↔BTC swap in one page.
//
// Forward (POK → BTC): the visitor brings a Tonkeeper with jettons and a BTC address to be paid
// at. The secret and the ephemeral claim key are born in this browser and never leave it; the
// jetton lock is signed by the visitor's own wallet; the BTC claim is signed HERE with the
// ephemeral key. The daemon is the counterparty, not a custodian — its BTC lock is re-verified
// byte for byte from the raw transaction before the claim is signed.
//
// Reverse (BTC → POK): the secret is still born here, along with an ephemeral REFUND key. The
// page derives the HTLC address itself from the agreed terms and shows it; the visitor pays it
// from any Bitcoin wallet. If the deal dies, the refund transaction is built and signed here too.
//
// The deal survives a reload: everything needed to finish lives in localStorage under the swap id.
import { Address, Cell, beginCell, contractAddress, toNano } from '@ton/core';
import { TonConnectUI } from '@tonconnect/ui';
import HTLC_CODE_B64 from './htlc-code.mjs';
import { pubkeyCompressed } from '../../core/ecdsa.mjs';
import { btcHtlcScript, btcHtlcAddress, btcHtlcSpk, spkOfAddress, bech32Decode,
         buildClaim, buildRefund, serialize, txidOf } from '../../driver/btc-tx.mjs';

const API = '/api-btc';
const api = (m, body) => fetch(`${API}/api/${m}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) })
  .then(async r => { const j = await r.json(); if (j.error) throw new Error(j.error); return j; });
const $ = id => document.getElementById(id);
const show = (id, t) => { const e = $(id); if (e) e.textContent = t; };
const step = n => { for (let i = 1; i <= 4; i++) $('s' + i).classList.toggle('on', i <= n); };
const hex = a => [...a].map(b => b.toString(16).padStart(2, '0')).join('');
const rand32 = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const sha256hex = async h => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16))))));

// one slot per deal + a pointer, so a second deal can never overwrite the first one's secret
const S_KEY = 'btcswap_active';
const dealKey = id => 'btcswap_deal_' + id;
const saved = () => {
  try {
    const id = localStorage.getItem(S_KEY);
    return id ? JSON.parse(localStorage.getItem(dealKey(id)) || 'null') : null;
  } catch { return null; }
};
const save = s => { localStorage.setItem(dealKey(s.id), JSON.stringify(s)); localStorage.setItem(S_KEY, s.id); };
const forget = s => { localStorage.removeItem(S_KEY); if (s?.id) localStorage.setItem(dealKey(s.id), JSON.stringify({ ...s, phase: 'done' })); };
const strays = () => Object.keys(localStorage).filter(k => k.startsWith('btcswap_deal_'))
  .map(k => { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } })
  .filter(d => d && !TERMINAL.has(d.phase));
const OP = { transfer: 0xf8a7ea5, refund: 0x72656664 };
const TERMINAL = new Set(['claimed', 'done', 'expired', 'refunded']);

let dir = 'fwd';                 // 'fwd' = jettons in, sats out; 'back' = sats in, jettons out
const A_KEY = 'btcswap_payout';  // remembered BTC payout address — public, safe in localStorage
let quote, ui, deal = (() => { const d = saved(); if (d && TERMINAL.has(d.phase)) { localStorage.removeItem(S_KEY); return null; } return d; })();

const fmtJ = v => (Number(v) / 10 ** quote.decimals).toLocaleString('ru-RU');
const fmtSats = v => Number(v).toLocaleString('ru-RU') + ' сат';
const explorer = txid => (quote.btcNet === 'main' ? 'https://mempool.space/tx/' : 'https://mempool.space/signet/tx/') + txid;
const HRP = () => quote.btcNet === 'main' ? 'bc' : 'tb';

function tonLockInit(walletCode) {
  const data = beginCell()
    .storeUint(BigInt('0x' + deal.hash), 256).storeUint(deal.tonDeadline, 32)
    .storeUint(0, 1).storeUint(quote.governed ? 1 : 0, 1).storeCoins(0)
    .storeRef(beginCell().storeAddress(Address.parse(quote.master)).storeAddress(Address.parse(deal.tonGiver ?? deal.tonSender)).storeAddress(Address.parse(deal.tonTaker ?? deal.tonRecipient)).endCell())
    .storeRef(walletCode).endCell();
  return { code: Cell.fromBase64(HTLC_CODE_B64), data };
}

async function jettonFacts() {
  const base = quote.chain === 'testnet' ? 'https://testnet.toncenter.com/api/v2' : 'https://toncenter.com/api/v2';
  const r = await fetch(`${base}/runGetMethod`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: quote.master, method: 'get_jetton_data', stack: [] }) }).then(x => x.json());
  if (!r.ok) throw new Error('жетон не читается: ' + JSON.stringify(r.error).slice(0, 100));
  return Cell.fromBase64(r.result.stack[4][1].bytes);
}
const jwData = (owner, master, code) => quote.governed
  ? beginCell().storeUint(0, 4).storeCoins(0).storeAddress(owner).storeAddress(master).endCell()
  : beginCell().storeCoins(0).storeAddress(owner).storeAddress(master).storeRef(code).endCell();
const jwOf = (owner, master, code) => {
  const si = beginCell().storeUint(0, 2).storeMaybeRef(code).storeMaybeRef(jwData(owner, master, code)).storeUint(0, 1).endCell();
  return new Address(0, si.hash());
};

// ---- step 1: the form --------------------------------------------------------------------------
async function start() {
  quote = await api('quote');
  const perToken = quote.rateSatsPerJetton * 10 ** quote.decimals;   // sats per one whole jetton
  show('rate', `1 ${quote.symbol} ≈ ${perToken.toLocaleString('ru-RU', { maximumFractionDigits: 4 })} сат · лимиты ${fmtJ(quote.minJettons)}–${fmtJ(quote.maxJettons)} ${quote.symbol}`);
  // the form first: a wallet-library failure must never leave a dead page
  $('jettons').oninput = () => {
    const raw = BigInt(Math.round(Number($('jettons').value || 0) * 10 ** quote.decimals));
    const sats = Math.floor(Number(raw) * quote.rateSatsPerJetton);
    show('btcOut', raw > 0n ? (dir === 'fwd' ? `≈ ${fmtSats(sats)}` : `отдашь ≈ ${fmtSats(sats)}`) : '');
  };
  const remembered = localStorage.getItem(A_KEY);
  if (remembered) $('payout').value = remembered;
  $('go').onclick = () => (dir === 'fwd' ? begin() : beginReverse()).catch(e => show('status', 'не вышло: ' + e.message));
  $('dirFwd').onclick = () => setDir('fwd');
  $('dirBack').onclick = () => setDir('back');
  setDir('fwd');
  try {
    ui = new TonConnectUI({ manifestUrl: location.origin + '/tonconnect-manifest.json', buttonRootId: 'connect',
      actionsConfiguration: { returnStrategy: 'back' } });
    ui.onStatusChange(w => { if (w) show('status', ''); });
  }
  catch (e) { show('status', 'кошелёк не инициализировался: ' + e.message + ' — обнови страницу'); return; }
  if (deal) resume();
  else {
    lockForm(false, 'Обменять');
    const left = strays();
    if (left.length) show('status', `Есть незавершённая сделка (${left[0].id}). Средства по ней вернутся по таймауту.`);
  }
}

// ---- forward: jettons in, sats out -------------------------------------------------------------
async function begin() {
  if (deal) return show('status', 'сделка уже идёт — дождись её конца или верни токены по таймауту');
  if (!ui.account) return show('status', 'сначала подключи кошелёк — кнопка выше');
  const jettons = BigInt(Math.round(Number($('jettons').value || 0) * 10 ** quote.decimals));
  const payout = $('payout').value.trim();
  try { bech32Decode(payout); } catch { return show('status', 'введи BTC-адрес выплаты (bc1…)'); }
  if (!payout.startsWith(HRP() + '1')) return show('status', `адрес не из этой сети — нужен ${HRP()}1…`);
  localStorage.setItem(A_KEY, payout);
  const secret = rand32();
  const claimKey = rand32();
  const hash = await sha256hex(secret);
  const me = Address.parse(ui.account.address).toString({ bounceable: false, testOnly: quote.chain === 'testnet' });
  const o = await api('offer', { jettons: String(jettons), hash,
    claimPub: pubkeyCompressed(claimKey), btcPayout: payout, tonGiver: me });
  deal = { id: o.id, secret, claimKey, hash, jettons: String(jettons), sats: o.sats, payout,
    tonGiver: me, tonTaker: o.tonTaker, tonDeadline: o.tonDeadline, phase: 'lock' };
  save(deal);
  await lockJettons();
}

// ---- step 2: lock the jettons with the visitor's own wallet ------------------------------------
async function lockJettons() {
  step(2);
  lockForm(true, 'запираем токены…');
  const walletCode = await jettonFacts();
  const init = tonLockInit(walletCode);
  const htlc = contractAddress(0, init);
  show('status', `запираем ${fmtJ(deal.jettons)} ${quote.symbol} — подтверди в кошельке`);
  const me = Address.parse(deal.tonGiver);
  const transfer = beginCell()
    .storeUint(OP.transfer, 32).storeUint(1n, 64).storeCoins(BigInt(deal.jettons))
    .storeAddress(htlc).storeAddress(me).storeUint(0, 1)
    .storeCoins(toNano('0.05')).storeUint(0, 1).endCell();
  await ui.sendTransaction({
    validUntil: Math.floor(Date.now() / 1000) + 300,
    messages: [
      { address: htlc.toString(), amount: toNano('0.04').toString(),
        stateInit: beginCell().storeUint(6, 5).storeRef(init.code).storeRef(init.data).endCell().toBoc().toString('base64') },
      { address: jwOf(me, Address.parse(quote.master), walletCode).toString(), amount: toNano('0.13').toString(),
        payload: transfer.toBoc().toString('base64') },
    ],
  });
  deal.phase = 'wait-btc'; deal.tonAddress = htlc.toString(); save(deal);
  poll();
}

// ---- step 3: wait for the daemon's BTC lock, verify it, claim ----------------------------------
async function poll() {
  step(3);
  lockForm(true, 'сделка идёт…');
  for (;;) {
    let st;
    try { st = await api('status', { id: deal.id }); } catch { await sleep(7000); continue; }
    if (st.state === 'open' || st.state === 'jetton-locked') {
      const t = 'Токены заперты. Ждём, пока вторая сторона запрёт BTC…';
      if ($('status').textContent !== t) show('status', t);
    }
    if (st.state === 'btc-locked' && st.btcRawTx) {
      if ((st.btcConfirmations ?? 0) >= 1) return claimBtc(st);
      $('status').innerHTML = `<a href="${explorer(st.btcLock.txid)}" target="_blank" rel="noopener">BTC заперты в цепи и ждут подтверждения сетью</a>`;
    }
    if (st.state === 'claimed' || st.state === 'done') return finish(st);
    if (st.state === 'expired') return show('status', 'срок вышел, сделка не состоялась. Токены вернутся по таймауту — кнопка возврата появится после срока.');
    await sleep(7000);
  }
}

async function claimBtc(st) {
  // trust nothing: rebuild the lock we expect and check the daemon's transaction against it
  const script = btcHtlcScript({ paymentHash: deal.hash, claimPub: pubkeyCompressed(deal.claimKey),
    refundPub: st.housePub, cltv: st.btcCltv });
  const raw = st.btcRawTx;
  const expectedSpk = btcHtlcSpk(script).toString('hex');
  // find our output in the raw funding tx (spk match + amount), then check the txid matches bytes
  const txidReal = st.btcLock.txid;
  if (!raw.includes(expectedSpk)) return show('status', 'BTC-замок не совпал с расчётным — стоп, ничего не подписываем');
  show('status', `BTC заперты (${fmtSats(st.sats)}). Забираем на ${deal.payout}…`);
  const claim = buildClaim({ script,
    funding: { txid: txidReal, vout: st.btcLock.vout ?? 0, sats: BigInt(st.sats) },
    preimage: deal.secret, claimKey: deal.claimKey, toSpk: spkOfAddress(deal.payout),
    fee: BigInt(Math.min(Number(st.claimFee ?? 400), 1500)) });   // market rate; capped so a rogue quote cannot eat the payout
  // the daemon is the broadcast path; keep the raw tx on screen so any node can carry it instead
  deal.claimRawtx = claim.raw; save(deal);
  const r = await api('claim', { id: deal.id, rawtx: claim.raw });
  deal.phase = 'claimed'; deal.btcClaimTxid = r.txid; save(deal);
  finish({ btcClaimTxid: r.txid });
}

function finish(st) {
  step(4);
  const t = st.btcClaimTxid ?? deal.btcClaimTxid;
  $('done').hidden = false; $('form').hidden = true;
  show('doneAddr', deal.payout);
  const a = $('expl'); if (a && t) { a.href = explorer(t); a.hidden = false; a.textContent = 'посмотреть выплату в обозревателе'; }
  if (deal.claimRawtx) { $('rawWrap').hidden = false; show('rawtx', deal.claimRawtx); }
  forget(deal);
}

// ---- reverse: sats in, jettons out -------------------------------------------------------------
async function beginReverse() {
  if (deal) return show('status', 'сделка уже идёт — дождись её конца');
  if (!ui.account) return show('status', 'подключи Tonkeeper — туда придут токены');
  const jettons = BigInt(Math.round(Number($('jettons').value || 0) * 10 ** quote.decimals));
  const secret = rand32();
  const refundKey = rand32();
  const hash = await sha256hex(secret);
  const me = Address.parse(ui.account.address).toString({ bounceable: false, testOnly: quote.chain === 'testnet' });
  const o = await api('offerReverse', { jettons: String(jettons), hash,
    btcRefundPub: pubkeyCompressed(refundKey), tonRecipient: me });
  // derive the lock address OURSELVES from the terms; refuse if the daemon names a different one
  const script = btcHtlcScript({ paymentHash: hash, claimPub: o.btcClaimPub,
    refundPub: pubkeyCompressed(refundKey), cltv: o.btcCltv });
  const myAddr = btcHtlcAddress(script, HRP());
  if (myAddr !== o.btcAddress) return show('status', 'адрес замка не сходится с условиями — стоп');
  deal = { id: o.id, dir: 'back', secret, refundKey, hash, jettons: String(jettons), sats: o.sats,
    tonRecipient: me, tonSender: o.tonSender, tonDeadline: o.tonDeadline,
    btcAddress: myAddr, btcCltv: o.btcCltv, btcClaimPub: o.btcClaimPub, phase: 'pay-btc' };
  save(deal);
  payBtc();
}

function payBtc() {
  step(2);
  lockForm(true, 'ждём оплату…');
  $('paybox').hidden = false;
  show('payAmount', fmtSats(deal.sats));
  show('payAddr', deal.btcAddress);
  $('payCopy').onclick = () => { navigator.clipboard?.writeText(deal.btcAddress); show('status', 'адрес скопирован'); };
  show('status', 'Отправь точную сумму с любого BTC-кошелька. Как только платёж подтвердится, вторая сторона запрёт токены.');
  pollReverse();
}

async function pollReverse() {
  for (;;) {
    let st;
    try { st = await api('statusReverse', { id: deal.id }); } catch { await sleep(9000); continue; }
    if (st.state === 'jettons-locked' || st.state === 'reverse-stuck') { $('paybox').hidden = true; return takeJettons(); }
    if (st.state === 'done') return finishReverse();
    if (st.state === 'expired' || st.state === 'jettons-refunded') return refundBtcUi('сделка не состоялась.');
    await sleep(9000);
  }
}

// claiming the jettons is the visitor's action: make the button be it, retryable
async function takeJettons() {
  step(3);
  const walletCode = await jettonFacts();
  const init = tonLockInit(walletCode);
  const htlc = contractAddress(0, init);
  const claim = async () => {
    show('status', 'подтверди в Tonkeeper…');
    $('go').disabled = true;
    try {
      await ui.sendTransaction({
        validUntil: Math.floor(Date.now() / 1000) + 300,
        messages: [{ address: htlc.toString(), amount: toNano('0.1').toString(),
          payload: beginCell().storeUint(0x636c6169, 32).storeUint(2n, 64).storeBuffer(Buffer.from(deal.secret, 'hex')).endCell().toBoc().toString('base64') }],
      });
      deal.phase = 'claimed'; save(deal);
      finishReverse();
    } catch (e) {
      show('status', 'выкуп не подтверждён — нажми «Забрать покупку», чтобы попробовать снова');
      $('go').disabled = false;
    }
  };
  const go = $('go');
  go.disabled = false; go.textContent = 'Забрать покупку';
  go.onclick = claim;
  show('status', 'Токены заперты и ждут тебя.');
  claim();
}

function finishReverse() {
  step(4);
  $('done').hidden = false; $('form').hidden = true;
  $('done').querySelector('dt').textContent = 'Токены отправлены на';
  show('doneAddr', deal.tonRecipient);
  const a = $('expl');
  if (a) { a.href = (quote.chain === 'testnet' ? 'https://testnet.tonviewer.com/' : 'https://tonviewer.com/') + deal.tonRecipient; a.hidden = false; a.textContent = 'посмотреть кошелёк в tonviewer'; }
  forget(deal);
}

// the reverse deal died after the visitor paid: build the refund HERE with the ephemeral key.
// It is valid only after the lock's height passes; until then we show it and explain.
async function refundBtcUi(prefix) {
  const payout = localStorage.getItem(A_KEY) || '';
  show('status', prefix + ' Если BTC уже ушли, они вернутся: после блока ' + deal.btcCltv +
    ' нажми «Вернуть BTC» и укажи адрес возврата.');
  $('refund').hidden = false;
  $('refund').textContent = 'Вернуть BTC (после срока)';
  $('refund').onclick = async () => {
    const to = prompt('BTC-адрес для возврата:', payout);
    if (!to) return;
    try {
      const st = await api('statusReverse', { id: deal.id });
      // the daemon tells us where the deposit sits; we rebuild and sign locally
      const script = btcHtlcScript({ paymentHash: deal.hash, claimPub: deal.btcClaimPub,
        refundPub: pubkeyCompressed(deal.refundKey), cltv: deal.btcCltv });
      const funding = st.btcLockUtxo;
      if (!funding) return show('status', 'депозит не найден — если ты платил, напиши нам, разберём вручную');
      const r = buildRefund({ script, funding: { txid: funding.txid, vout: funding.vout, sats: BigInt(funding.sats) },
        cltv: deal.btcCltv, refundKey: deal.refundKey, toSpk: spkOfAddress(to), fee: 400n });
      $('rawWrap').hidden = false; show('rawtx', r.raw);
      show('status', 'возврат собран и подписан — отправь его через любой узел Bitcoin (sendrawtransaction), или мы отправим: транзакция ниже.');
      await api('broadcast', { rawtx: r.raw }).then(x => show('status', 'возврат отправлен: ' + x.txid)).catch(() => {});
    } catch (e) { show('status', 'возврат не собрался: ' + e.message); }
  };
}

// after the deadline the jettons walk home on a single wallet message (forward direction)
async function refundJettons() {
  if (!deal?.tonAddress) return;
  await ui.sendTransaction({ validUntil: Math.floor(Date.now() / 1000) + 300,
    messages: [{ address: deal.tonAddress, amount: toNano('0.15').toString(),
      payload: beginCell().storeUint(OP.refund, 32).storeUint(3n, 64).endCell().toBoc().toString('base64') }] });
  show('status', 'возврат отправлен — токены вернутся на твой кошелёк');
}

function resume() {
  setDirLocked();
  if (deal.dir === 'back') {
    dir = 'back'; setDirLocked();
    $('jettons').value = Number(deal.jettons) / 10 ** quote.decimals;
    if (deal.phase === 'pay-btc') return payBtc();
    pollReverse();
    return;
  }
  $('jettons').value = Number(deal.jettons) / 10 ** quote.decimals;
  $('payout').value = deal.payout || '';
  show('btcOut', `≈ ${fmtSats(deal.sats)}`);
  if (deal.phase === 'lock') lockJettons().catch(e => show('status', e.message));
  else poll();
  if (Date.now() / 1000 > deal.tonDeadline) { $('refund').hidden = false; $('refund').onclick = refundJettons; }
}

function setDirLocked() {
  $('dirFwd').classList.toggle('on', dir === 'fwd');
  $('dirBack').classList.toggle('on', dir === 'back');
  $('payoutWrap').hidden = dir !== 'fwd';
}

function setDir(d) {
  if (deal) return;
  dir = d;
  $('dirFwd').classList.toggle('on', d === 'fwd');
  $('dirBack').classList.toggle('on', d === 'back');
  $('payoutWrap').hidden = d !== 'fwd';          // forward: where to be paid. reverse: not needed
  $('paybox').hidden = true;
  $('jettons').parentElement.childNodes[0].textContent = d === 'fwd' ? 'Сколько токенов отдаёшь' : 'Сколько токенов хочешь получить';
  $('jettons').dispatchEvent(new Event('input'));
  show('status', '');
}

function lockForm(on, label) {
  for (const id of ['jettons', 'go', 'payout']) { const e = $(id); if (e) e.disabled = on; }
  if (label) $('go').textContent = label;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
start().catch(e => show('status', 'ошибка: ' + (e?.message || e)));
