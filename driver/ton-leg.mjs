// ton-leg.mjs — the TON half: derive the contract for a given lock, deploy it, read its state,
// claim with a preimage, refund after the deadline, and pull the preimage back out of the chain
// once someone else has revealed it. Everything is a parameter; nothing about a particular swap
// is baked in.
import { TonClient, WalletContractV4, internal } from '@ton/ton';
import { Address, Cell, beginCell, contractAddress, toNano } from '@ton/core';
import { mnemonicToPrivateKey } from '@ton/crypto';
import { readFileSync } from 'fs';

export const OP = { transfer: 0xf8a7ea5, notify: 0x7362d09c, claim: 0x636c6169, refund: 0x72656664, rescue: 0x72657363 };
const sleep = ms => new Promise(r => setTimeout(r, ms));

export const retry = async (fn, tries = 8) => {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) { if (i >= tries) throw e; await sleep(2000 * (i + 1)); }
  }
};

export async function tonClient({ endpoint, apiKey } = {}) {
  const raw = new TonClient({ endpoint: endpoint || 'https://toncenter.com/api/v2/jsonRPC', apiKey });
  const _unused = async (fn, tries = 8) => {
    for (let i = 0; ; i++) {
      try { return await fn(); } catch (e) { if (i >= tries) throw e; await sleep(2000 * (i + 1)); }
    }
  };
  const READ = new Set(['getContractState', 'runMethod', 'callGetMethod', 'getBalance', 'getTransactions']);
  return new Proxy(raw, {
    get(t, k) {
      const v = t[k];
      if (typeof v !== 'function') return v;
      if (!READ.has(k)) return v.bind(t);
      return async (...a) => { await sleep(500); return retry(() => v.apply(t, a)); };
    },
  });
}

export async function tonWallet(client, mnemonicFile) {
  const { mnemonic } = JSON.parse(readFileSync(mnemonicFile, 'utf8'));
  const key = await mnemonicToPrivateKey(mnemonic);
  const wallet = client.open(WalletContractV4.create({ workchain: 0, publicKey: key.publicKey }));
  const send = async (to, value, body, init) => {
    // running out of gas looks exactly like a network fault from the outside; say which it is
    const have = await retry(() => client.getBalance(wallet.address));
    if (have < value + 10000000n) {
      throw new Error(`not enough TON for gas: have ${Number(have) / 1e9}, need about ${Number(value + 10000000n) / 1e9}`);
    }
    const seqno = await retry(() => wallet.getSeqno());
    // re-sending the same external message is harmless: the wallet accepts one seqno once
    await retry(() => wallet.sendTransfer({ seqno, secretKey: key.secretKey,
      messages: [internal({ to, value, body, init, bounce: !init })] }));
    for (let i = 0; i < 90; i++) {
      await sleep(2500);
      try { if (await retry(() => wallet.getSeqno(), 2) > seqno) return; } catch {}
    }
    throw new Error('TON transfer did not confirm');
  };
  return { address: wallet.address, send };
}

/** The contract for one lock. Deterministic: both sides can compute it before anything is sent. */
export function tonLock({ codeCell, paymentHash, deadline, master, walletCode, governed, sender, recipient }) {
  const data = beginCell()
    .storeUint(BigInt('0x' + paymentHash), 256).storeUint(deadline, 32)
    .storeUint(0, 1).storeUint(governed ? 1 : 0, 1).storeCoins(0)
    .storeRef(beginCell().storeAddress(master).storeAddress(sender).storeAddress(recipient).endCell())
    .storeRef(walletCode)
    .endCell();
  const init = { code: codeCell, data };
  return { init, address: contractAddress(0, init), paymentHash, deadline };
}

export async function tonDeploy(wallet, client, lock, value = '0.05') {
  await wallet.send(lock.address, toNano(value), beginCell().endCell(), lock.init);
  for (let i = 0; i < 40; i++) {
    if ((await client.getContractState(lock.address)).state === 'active') return;
    await sleep(3000);
  }
  throw new Error('the lock never went active');
}

/** Push jettons into a lock. forward_ton_amount must be enough for the notice to run. */
export const tonFund = (wallet, myJettonWallet, lock, amount, response, gas = '0.2', forward = '0.1') =>
  wallet.send(myJettonWallet, toNano(gas), beginCell()
    .storeUint(OP.transfer, 32).storeUint(1n, 64).storeCoins(amount)
    .storeAddress(lock.address).storeAddress(response).storeUint(0, 1)
    .storeCoins(toNano(forward)).storeUint(0, 1).endCell());

export const tonClaim = (wallet, lock, preimageHex, gas = '0.15') =>
  wallet.send(lock.address, toNano(gas), beginCell()
    .storeUint(OP.claim, 32).storeUint(2n, 64).storeBuffer(Buffer.from(preimageHex, 'hex')).endCell());

export const tonRefund = (wallet, lock, gas = '0.15') =>
  wallet.send(lock.address, toNano(gas), beginCell()
    .storeUint(OP.refund, 32).storeUint(3n, 64).endCell());

export async function tonState(client, lock) {
  const st = await client.getContractState(lock.address);
  if (st.state !== 'active') return { deployed: false };
  // a freshly deployed contract can be 'active' on one node and unknown on the next one we hit
  let r;
  try { r = await client.runMethod(lock.address, 'get_state'); }
  catch { return { deployed: true, funded: false, amount: 0n }; }
  return { deployed: true, funded: r.stack.readNumber() === 1, amount: r.stack.readBigNumber(),
    hash: r.stack.readBigNumber().toString(16).padStart(64, '0'), deadline: r.stack.readNumber() };
}

/** Jetton facts: the wallet a given owner holds, its balance, and the jetton's wallet code. */
export async function jetton(client, master) {
  const d = await client.runMethod(master, 'get_jetton_data');
  d.stack.readBigNumber(); d.stack.readNumber(); d.stack.readAddressOpt(); d.stack.readCell();
  const walletCode = d.stack.readCell();
  const walletOf = async owner => (await client.runMethod(master, 'get_wallet_address',
    [{ type: 'slice', cell: beginCell().storeAddress(owner).endCell() }])).stack.readAddress();
  const balanceOf = async owner => {
    try { return (await client.runMethod(await walletOf(owner), 'get_wallet_data')).stack.readBigNumber(); }
    catch { return 0n; }
  };
  return { master, walletCode, walletOf, balanceOf };
}

/** Read the preimage back out of the chain: scan the lock's incoming messages for a claim. */
export async function tonRevealedPreimage(client, lock) {
  const txs = await client.getTransactions(lock.address, { limit: 30 });
  for (const tx of txs) {
    const body = tx.inMessage?.body;
    if (!body) continue;
    try {
      const s = body.beginParse();
      if (s.remainingBits < 32 + 64 + 256) continue;
      if (s.loadUint(32) !== OP.claim) continue;
      s.loadUintBig(64);
      return s.loadBuffer(32).toString('hex');
    } catch {}
  }
  return null;
}

export { Address, Cell, beginCell, toNano };
