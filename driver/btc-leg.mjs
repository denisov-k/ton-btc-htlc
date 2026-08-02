// btc-leg.mjs — the node-side half of the Bitcoin leg: talk to bitcoind over bitcoin-cli, fund
// the HTLC from a key's own p2wpkh coins, broadcast claims and refunds. All transaction math
// lives in btc-tx.mjs (pure, shared with the browser); this file is only glue and signing flow.
import { execFileSync } from 'node:child_process';
import { pubkeyCompressed } from '../core/ecdsa.mjs';
import { btcHtlcSpk, btcWpkSpk, btcAddress, serialize, sighash143, derSig, wpkScriptCode,
         buildClaim, buildRefund } from './btc-tx.mjs';
export { btcHtlcScript, btcHtlcSpk, btcHtlcAddress, btcWpkSpk, btcAddress, spkOfAddress,
         bech32Encode, bech32Decode } from './btc-tx.mjs';

export function btcNode({ bin = '/root/bitcoin-core/bin/bitcoin-cli', args = [] } = {}) {
  const cli = (...a) => execFileSync(bin, [...args, ...a], { encoding: 'utf8' }).trim();
  const json = (...a) => JSON.parse(cli(...a));
  // the node runs one scantxoutset at a time; when someone else's scan is in flight, wait it out
  const scan = descs => {
    for (let i = 0; ; i++) {
      try { return json('scantxoutset', 'start', JSON.stringify(descs)); }
      catch (e) {
        if (!String(e.stderr || e.message).includes('already in progress') || i >= 10) throw e;
        execFileSync('sleep', ['2']);
      }
    }
  };
  return {
    cli, json, scan,
    tip: () => json('getblockcount'),
    // confirmed coins of an address. scantxoutset reads the UTXO set, so mempool spends of these
    // coins are invisible — the gettxout re-check keeps us from double-building on one coin.
    coins(address) {
      return (scan([`addr(${address})`]).unspents ?? [])
        .map(u => ({ txid: u.txid, vout: u.vout, sats: BigInt(Math.round(u.amount * 1e8)), height: u.height }))
        .filter(u => { try { return !!cli('gettxout', u.txid, String(u.vout)); } catch { return false; } });
    },
    outAt(txid, vout) { try { return json('gettxout', txid, String(vout)); } catch { return null; } },
    send(rawHex) { return cli('sendrawtransaction', rawHex); },
    mempoolHas(txid) { try { cli('getmempoolentry', txid); return true; } catch { return false; } },
  };
}

/** Fund `sats` into the HTLC from the key's own p2wpkh coins; change back to the key. */
export function btcFund({ node, key, script, sats, fee = 400n, hrp = 'bc' }) {
  const pub = pubkeyCompressed(key);
  const coins = node.coins(btcAddress(key, hrp));
  const picked = []; let total = 0n;
  for (const c of coins) { picked.push(c); total += c.sats; if (total >= sats + fee) break; }
  if (total < sats + fee) throw new Error(`not enough BTC: have ${total}, need ${sats + fee}`);
  const outs = [{ sats, spk: btcHtlcSpk(script) }];
  const change = total - sats - fee;
  if (change >= 294n) outs.push({ sats: change, spk: btcWpkSpk(pub) });
  const tx = { version: 2, ins: picked.map(c => ({ txid: c.txid, vout: c.vout })), outs, locktime: 0 };
  tx.ins.forEach((inp, i) => {
    const digest = sighash143(tx, i, wpkScriptCode(pub), picked[i].sats);
    inp.witness = [derSig(key, digest), Buffer.from(pub, 'hex')];
  });
  const raw = serialize(tx).toString('hex');
  return { txid: node.send(raw), vout: 0, raw };
}

/** Spend the HTLC with the preimage to `toSpk` and broadcast. */
export function btcClaim({ node, script, funding, preimage, claimKey, toSpk, fee = 300n }) {
  const { raw } = buildClaim({ script, funding, preimage, claimKey, toSpk, fee });
  return { txid: node.send(raw), raw };
}

/** Take the HTLC back after the timeout and broadcast. */
export function btcRefund({ node, script, funding, cltv, refundKey, toSpk, fee = 300n }) {
  const { raw } = buildRefund({ script, funding, cltv, refundKey, toSpk, fee });
  return { txid: node.send(raw), raw };
}
