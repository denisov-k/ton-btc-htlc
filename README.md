# ton-btc-htlc

Atomic swaps between a TON jetton and Bitcoin. No bridge, no custodian, no wrapped anything:
one SHA-256 secret opens two hash-time-locked contracts on two chains, or two timeouts return
two deposits. Sibling of [ton-jetton-htlc](https://github.com/denisov-k/ton-jetton-htlc), which
swaps the same jetton against Freicoin.

## How a swap works

Forward (jetton → BTC), as the visitor sees it:

1. Their browser invents a 32-byte secret and an ephemeral Bitcoin key. Neither leaves the page.
2. They lock jettons into the FunC HTLC (`contracts/htlc.fc`) with their own wallet via
   TON Connect. The lock pays out against the secret's SHA-256 hash, refundable after a deadline.
3. The desk daemon verifies that lock — amount, hash, contract code hash, timing — and answers
   with a Bitcoin P2WSH HTLC carrying the same hash: claimable by the visitor's ephemeral key
   with the secret, refundable to the desk after a shorter deadline. (Shorter is not an accident:
   whoever reveals the secret must be working against the shorter clock.)
4. The page re-derives the P2WSH script itself and checks the daemon's funding transaction byte
   for byte. Only then does it sign the claim — revealing the secret on Bitcoin — and the payout
   lands on whatever address the visitor named.
5. The daemon reads the secret out of the claim's witness and takes the jettons. Either both
   happened or, after the timeouts, both sides took their money back.

Reverse (BTC → jetton) mirrors it: the visitor's browser derives the P2WSH address from the
agreed terms (refund key ephemeral, in-browser), they pay it from any Bitcoin wallet, the daemon
locks jettons for them, the Tonkeeper claim reveals the secret on TON, and the daemon claims the
BTC. If the deal dies, the page builds and signs the refund locally — after the locktime, the
deposit walks home.

## The Bitcoin script

Classic swap HTLC, spendable two ways:

```
OP_IF
  OP_SHA256 <hash32> OP_EQUALVERIFY <claimPub> OP_CHECKSIG
OP_ELSE
  <cltv> OP_CHECKLOCKTIMEVERIFY OP_DROP <refundPub> OP_CHECKSIG
OP_ENDIF
```

wrapped in P2WSH, signed BIP143. The implementation (`driver/btc-tx.mjs`) is dependency-light,
pure JS, and identical in the daemon and the browser bundle — the page verifies with the same
code the daemon builds with.

## Layout

```
contracts/htlc.fc       the TON-side FunC contract (same deployed code as ton-jetton-htlc)
core/                   vendored crypto: secp256k1 ECDSA (RFC6979), hashes via @noble/hashes
driver/btc-tx.mjs       pure Bitcoin primitives: script, bech32, BIP143, claim/refund builders
driver/btc-leg.mjs      node glue: bitcoin-cli, funding from the daemon's own p2wpkh coins
driver/ton-leg.mjs      TON glue: client, wallet, jetton lock deploy/fund/claim/refund
driver/botd.mjs         the swap-desk daemon: HTTP API + a state machine per deal
web/                    the one-page desk the visitor uses
deploy/                 systemd unit
```

## Running the desk

The daemon wants a config (see `driver/botd.signet.json` for the shape): a Bitcoin node
(pruned is fine — everything works off `scantxoutset`/`gettxout`), a hot key file for its BTC
side, a TON wallet mnemonic for its jetton side, a rate, and limits.

```
BOTD_CONFIG=driver/botd.signet.json node driver/botd.mjs
npm run page        # bundle web/dist/swap.js
```

The state machines survive restarts: every deal is journaled to disk on every transition, and
each direction knows how to refund, finish late, or leave the counterparty's money alone.

## What is deliberately not here

- **No AML / provenance screening.** Out of scope for now; run small limits.
- **No price feed.** The rate is quoted by the operator in the config.
- **No custody.** At no point does either side hold both legs; the deepest trust left is that
  the daemon is also the visitor's broadcast path — and the page keeps the signed raw
  transaction on screen so any Bitcoin node can carry it instead.

## Status

The Bitcoin leg is exercised end-to-end on signet (fund → claim-with-secret, fund → refund-after-
timeout, wrong-preimage rejection). The TON leg is the same deployed contract already carrying
live mainnet swaps in ton-jetton-htlc. The desk currently runs against signet BTC while the
jetton side is mainnet — flip the config to `"net": "main"` when the reserves are funded.
