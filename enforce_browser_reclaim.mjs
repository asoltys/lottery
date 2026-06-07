// Proves the SHARED browser reclaim path (dispute.mjs) end-to-end: a "tab"
// (participant key) deposits + cosigns a covenant; the engine settles a WRONG
// winner and pre-signs the disprove-locked unroll; the tab then calls the exact
// browser code (disputeAndReclaim) — broadcasting via /api/broadcast (the relay a
// real browser uses) — to detect the fraud and take back its own leaf. If this
// passes, the in-browser reclaim works (the browser bundles the same dispute.mjs).
//
// Prereq: lottery-engine on :8090 (with /api/settle + /api/broadcast) + regtest.
// Run:    node enforce_browser_reclaim.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { disputeAndReclaim } from './dispute.mjs';
import { verifyCutChoose } from './garble.mjs';
import { bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

// the browser's broadcast: POST the signed tx to the arcade relay.
const browserBroadcast = async (txHex) => {
  const r = await post('/api/broadcast', { tx_hex: txHex });
  if (!r.ok) throw new Error(r.error);
  return r.txid;
};

function newPlayer() {
  const s = new Uint8Array(32);
  globalThis.crypto.getRandomValues(s);
  return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) };
}

async function main() {
  const SEED = 5000;
  const players = [newPlayer(), newPlayer(), newPlayer()];
  const sockets = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey);
    sockets.push(ws);
  }
  await sleep(800);

  // deposit + genesis.
  const amounts = [0.30, 0.40, 0.50];
  for (let i = 0; i < players.length; i++) {
    const da = await (await fetch(`${BASE}/api/deposit_address?account=${players[i].accountKey}`)).json();
    const fundTxid = cli(`sendtoaddress ${da.address} ${amounts[i]}`);
    cli('-generate 1');
    const raw = cliJSON(`getrawtransaction ${fundTxid} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
    await post('/api/deposit', { account_key: players[i].accountKey, txid: fundTxid, vout });
  }
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok) fail('genesis', JSON.stringify(g));

  // engine settles a WRONG winner + pre-signs the disprove-locked unroll.
  const total = g.covenant_value;
  const honest = await post('/api/settle', { seed: SEED });
  const wrongIdx = honest.honest_winner === 1 ? 2 : 1;
  const settle = await post('/api/settle', { seed: SEED, winner: wrongIdx });
  if (!settle.ok) fail('settle', JSON.stringify(settle));
  // cut-and-choose: re-garble the opened instances and verify honest garbling.
  const opened = verifyCutChoose(settle);
  console.log(`cut-and-choose: re-garbled + verified ${opened}/${settle.k} opened instances (settle uses unopened #${settle.settle_instance}).`);

  // THE TAB (player 0) runs the exact browser code to detect + reclaim.
  const tab = players[0];
  const leaf = settle.leaves.find((l) => l.account.toLowerCase() === tab.accountKey.toLowerCase());
  if (!leaf) fail('tab has no leaf in the settle');
  const trueRg = Number(BigInt(SEED) % (BigInt(total) * 476n)); // tab recomputes the draw
  const destSpk = '5120' + tab.accountKey; // reclaim to the tab's own key (P2TR)

  const res = await disputeAndReclaim({
    assertion: settle.assertion, trueRg,
    unrollTxHex: settle.unroll_tx_hex, unrollTxid: settle.unroll_txid,
    leaf, secpHex: tab.secpHex, destSpk, broadcast: browserBroadcast,
  });
  for (const ws of sockets) ws.close();

  if (!res.fraud) fail('tab did not detect the fraud');
  cli('-generate 1');
  const tx = cliJSON(`getrawtransaction ${res.reclaimTxid} true`);
  console.log(`tab detected fraud (secret ${res.secret.slice(0, 12)}…)`);
  console.log(`unroll ${res.unrollTxid.slice(0, 16)}… broadcast via /api/broadcast`);
  console.log(`RECLAIM ${res.reclaimTxid.slice(0, 16)}… took back ${res.outValue} sat (${tx.confirmations} conf)`);
  if (tx.confirmations >= 1) {
    console.log('\nPASS — the in-browser reclaim path works: a tab detects a false settle AND takes');
    console.log('back its own on-chain VTXO leaf, broadcasting through the relay, all native JS.');
    process.exit(0);
  }
  fail('reclaim not confirmed');
}
main().catch((e) => { console.error(e); process.exit(1); });
