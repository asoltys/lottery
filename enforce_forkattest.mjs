// Live connector-bound fork-attest reclaim (the full exit-ladder graph, on-chain).
// Same setup as enforce_browser_reclaim, but the tab reclaims via a tx::fork-attest
// that spends [its leaf disprove-path, an exit-ladder connector]. Both signatures
// commit the connector, so the dispute is bound to the canonical exit-ladder and
// the engine can't dodge onto a fork. All native JS (shared dispute.mjs).
//
// Prereq: lottery-engine on :8090 + regtest bitcoind /tmp/cube-regtest.
// Run:    node enforce_forkattest.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { forkAttestReclaim } from './dispute.mjs';
import { verifyCutChoose } from './garble.mjs';
import { bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
const reverseHex = (h) => h.match(/../g).reverse().join('');
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };
const broadcast = async (txHex) => { const r = await post('/api/broadcast', { tx_hex: txHex }); if (!r.ok) throw new Error(r.error); return r.txid; };
function newPlayer() { const s = new Uint8Array(32); globalThis.crypto.getRandomValues(s); return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) }; }

// The exit-ladder: fund the connector spk (the tab's BIP86 P2TR). Returns its outpoint.
const provideConnector = async (spk) => {
  const addr = cliJSON(`decodescript ${spk}`).address;
  const txid = cli(`sendtoaddress ${addr} 0.0001`);
  cli('-generate 1');
  const raw = cliJSON(`getrawtransaction ${txid} true`);
  const v = raw.vout.find((o) => o.scriptPubKey.hex === spk);
  if (!v) throw new Error('connector vout not found');
  return { txidInternal: reverseHex(txid), vout: v.n, value: Math.round(v.value * 1e8) };
};

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

  const honest = await post('/api/settle', { seed: SEED });
  const wrongIdx = honest.honest_winner === 1 ? 2 : 1;
  const settle = await post('/api/settle', { seed: SEED, winner: wrongIdx });
  if (!settle.ok) fail('settle', JSON.stringify(settle));
  const opened = verifyCutChoose(settle);
  console.log(`cut-and-choose: verified ${opened}/${settle.k} opened (settle unopened #${settle.settle_instance}).`);

  const tab = players[0];
  const leaf = settle.leaves.find((l) => l.account.toLowerCase() === tab.accountKey.toLowerCase());
  if (!leaf) fail('tab has no leaf');
  const trueRg = Number(BigInt(SEED) % (BigInt(g.covenant_value) * 476n));
  const destSpk = cliJSON(`getaddressinfo ${cli('getnewaddress')}`).scriptPubKey;

  const res = await forkAttestReclaim({
    assertion: settle.assertion, trueRg,
    unrollTxHex: settle.unroll_tx_hex, unrollTxid: settle.unroll_txid,
    leaf, secpHex: tab.secpHex, accountKey: tab.accountKey,
    destSpk, broadcast, provideConnector,
  });
  for (const ws of sockets) ws.close();
  if (!res.fraud) fail('tab did not detect fraud');
  cli('-generate 1');
  const tx = cliJSON(`getrawtransaction ${res.reclaimTxid} true`);
  console.log(`fork-attest ${res.reclaimTxid.slice(0, 16)}… spent [leaf disprove, connector] -> ${res.outValue} sat (${tx.confirmations} conf, ${tx.vin.length} inputs)`);
  if (tx.confirmations >= 1 && tx.vin.length === 2) {
    console.log('\nPASS — live connector-bound fork-attest: the tab reclaimed via [leaf disprove-path,');
    console.log('exit-ladder connector], binding the dispute to the canonical exit-ladder. Native JS.');
    process.exit(0);
  }
  fail('fork-attest reclaim not confirmed as a 2-input tx');
}
main().catch((e) => { console.error(e); process.exit(1); });
