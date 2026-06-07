// Watchtower test on regtest: build a covenant + its pre-signed unroll, then
// simulate the engine going SILENT (covenant sits unspent for staleBlocks). The
// watchtower — holding only public data, no key — broadcasts the unroll so
// holders can exit. Proves liveness-free exit even if the engine disappears.
//
// Prereq: regtest bitcoind at /tmp/cube-regtest (wallet 'cube') + cosign server.
// Run:    node cosign_watchtower_test.mjs

import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { liftV2Spk } from './covenant.mjs';
import { bytesToHex } from './musig.mjs';
import { makeCli, watchAndGuard } from './watchtower.mjs';

const BASE = 'http://127.0.0.1:8099';
const WS = 'ws://127.0.0.1:8099/cosign';
const cli = makeCli('/tmp/cube-regtest', 'cube');
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
const reverseHex = (h) => h.match(/../g).reverse().join('');
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

function newPlayer() {
  const s = new Uint8Array(32);
  globalThis.crypto.getRandomValues(s);
  return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) };
}

async function main() {
  const engineKey = (await (await fetch(`${BASE}/engine`)).json()).engine_key;
  const players = [newPlayer(), newPlayer()];
  const sockets = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey);
    sockets.push(ws);
  }
  for (let i = 0; i < 40; i++) {
    const r = await (await fetch(`${BASE}/connected`)).json();
    if (players.every((p) => (r.connected || []).includes(p.accountKey))) break;
    await sleep(100);
  }

  // fund + genesis.
  const amounts = [0.5, 0.5];
  const deposits = players.map((p, i) => {
    const spk = liftV2Spk(p.accountKey, engineKey).spk;
    const addr = cliJSON(`decodescript ${spk}`).address;
    return { account: p.accountKey, spk, fundTxid: cli(`sendtoaddress ${addr} ${amounts[i]}`), value: sat(amounts[i]) };
  });
  cli('-generate 1');
  for (const d of deposits) {
    const raw = cliJSON(`getrawtransaction ${d.fundTxid} true`);
    d.prev_vout = raw.vout.find((o) => o.scriptPubKey.hex === d.spk).n;
    d.prev_txid = reverseHex(d.fundTxid);
  }
  const GEN_FEE = 1000;
  const gres = await (await fetch(`${BASE}/genesis`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ deposits: deposits.map((d) => ({ account: d.account, prev_txid: d.prev_txid, prev_vout: d.prev_vout, prev_value: d.value })), fee: GEN_FEE }) })).json();
  if (!gres.ok) fail('genesis', gres.error);
  const genTxid = cli(`sendrawtransaction ${gres.signed_tx}`);
  cli('-generate 1');
  const genTx = cliJSON(`getrawtransaction ${genTxid} true`);
  const allocs = gres.covenant_allocations;
  const covValue = gres.covenant_value;
  const covVout = genTx.vout.findIndex((o) => o.value && sat(o.value) === covValue);

  // pre-sign the unroll (engine + players online now) — but DON'T broadcast it.
  const ures = await (await fetch(`${BASE}/unroll`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ allocations: allocs, prev_txid: reverseHex(genTxid), prev_vout: covVout, prev_value: covValue, exit_delay: 6, fee: 1000 }) })).json();
  if (!ures.ok || !ures.valid) fail('unroll pre-sign', ures.error);
  console.log(`covenant ${genTxid.slice(0, 16)}…:${covVout} live; unroll pre-signed (held by watchtower)`);

  // players + engine "disappear".
  for (const ws of sockets) ws.close();

  // engine goes SILENT: the covenant sits unspent while blocks tick by.
  const baseline = parseInt(cli('getblockcount'), 10);
  cli('-generate 3');

  // the watchtower (only public data, no key) notices and broadcasts the unroll.
  const res = await watchAndGuard({
    cli, covenantTxid: genTxid, covenantVout: covVout, unrollHex: ures.signed_tx,
    staleBlocks: 3, baselineHeight: baseline, log: (m) => console.log('  watchtower:', m),
  });
  if (!res.fired) fail('watchtower did not fire', res.reason);
  cli('-generate 1');

  // covenant is now spent by the unroll; leaves exist for unilateral exit.
  const spent = cli(`gettxout ${genTxid} ${covVout}`) === '';
  const unrollTx = cliJSON(`getrawtransaction ${res.unrollTxid} true`);
  console.log(`UNROLL broadcast by watchtower: ${res.unrollTxid.slice(0, 16)}…  (${unrollTx.vout.length} leaves, ${unrollTx.confirmations} conf)`);

  if (spent && unrollTx.confirmations >= 1) {
    console.log('\nPASS — watchtower forced the pot into exitable VTXO leaves with no key and nobody online.');
    process.exit(0);
  }
  fail('covenant not unrolled');
}

main().catch((e) => { console.error(e); process.exit(1); });
