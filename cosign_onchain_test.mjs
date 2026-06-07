// ON-CHAIN validation on regtest: prove the cosign stack produces REAL,
// consensus-valid Bitcoin transactions. We fund a LiftV2 deposit for each player,
// combine them into the pot covenant (GENESIS, multi-input), then move the pot
// (REFRESH), broadcasting both with bitcoin-cli and asserting they confirm. This
// validates taproot key-path verification against Bitcoin Core itself.
//
// Prereq:  regtest bitcoind at /tmp/cube-regtest (wallet 'cube', funded) and
//          cargo run --bin cosign_test_server  (:8099)
// Run:     node cosign_onchain_test.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { liftV2Spk } from './covenant.mjs';
import { bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8099';
const WS = 'ws://127.0.0.1:8099/cosign';
const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
// bitcoin-cli prints display (big-endian) txids; the tx serializer / Txid::from_byte_array
// wants internal (reversed) byte order in the outpoint.
const reverseHex = (h) => h.match(/../g).reverse().join('');

function newPlayer() {
  const s = new Uint8Array(32);
  globalThis.crypto.getRandomValues(s);
  return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) };
}
const mine = (n = 1) => cli(`-generate ${n}`);
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

async function main() {
  const engineKey = (await (await fetch(`${BASE}/engine`)).json()).engine_key;
  console.log('engine key:', engineKey);

  const players = [newPlayer(), newPlayer(), newPlayer()];
  const sockets = [];
  const events = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, (k, d) => events.push({ who: p.accountKey.slice(0, 6), k, ...d }));
    sockets.push(ws);
  }
  for (let i = 0; i < 40; i++) {
    const r = await (await fetch(`${BASE}/connected`)).json();
    if (players.every((p) => (r.connected || []).includes(p.accountKey))) break;
    await sleep(100);
  }

  // 1) fund a real LiftV2 deposit UTXO for each player.
  const amounts = [0.30, 0.40, 0.50];
  const deposits = players.map((p, i) => {
    const spk = liftV2Spk(p.accountKey, engineKey).spk;
    const addr = cliJSON(`decodescript ${spk}`).address;
    const fundTxid = cli(`sendtoaddress ${addr} ${amounts[i]}`);
    return { account: p.accountKey, spk, addr, fundTxid, value: sat(amounts[i]) };
  });
  mine(1);
  for (const d of deposits) {
    const raw = cliJSON(`getrawtransaction ${d.fundTxid} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === d.spk);
    if (!vout) fail('deposit vout not found', d.addr);
    d.prev_txid = reverseHex(d.fundTxid); // internal byte order for the outpoint
    d.prev_vout = vout.n;
  }
  console.log('funded deposits:', deposits.map((d) => `${d.addr.slice(0, 12)}…=${d.value}`).join(', '));

  // 2) GENESIS: deposits -> one pot covenant. Broadcast + confirm.
  const GEN_FEE = 1000;
  const gres = await (await fetch(`${BASE}/genesis`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deposits: deposits.map((d) => ({ account: d.account, prev_txid: d.prev_txid, prev_vout: d.prev_vout, prev_value: d.value })), fee: GEN_FEE }),
  })).json();
  if (!gres.ok) fail('genesis cosign', gres.error);
  let genTxid;
  try { genTxid = cli(`sendrawtransaction ${gres.signed_tx}`); }
  catch (e) { fail('genesis broadcast rejected by bitcoind', String(e.stderr || e)); }
  mine(1);
  const genTx = cliJSON(`getrawtransaction ${genTxid} true`);
  console.log(`\nGENESIS confirmed: ${genTxid.slice(0, 16)}…  (${genTx.vin.length} deposit inputs -> 1 covenant, ${genTx.confirmations} conf)`);

  // use the SERVER's canonical covenant allocations (avoids fee-ambiguity).
  const allocs = gres.covenant_allocations;
  const covValue = gres.covenant_value;
  const covVout = genTx.vout.findIndex((o) => o.value && sat(o.value) === covValue);
  if (covVout < 0) fail('covenant vout not found', covValue);

  // 3) REFRESH: move the pot covenant forward (N-of-N). Broadcast + confirm.
  const REF_FEE = 1000;
  const rres = await (await fetch(`${BASE}/trigger`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ allocations: allocs, prev_txid: reverseHex(genTxid), prev_vout: covVout, prev_value: covValue, fee: REF_FEE }),
  })).json();
  if (!rres.ok || !rres.valid) fail('refresh cosign', rres.error);
  let refTxid;
  try { refTxid = cli(`sendrawtransaction ${rres.signed_tx}`); }
  catch (e) { fail('refresh broadcast rejected by bitcoind', String(e.stderr || e)); }
  mine(1);
  const refTx = cliJSON(`getrawtransaction ${refTxid} true`);
  console.log(`REFRESH confirmed: ${refTxid.slice(0, 16)}…  (spends covenant -> new covenant, ${refTx.confirmations} conf)`);

  for (const ws of sockets) ws.close();

  const rejected = events.filter((e) => e.k === 'reject');
  if (genTx.confirmations >= 1 && refTx.confirmations >= 1 && rejected.length === 0) {
    console.log('\nPASS — deposit -> genesis -> refresh all confirmed on regtest. The cosign');
    console.log('stack produces consensus-valid taproot key-path spends.');
    process.exit(0);
  } else {
    fail('not all txs confirmed or a client rejected', JSON.stringify(rejected));
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
