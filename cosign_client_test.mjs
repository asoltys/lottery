// End-to-end test of the live WS refresh-cosign: spin up N players (each with a
// random secp key, like a browser tab), connect them to the cosign test server,
// then trigger a refresh and assert the engine aggregates their partials into a
// valid N-of-N Projector key-path signature over the old covenant key.
//
// Prereq:  cargo run --bin cosign_test_server   (in ./server, listens on :8099)
// Run:     node cosign_client_test.mjs

import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { bytesToHex, hexToBytes } from './musig.mjs';

const BASE = 'http://127.0.0.1:8099';
const WS = 'ws://127.0.0.1:8099/cosign';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function newPlayer() {
  const secp = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secp);
  const secpHex = bytesToHex(secp);
  const accountKey = bytesToHex(schnorr.getPublicKey(secp)); // x-only (even-Y)
  return { secpHex, accountKey };
}

async function main() {
  const players = [newPlayer(), newPlayer(), newPlayer()];
  const allocations = players.map((p, i) => ({ account: p.accountKey, value: 20000 + i * 5000 }));

  // connect each player and attach the cosign handler.
  const sockets = [];
  const events = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });
    attachCosign(ws, p.secpHex, p.accountKey, (kind, detail) =>
      events.push({ who: p.accountKey.slice(0, 8), kind, ...detail }));
    sockets.push(ws);
  }

  // wait until the server registers all of them.
  let registered = [];
  for (let i = 0; i < 40; i++) {
    const r = await (await fetch(`${BASE}/connected`)).json();
    registered = r.connected || [];
    if (players.every((p) => registered.includes(p.accountKey))) break;
    await sleep(100);
  }
  console.log(`connected players: ${registered.length}/${players.length}`);
  if (registered.length < players.length) { console.error('FAIL: not all players connected'); process.exit(1); }

  // trigger the refresh; the server collects nonces+partials over the sockets.
  const res = await (await fetch(`${BASE}/trigger`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ allocations }),
  })).json();

  console.log('\n--- protocol events ---');
  for (const e of events) console.log(`  [${e.who}] ${e.kind}${e.session ? ' ' + e.session : ''}`);

  console.log('\n--- trigger result ---');
  console.log('  ok:        ', res.ok);
  console.log('  valid:     ', res.valid);
  console.log('  agg_key:   ', res.agg_key);
  console.log('  message:   ', res.message);
  console.log('  agg_sig:   ', res.agg_sig);
  console.log('  txid:      ', res.txid);

  for (const ws of sockets) ws.close();

  if (res.ok && res.valid) {
    console.log('\nPASS — N-of-N live cosign produced a valid Projector key-path signature.');
    process.exit(0);
  } else {
    console.error('\nFAIL —', res.error || 'signature did not verify');
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
