// NEGATIVE test: a malicious engine tries to divert the pot (refresh output paid
// to an engine-only key) while advertising the honest covenant in the context.
// A verifying client must REBUILD the covenant + sighash, detect the mismatch,
// and REFUSE to sign — so the cosign never completes (no theft).
//
// Prereq:  cargo run --bin cosign_test_server   (in ./server, :8099)
// Run:     node cosign_evil_test.mjs

import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8099';
const WS = 'ws://127.0.0.1:8099/cosign';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function newPlayer() {
  const secp = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secp);
  return { secpHex: bytesToHex(secp), accountKey: bytesToHex(schnorr.getPublicKey(secp)) };
}

async function main() {
  const players = [newPlayer(), newPlayer()];
  const allocations = players.map((p, i) => ({ account: p.accountKey, value: 25000 + i * 5000 }));

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
  for (let i = 0; i < 40; i++) {
    const r = await (await fetch(`${BASE}/connected`)).json();
    if (players.every((p) => (r.connected || []).includes(p.accountKey))) break;
    await sleep(100);
  }

  const res = await (await fetch(`${BASE}/trigger_evil`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ allocations }),
  })).json();

  console.log('--- protocol events ---');
  for (const e of events) console.log(`  [${e.who}] ${e.kind}${e.errors ? ' :: ' + e.errors.join('; ') : ''}`);
  console.log('\n--- evil trigger result ---');
  console.log('  ok:   ', res.ok, '(expected false — cosign must NOT complete)');
  console.log('  error:', res.error);

  for (const ws of sockets) ws.close();

  const everyoneRejected = players.every((p) =>
    events.some((e) => e.who === p.accountKey.slice(0, 8) && e.kind === 'reject'));
  const noPartials = !events.some((e) => e.kind === 'partial');

  if (!res.ok && everyoneRejected && noPartials) {
    console.log('\nPASS — every client detected the theft and refused; the pot could not move.');
    process.exit(0);
  } else {
    console.error('\nFAIL — a malicious refresh was NOT blocked as expected.');
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
