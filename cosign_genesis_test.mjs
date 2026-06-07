// End-to-end test of GENESIS: several depositors (random keys, like browser tabs)
// each hold a LiftV2 deposit; the engine combines them in ONE multi-input tx whose
// single output is the pot covenant. Each depositor cosigns only its own input,
// verifying the whole tx + its covenant claim. Proves multi-input lift-in.
//
// Prereq:  cargo run --bin cosign_test_server   (in ./server, :8099)
// Run:     node cosign_genesis_test.mjs

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
// a distinct fake funding txid per depositor (their on-chain LiftV2 deposit UTXO).
const fakeTxid = (i) => (i + 1).toString(16).padStart(2, '0').repeat(32);

async function main() {
  const players = [newPlayer(), newPlayer(), newPlayer()];
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

  const deposits = players.map((p, i) => ({
    account: p.accountKey,
    prev_txid: fakeTxid(i),
    prev_vout: 0,
    prev_value: 30000 + i * 10000,
  }));

  const res = await (await fetch(`${BASE}/genesis`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deposits, fee: 500 }),
  })).json();

  console.log('--- protocol events ---');
  for (const e of events) console.log(`  [${e.who}] ${e.kind}${e.errors ? ' :: ' + e.errors.join('; ') : ''}`);
  console.log('\n--- genesis result ---');
  console.log('  ok:    ', res.ok);
  console.log('  valid: ', res.valid);
  console.log('  txid:  ', res.txid);
  console.log('  tx len:', res.signed_tx ? res.signed_tx.length / 2 + ' bytes' : '—');

  for (const ws of sockets) ws.close();

  // every depositor must have cosigned (nonce + partial), none rejected.
  const allSigned = players.every((p) => {
    const k = p.accountKey.slice(0, 8);
    return events.some((e) => e.who === k && e.kind === 'partial');
  });
  const anyReject = events.some((e) => e.kind === 'reject');

  if (res.ok && res.valid && allSigned && !anyReject) {
    console.log('\nPASS — multi-input genesis: all deposits cosigned into one pot covenant.');
    process.exit(0);
  } else {
    console.error('\nFAIL —', res.error || 'genesis did not complete cleanly');
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
