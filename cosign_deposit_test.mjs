// End-to-end test of the live LiftV2 deposit lift-in cosign: a depositor (random
// secp key, like a browser) connects, the engine drives a cooperative 2-of-2
// (account+engine) taproot key-path cosign over WebSocket, and we assert the
// aggregate is a valid key-path spend of the deposit output key.
//
// Prereq:  cargo run --bin cosign_test_server   (in ./server, :8099)
// Run:     node cosign_deposit_test.mjs

import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8099';
const WS = 'ws://127.0.0.1:8099/cosign';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const secp = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secp);
  const secpHex = bytesToHex(secp);
  const accountKey = bytesToHex(schnorr.getPublicKey(secp)); // x-only (even-Y)

  const ws = new WebSocket(WS);
  await new Promise((res, rej) => {
    ws.addEventListener('open', res, { once: true });
    ws.addEventListener('error', rej, { once: true });
  });
  const events = [];
  attachCosign(ws, secpHex, accountKey, (kind, detail) => events.push({ kind, ...detail }));

  // wait for registration.
  for (let i = 0; i < 40; i++) {
    const r = await (await fetch(`${BASE}/connected`)).json();
    if ((r.connected || []).includes(accountKey)) break;
    await sleep(100);
  }

  const res = await (await fetch(`${BASE}/deposit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ account: accountKey, prev_value: 100000, fee: 300 }),
  })).json();

  console.log('--- protocol events ---');
  for (const e of events) console.log(`  ${e.kind}${e.session ? ' ' + e.session : ''}`);
  console.log('\n--- deposit result ---');
  console.log('  ok:     ', res.ok);
  console.log('  valid:  ', res.valid);
  console.log('  agg_key:', res.agg_key);
  console.log('  txid:   ', res.txid);

  ws.close();
  if (res.ok && res.valid) {
    console.log('\nPASS — LiftV2 deposit lift-in cosign produced a valid 2-of-2 key-path signature.');
    process.exit(0);
  } else {
    console.error('\nFAIL —', res.error || 'signature did not verify');
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
