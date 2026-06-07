// Verify the native-JS garble challenger reproduces the engine's Rust garbling:
// fetch a settle assertion from the LIVE arcade and confirm an honest winner yields
// no secret while a wrong winner yields the disprove secret that opens the lock.
// Run (arcade on :8090 with a covenant): node verify_garble.mjs

import { sha256 } from '@noble/hashes/sha2.js';
import { challenge } from './garble.mjs';

const BASE = 'http://127.0.0.1:8090';
const post = (p, b) => fetch(BASE + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }).then((r) => r.json());
const hex = (u) => Array.from(u, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));

async function main() {
  const honest = await post('/api/settle_assertion', { seed: 5000 });
  if (!honest.ok) { console.error('FAIL — settle_assertion:', honest.error); process.exit(1); }
  const wrongIdx = honest.honest_winner === 1 ? 2 : 1;

  const hsecret = challenge(honest.assertion, honest.rg);
  const wrong = await post('/api/settle_assertion', { seed: 5000, winner: wrongIdx });
  const wsecret = challenge(wrong.assertion, wrong.rg);

  console.log(`honest winner ${honest.honest_winner}: challenge -> ${hsecret} (expect null)`);
  console.log(`wrong winner ${wrongIdx}:  challenge -> ${wsecret ? wsecret.slice(0, 16) + '…' : null}`);

  const opens = wsecret !== null && hex(sha256(fromHex(wsecret))) === wrong.disprove_hash;
  if (hsecret === null && wsecret !== null && opens) {
    console.log('\nPASS — native-JS garble.mjs matches the engine garbling; the derived secret opens the round disprove lock. No WASM.');
    process.exit(0);
  }
  console.error('\nFAIL — JS challenge did not match the engine garbling');
  process.exit(1);
}
main().catch((e) => { console.error(e); process.exit(1); });
