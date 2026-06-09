// DISSOLVE e2e: the liveness-failure escape that guarantees nobody is ever trapped
// in an unexitable covenant. Flow: A deposits + genesis -> covenant {A} WITH a
// pre-signed unroll (atomic presign). A goes OFFLINE. B deposits; cooperative join
// is blocked (A offline). Once the covenant hits expiry, the engine DISSOLVES it via
// the expiry path -> A's funds return to A's own LiftV2 output (unilaterally
// exitable), and auto-genesis re-pools the ONLINE player B into a fresh covenant {B}
// that again has a pre-signed unroll. A's L2 balance is preserved (NOT double-
// credited), and A can still withdraw its funds afterward.
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube),
//         engine built with COVENANT_EXPIRY_WINDOW=144.
// Run:    node dissolve_test.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { attachCosign, setPendingWithdrawSpk } from './cosign_client.mjs';
import { bytesToHex, hexToBytes } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const DD = '/tmp/cube-regtest';
const Fr = bls.fields.Fr;
const enc = new TextEncoder();
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const get = async (p) => (await fetch(`${BASE}${p}`)).json();
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };
const cat = (...a) => { const arr = a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))); const n = arr.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of arr) { o.set(x, i); i += x.length; } return o; };
const u64le = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };
const tag512 = (t, m) => { const x = sha512(enc.encode(t)); return sha512(cat(x, x, m)); };
const blsScalar = (secp) => { let x = 0n; for (const c of tag512('Cube/bls/secretkey', secp).slice(0, 48)) x = (x << 8n) | BigInt(c); return x % Fr.ORDER; };
const blsPub = (secp) => bls.G1.Point.BASE.multiply(blsScalar(secp)).toBytes();
const blsSign = (secp, h) => bls.G2.hashToCurve(h, { DST: enc.encode('Cube/bls/message') }).multiply(blsScalar(secp)).toBytes();
const newPlayer = () => { const s = new Uint8Array(32); crypto.getRandomValues(s); return { secpHex: bytesToHex(s), secp: s, accountKey: bytesToHex(schnorr.getPublicKey(s)), blsKey: bytesToHex(blsPub(s)) }; };
const inCov = (cov, acct) => (cov?.allocations || []).filter(([h]) => h.toLowerCase() === acct.toLowerCase()).reduce((s, [, v]) => s + Number(v), 0);

async function connect(p) {
  const ws = new WebSocket(WS);
  await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
  attachCosign(ws, p.secpHex, p.accountKey, (k, d) => { if (k === 'reject') console.log('  cosign reject', JSON.stringify(d)); });
  p.ws = ws; await sleep(400);
}
async function depositClaim(p, amount) {
  const da = await get(`/api/deposit_address?account=${p.accountKey}`);
  const tx = cli(`sendtoaddress ${da.address} ${amount}`);
  cli('-generate 1');
  const vout = cliJSON(`getrawtransaction ${tx} true`).vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
  if (!(await post('/api/deposit', { account_key: p.accountKey, txid: tx, vout })).ok) fail('deposit');
  const csig = bytesToHex(schnorr.sign(tag256('Cube/sighash/arcade/deposit-claim', cat(hexToBytes(p.accountKey), hexToBytes(p.blsKey))), p.secp));
  if (!(await post('/api/deposit/claim', { account_key: p.accountKey, bls_key: p.blsKey, sig: csig })).ok) fail('claim');
}
const bal = async (p) => ((await get(`/api/state?account=${p.accountKey}`)).account || {}).balance || 0;

async function main() {
  const A = newPlayer(), B = newPlayer();

  // A deposits 0.40 + genesis -> covenant {A}; assert the unroll is presigned ATOMICALLY.
  await connect(A);
  await depositClaim(A, 0.40);
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));
  let st = await get('/api/covenant');
  if (!st.covenant) fail('no covenant after genesis');
  if (!st.unroll_present) fail('genesis covenant has NO pre-signed unroll (atomic presign broken)');
  const genesisTxid = st.covenant.txid, genesisExpiry = Number(st.covenant.expiry);
  const aBal0 = await bal(A);
  console.log(`genesis covenant {A}=${inCov(st.covenant, A.accountKey)} unroll_present=${st.unroll_present}; A balance ${aBal0}`);

  // A ABANDONS (offline). B deposits 0.30 and stays online.
  A.ws.close(); await sleep(500);
  console.log('A went OFFLINE.');
  await connect(B);
  await depositClaim(B, 0.30);

  // Pre-expiry: cooperative join must stay blocked (A offline) — covenant unchanged.
  for (let i = 0; i < 4; i++) { cli('-generate 1'); await sleep(2500); }
  st = await get('/api/covenant');
  if (st.covenant && st.covenant.txid !== genesisTxid) fail('covenant changed before expiry (join should be blocked by offline A)');
  console.log('pre-expiry: covenant unchanged, B not absorbed (correct).');

  // Past expiry: engine DISSOLVES {A} -> A's LiftV2 output, then re-pools online B.
  console.log(`mining past expiry (${genesisExpiry}) so the engine dissolves + re-pools…`);
  cli('-generate 150');
  let done = false;
  for (let i = 0; i < 60; i++) {
    cli('-generate 1'); await sleep(3000);
    st = await get('/api/covenant');
    if (st.covenant && inCov(st.covenant, B.accountKey) > 0) { done = true; break; }
  }
  if (!done) fail('engine did not re-pool B after dissolve', JSON.stringify(st));

  // The new covenant should be {B} ONLY, with a fresh pre-signed unroll.
  const bIn = inCov(st.covenant, B.accountKey), aIn = inCov(st.covenant, A.accountKey);
  console.log(`reformed covenant {B}=${bIn} {A}=${aIn} unroll_present=${st.unroll_present} txid=${st.covenant.txid.slice(0, 12)}…`);
  if (bIn === 0) fail('B not pooled after dissolve');
  if (aIn !== 0) fail('A (offline) should NOT be in the new covenant — dissolve must evict, not carry');
  if (!st.unroll_present) fail('re-pooled covenant has NO pre-signed unroll (atomic presign broken)');

  // CRITICAL: A's L2 balance must be preserved exactly (no double-credit, not zeroed).
  const aBal1 = await bal(A);
  console.log(`A balance after dissolve: ${aBal1} (was ${aBal0})`);
  if (aBal1 !== aBal0) fail(`A's balance changed across dissolve (double-credit or loss): ${aBal0} -> ${aBal1}`);

  // A reconnects and withdraws its (now un-pooled, LiftV2) funds cooperatively.
  await connect(A);
  await sleep(1500);
  const dest = cli('getnewaddress');
  const spk = cliJSON(`getaddressinfo ${dest}`).scriptPubKey;
  setPendingWithdrawSpk(spk);
  const amt = await bal(A);
  const wsh = tag256('Cube/sighash/arcade/withdraw', cat(hexToBytes(A.accountKey), u64le(amt), enc.encode(dest)));
  const w = await post('/api/withdraw', { account_key: A.accountKey, bls_key: A.blsKey, address: dest, amount: amt, bls_signature: bytesToHex(blsSign(A.secp, wsh)) });
  setPendingWithdrawSpk(null);
  if (!w.ok) fail('A could not withdraw its dissolved funds', JSON.stringify(w));
  cli('-generate 1');
  const recv = cliJSON(`getreceivedbyaddress ${dest} 0`);
  console.log(`A withdrew ${w.withdrawn} sats; address received ${recv} BTC`);
  if (Math.round(recv * 1e8) < 39_000_000) fail('A did not receive its withdrawal on-chain', String(recv));

  B.ws.close(); A.ws.close();
  console.log('\nPASS — an offline member was DISSOLVED to its own exitable LiftV2 output (not trapped); the online player was re-pooled into a fresh covenant WITH a pre-signed unroll; balances were preserved (no double-credit); and the evicted member could still withdraw its funds. Nobody is ever stuck in an unexitable pot.');
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
