// EPOCH REFORM e2e: an offline/abandoned covenant member must NOT be able to
// deadlock new joins forever. Flow: player A deposits + genesis (covenant = {A}).
// A then goes OFFLINE. Player B deposits post-genesis — cooperative auto-join
// CANNOT run (input 0 is N-of-N and A is gone). Once the covenant reaches its
// CLTV expiry, the engine REFORMS it via the engine-only expiry script path
// (no member cosign): it carries A's claim forward AND absorbs B, all without A.
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube),
//         engine built with a short COVENANT_EXPIRY_WINDOW (144).
// Run:    node epoch_reform_test.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { attachCosign } from './cosign_client.mjs';
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
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };
const tag512 = (t, m) => { const x = sha512(enc.encode(t)); return sha512(cat(x, x, m)); };
const blsScalar = (secp) => { let x = 0n; for (const c of tag512('Cube/bls/secretkey', secp).slice(0, 48)) x = (x << 8n) | BigInt(c); return x % Fr.ORDER; };
const blsPub = (secp) => bls.G1.Point.BASE.multiply(blsScalar(secp)).toBytes();
const newPlayer = () => { const s = new Uint8Array(32); crypto.getRandomValues(s); return { secpHex: bytesToHex(s), secp: s, accountKey: bytesToHex(schnorr.getPublicKey(s)), blsKey: bytesToHex(blsPub(s)) }; };

async function connect(p) {
  const ws = new WebSocket(WS);
  await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
  attachCosign(ws, p.secpHex, p.accountKey, (k, d) => { if (k === 'reject') console.log('  cosign reject', JSON.stringify(d)); });
  p.ws = ws;
  await sleep(400);
}

async function depositClaim(p, amount) {
  const da = await get(`/api/deposit_address?account=${p.accountKey}`);
  const tx = cli(`sendtoaddress ${da.address} ${amount}`);
  cli('-generate 1');
  const vout = cliJSON(`getrawtransaction ${tx} true`).vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
  if (!(await post('/api/deposit', { account_key: p.accountKey, txid: tx, vout })).ok) fail('deposit');
  const csig = bytesToHex(schnorr.sign(tag256('Cube/sighash/arcade/deposit-claim', cat(hexToBytes(p.accountKey), hexToBytes(p.blsKey))), p.secp));
  const cr = await post('/api/deposit/claim', { account_key: p.accountKey, bls_key: p.blsKey, sig: csig });
  if (!cr.ok) fail('claim', JSON.stringify(cr));
}
const inCov = (cov, acct) => (cov.allocations || []).filter(([h]) => h.toLowerCase() === acct.toLowerCase()).reduce((s, [, v]) => s + Number(v), 0);

async function main() {
  const A = newPlayer(), B = newPlayer();

  // A deposits 0.40 + genesis -> covenant = {A}.
  await connect(A);
  await depositClaim(A, 0.40);
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));
  let cov = (await get('/api/covenant')).covenant;
  if (!cov) fail('no covenant after genesis');
  const genesisTxid = cov.txid, genesisExpiry = Number(cov.expiry);
  console.log(`genesis covenant ${cov.txid.slice(0, 12)}… value ${cov.value} expiry ${genesisExpiry}; A in cov: ${inCov(cov, A.accountKey)}`);
  if (inCov(cov, A.accountKey) === 0) fail('A not in genesis covenant');

  // A ABANDONS the covenant (goes offline). From here on A never cosigns again.
  A.ws.close();
  console.log('A went OFFLINE (abandoned). A will not cosign anything from here.');
  await sleep(500);

  // B deposits 0.30 post-genesis and stays online.
  await connect(B);
  await depositClaim(B, 0.30);

  // Phase 1: cooperative join must NOT succeed (A is offline → N-of-N can't run).
  // Give it a few ticks (well before expiry) and confirm the covenant is unchanged.
  console.log('B deposited; confirming cooperative join is BLOCKED while A is offline (pre-expiry)…');
  for (let i = 0; i < 5; i++) { cli('-generate 1'); await sleep(3000); }
  cov = (await get('/api/covenant')).covenant;
  if (cov.txid !== genesisTxid) fail('covenant changed before expiry — join should have been blocked by offline A', JSON.stringify(cov));
  if (inCov(cov, B.accountKey) !== 0) fail('B absorbed before expiry — should be impossible without A');
  console.log('  confirmed: covenant unchanged, B not absorbed (offline A correctly blocks cooperative join).');

  // Phase 2: push the chain PAST the covenant expiry → engine reforms unilaterally.
  console.log(`mining past expiry (${genesisExpiry}) so the engine can reform via the expiry path…`);
  cli('-generate 150');
  let reformed = false;
  for (let i = 0; i < 60; i++) {
    cli('-generate 1');
    await sleep(3000);
    cov = (await get('/api/covenant')).covenant;
    if (cov && cov.txid !== genesisTxid && inCov(cov, B.accountKey) > 0) { reformed = true; break; }
  }
  if (!reformed) fail('engine did not reform the covenant after expiry', JSON.stringify(cov));

  const a = inCov(cov, A.accountKey), b = inCov(cov, B.accountKey);
  console.log(`reformed covenant ${cov.txid.slice(0, 12)}… value ${cov.value} expiry ${cov.expiry}; A=${a} B=${b}`);
  if (Number(cov.expiry) <= genesisExpiry) fail('reformed covenant did not advance its expiry', String(cov.expiry));
  if (a === 0) fail('A (the offline member) was dropped — reform must carry every existing claim forward');
  if (b === 0) fail('B not absorbed into the reformed covenant');
  if (b < 29_900_000) fail('B claim too small', String(b));
  if (a < 39_900_000) fail('A claim shrank unexpectedly', String(a));
  if (cov.value !== a + b) fail('covenant value != Σ claims', `${cov.value} != ${a + b}`);

  B.ws.close();
  console.log('\nPASS — an offline/abandoned member (A) could NOT deadlock the covenant: cooperative join was correctly blocked pre-expiry, then once the covenant reached expiry the ENGINE reformed it via the expiry path (no A cosign), carrying A\'s claim forward AND absorbing B. New joins/withdrawals are liveness-independent.');
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
