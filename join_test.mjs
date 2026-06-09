// DEPOSIT ABSORPTION (join) e2e: a player who deposits AFTER genesis is absorbed
// into the existing covenant, so their funds become covenant-backed (instead of
// sitting at a separate LiftV2 address, decoupled from the pot). Flow: player A
// deposits + genesis (covenant = {A}); player B deposits later; the engine's
// auto-join spends [covenant + B's deposit] into a new covenant = {A, B}.
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube).
// Run:    node join_test.mjs

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
  for (const p of [A, B]) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, (k, d) => { if (k === 'reject') console.log('  cosign reject', JSON.stringify(d)); });
    p.ws = ws;
  }
  await sleep(800);

  // A deposits 0.40 + genesis -> covenant = {A}.
  await depositClaim(A, 0.40);
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));
  let cov = (await get('/api/covenant')).covenant;
  if (!cov) fail('no covenant after genesis');
  console.log(`genesis covenant ${cov.txid.slice(0, 12)}… value ${cov.value}; A in cov: ${inCov(cov, A.accountKey)}`);
  if (inCov(cov, A.accountKey) === 0) fail('A not in genesis covenant');
  if (inCov(cov, B.accountKey) !== 0) fail('B unexpectedly already in covenant');

  // B deposits 0.30 AFTER genesis -> auto-join should absorb B into the covenant.
  await depositClaim(B, 0.30);
  console.log('B deposited post-genesis; waiting for auto-join to absorb B…');
  const genesisTxid = cov.txid;
  let joined = false;
  for (let i = 0; i < 40; i++) {
    cli('-generate 1'); // nudge the watcher / chain
    await sleep(3000);
    cov = (await get('/api/covenant')).covenant;
    if (cov && cov.txid !== genesisTxid && inCov(cov, B.accountKey) > 0) { joined = true; break; }
  }
  if (!joined) fail('auto-join did not absorb B in time', JSON.stringify(cov));

  const a = inCov(cov, A.accountKey), b = inCov(cov, B.accountKey);
  console.log(`joined covenant ${cov.txid.slice(0, 12)}… value ${cov.value}; A=${a} B=${b}`);
  if (a === 0) fail('A dropped from covenant after join');
  if (b === 0) fail('B not absorbed into covenant');
  // B's claim should be ~0.30 (30M minus its share of fee); A ~0.40.
  if (b < 29_900_000) fail('B claim too small', String(b));
  if (a < 39_900_000) fail('A claim shrank unexpectedly', String(a));
  // both deposits now backed on-chain by one covenant.
  if (cov.value !== a + b) fail('covenant value != Σ claims', `${cov.value} != ${a + b}`);

  for (const p of [A, B]) p.ws.close();
  console.log('\nPASS — a post-genesis deposit was ABSORBED into the existing covenant (covenant = {A,B}); both players are now covenant-backed. The covenant tracks the game.');
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
