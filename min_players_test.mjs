// MIN-PLAYERS gate e2e: a round must NOT start its draw countdown until at least
// 2 DISTINCT players have entered. With one player in, the countdown stays parked
// at the full duration and no draw happens; once a second distinct player enters,
// the countdown begins (time_left drops below the full duration).
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube).
// Run:    node min_players_test.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
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
const u16le = (n) => Uint8Array.from([n & 0xff, (n >> 8) & 0xff]);
const u32le = (n) => { const b = new Uint8Array(4); let v = n >>> 0; for (let i = 0; i < 4; i++) { b[i] = v & 0xff; v >>>= 8; } return b; };
const u64le = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };
const tag512 = (t, m) => { const x = sha512(enc.encode(t)); return sha512(cat(x, x, m)); };
const blsScalar = (secp) => { let x = 0n; for (const c of tag512('Cube/bls/secretkey', secp).slice(0, 48)) x = (x << 8n) | BigInt(c); return x % Fr.ORDER; };
const blsPub = (secp) => bls.G1.Point.BASE.multiply(blsScalar(secp)).toBytes();
const blsSign = (secp, h) => bls.G2.hashToCurve(h, { DST: enc.encode('Cube/bls/message') }).multiply(blsScalar(secp)).toBytes();
const newPlayer = () => { const s = new Uint8Array(32); crypto.getRandomValues(s); return { secpHex: bytesToHex(s), secp: s, accountKey: bytesToHex(schnorr.getPublicKey(s)), blsKey: bytesToHex(blsPub(s)) }; };
const sat = (btc) => Math.round(btc * 1e8);

function encCall(c) {
  const account = cat([0x02], hexToBytes(c.accountKey), u64le(c.registeryIndex), hexToBytes(c.blsKey));
  const contract = cat(hexToBytes(c.contractId), u64le(c.contractRegisteryIndex));
  let cd = u32le(1); cd = cat(cd, [0x09], u32le(c.amount));
  return cat([0x01], u32le(account.length), account, u32le(contract.length), contract, u16le(0), u32le(cd.length), cd, [0x00], u64le(c.opsPrice), u64le(c.target));
}
const callSighash = (c) => tag256('Cube/sighash/entry/call', encCall(c));

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

async function enter(p, amount) {
  const st = await get('/api/state');
  const acct = (await get(`/api/state?account=${p.accountKey}`)).account;
  const call = { accountKey: p.accountKey, registeryIndex: acct.registery_index, blsKey: p.blsKey, contractId: st.contract_id, contractRegisteryIndex: st.contract_registery_index, amount, opsPrice: 100, target: st.batch_height_tip + 1 };
  const sig = bytesToHex(blsSign(p.secp, callSighash(call)));
  const r = await post('/api/call', { account_key: p.accountKey, registery_index: call.registeryIndex, bls_key: p.blsKey, method_index: 0, calldata: [{ type: 'payable', value: amount }], ops_price: 100, target: call.target, bls_signature: sig });
  if (!r.ok) fail('enter', JSON.stringify(r));
}

async function main() {
  const A = newPlayer(), B = newPlayer();
  await depositClaim(A, 0.50);
  await depositClaim(B, 0.50);

  // Player A enters alone.
  await enter(A, sat(0.10));
  let st = await get('/api/state');
  console.log(`after A enters: participants ${st.participants}, min ${st.min_participants}, time_left ${st.time_left}, duration ${st.round_duration}`);
  if (st.participants !== 1) fail('expected 1 distinct player', JSON.stringify(st.participants));
  if (st.min_participants < 2) fail('min_participants should be >= 2', String(st.min_participants));
  if (st.time_left !== st.round_duration) fail('countdown should NOT have started with 1 player', String(st.time_left));

  // Let several lifecycle ticks pass — the round must still not draw or count down.
  for (let i = 0; i < 5; i++) { cli('-generate 1'); await sleep(2500); }
  st = await get('/api/state');
  const hist1 = (await get('/api/history')).count;
  console.log(`after waiting with 1 player: participants ${st.participants}, time_left ${st.time_left}, rounds settled ${hist1}`);
  if (st.time_left !== st.round_duration) fail('countdown started with only 1 player (should be parked)', String(st.time_left));
  if (hist1 !== 0) fail('a round drew with only 1 player', String(hist1));

  // Second DISTINCT player enters → quorum reached, countdown begins.
  await enter(B, sat(0.10));
  cli('-generate 1'); await sleep(3000);
  st = await get('/api/state');
  console.log(`after B enters: participants ${st.participants}, time_left ${st.time_left}`);
  if (st.participants !== 2) fail('expected 2 distinct players', String(st.participants));
  if (!(st.time_left < st.round_duration)) fail('countdown should have started once 2 players are in', String(st.time_left));

  console.log('\nPASS — the draw countdown is gated on 2 distinct players: parked at full duration with one player (no draw), and only starts ticking once a second distinct player joins.');
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
