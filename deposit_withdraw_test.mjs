// DEPOSIT WITHDRAW e2e: a freshly-deposited, NOT-yet-pooled balance must be
// withdrawable directly (2-of-2 LiftV2 spend) with no covenant and no other
// members online. Flow: player A deposits 0.40, never genesis/plays, and
// withdraws straight to a regtest address — the engine cosigns A's deposit
// UTXO out to A's address; A's L2 balance goes to 0 and the address receives
// ~0.40 (minus fee).
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube).
// Run:    node deposit_withdraw_test.mjs

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

async function main() {
  const A = newPlayer();
  const ws = new WebSocket(WS);
  await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
  attachCosign(ws, A.secpHex, A.accountKey, (k, d) => { if (k === 'reject') console.log('  cosign reject', JSON.stringify(d)); });
  await sleep(800);

  await depositClaim(A, 0.40);
  // wait for the deposit to confirm + be credited.
  let info = null;
  for (let i = 0; i < 20; i++) {
    cli('-generate 1'); await sleep(1500);
    info = (await get(`/api/state?account=${A.accountKey}`)).account;
    if (info && info.balance >= 39_000_000 && (info.deposit_withdrawable || 0) > 0) break;
  }
  if (!info || info.balance === 0) fail('A balance not credited', JSON.stringify(info));
  console.log(`A balance ${info.balance}; deposit_withdrawable ${info.deposit_withdrawable}; onchain_claim ${info.onchain_claim}`);
  if ((info.deposit_withdrawable || 0) === 0) fail('deposit_withdrawable should be > 0 for an un-pooled deposit');
  if ((info.onchain_claim || 0) !== 0) fail('A should NOT be in any covenant');

  // withdraw straight to a fresh regtest address.
  const dest = cli('getnewaddress');
  const spk = cliJSON(`getaddressinfo ${dest}`).scriptPubKey;
  setPendingWithdrawSpk(spk);
  const amount = info.balance;
  const sighash = tag256('Cube/sighash/arcade/withdraw', cat(hexToBytes(A.accountKey), u64le(amount), enc.encode(dest)));
  const sig = bytesToHex(blsSign(A.secp, sighash));
  const r = await post('/api/withdraw', { account_key: A.accountKey, bls_key: A.blsKey, address: dest, amount, bls_signature: sig });
  setPendingWithdrawSpk(null);
  if (!r.ok) fail('withdraw failed', JSON.stringify(r));
  console.log(`withdrew ${r.withdrawn} sats to ${dest} (tx ${r.txid.slice(0, 12)}…); A balance now ${r.balance}`);
  cli('-generate 1');

  // the destination address must have received the payout on-chain.
  const recv = cliJSON(`getreceivedbyaddress ${dest} 0`);
  console.log(`address received ${recv} BTC on-chain`);
  if (Math.round(recv * 1e8) < 39_900_000) fail('destination did not receive the withdrawal', String(recv));
  if (r.balance !== 0) fail('A L2 balance should be 0 after full withdrawal', String(r.balance));

  // a second withdraw must now find nothing.
  const r2 = await post('/api/withdraw', { account_key: A.accountKey, bls_key: A.blsKey, address: dest, amount: 1, bls_signature: bytesToHex(blsSign(A.secp, tag256('Cube/sighash/arcade/withdraw', cat(hexToBytes(A.accountKey), u64le(1), enc.encode(dest))))) });
  if (r2.ok) fail('second withdraw should have nothing to withdraw', JSON.stringify(r2));

  ws.close();
  console.log('\nPASS — an un-pooled deposit was withdrawn DIRECTLY (2-of-2 LiftV2 spend) to the player\'s address with no covenant and no other members. A freshly-deposited balance is always recoverable.');
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
