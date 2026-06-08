// COOPERATIVE WITHDRAW fee-incidence test on the LIVE arcade (regtest).
// deposit -> claim (credit L2) -> genesis -> player 0 cooperatively withdraws.
// Proves: the LEAVER pays their own on-chain fee (payout = claim − fee), and the
// remaining members' covenant is NOT charged (new covenant == Σ other claims).
//
// Prereq: lottery-engine arcade :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube).
// Run:    node cosign_withdraw_test.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { attachCosign, setPendingWithdrawSpk } from './cosign_client.mjs';
import { bech32, bech32m } from '@scure/base';
import { bytesToHex, hexToBytes } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const DD = '/tmp/cube-regtest';
const Fr = bls.fields.Fr;
const enc = new TextEncoder();
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

const cat = (...a) => { const arr = a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))); const n = arr.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of arr) { o.set(x, i); i += x.length; } return o; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const beToBig = (u) => { let x = 0n; for (const c of u) x = (x << 8n) | BigInt(c); return x; };
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };
const tag512 = (t, m) => { const x = sha512(enc.encode(t)); return sha512(cat(x, x, m)); };
const blsScalar = (secp) => beToBig(tag512('Cube/bls/secretkey', secp).slice(0, 48)) % Fr.ORDER;
const blsPub = (secp) => bls.G1.Point.BASE.multiply(blsScalar(secp)).toBytes();
const blsSign = (secp, h) => bls.G2.hashToCurve(h, { DST: enc.encode('Cube/bls/message') }).multiply(blsScalar(secp)).toBytes();

const newPlayer = () => {
  const s = new Uint8Array(32); crypto.getRandomValues(s);
  const secpHex = bytesToHex(s);
  return { secpHex, secp: s, accountKey: bytesToHex(schnorr.getPublicKey(s)), blsKey: bytesToHex(blsPub(s)) };
};

async function main() {
  const players = [newPlayer(), newPlayer(), newPlayer()];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, () => {});
    p.ws = ws;
  }
  await sleep(800);

  // deposit + claim (credit L2 balance) per player.
  const amounts = [0.30, 0.40, 0.50];
  for (let i = 0; i < players.length; i++) {
    const p = players[i];
    const da = await (await fetch(`${BASE}/api/deposit_address?account=${p.accountKey}`)).json();
    const fundTxid = cli(`sendtoaddress ${da.address} ${amounts[i]}`);
    cli('-generate 1');
    const raw = cliJSON(`getrawtransaction ${fundTxid} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
    const dr = await post('/api/deposit', { account_key: p.accountKey, txid: fundTxid, vout });
    if (!dr.ok) fail('deposit', JSON.stringify(dr));
    p.deposit = dr.value;
    // claim → credit L2
    const csig = bytesToHex(schnorr.sign(tag256('Cube/sighash/arcade/deposit-claim', cat(hexToBytes(p.accountKey), hexToBytes(p.blsKey))), p.secp));
    const cr = await post('/api/deposit/claim', { account_key: p.accountKey, bls_key: p.blsKey, sig: csig });
    if (!cr.ok) fail('claim', JSON.stringify(cr));
  }

  const g = await post('/api/covenant/genesis', {});
  if (!g.ok) fail('genesis', JSON.stringify(g));
  const cov0 = await (await fetch(`${BASE}/api/covenant`)).json();
  const allocOf = (acct) => Number((cov0.covenant.allocations.find(([h]) => h.toLowerCase() === acct.toLowerCase()) || [, 0])[1]);
  const a0 = allocOf(players[0].accountKey), a1 = allocOf(players[1].accountKey), a2 = allocOf(players[2].accountKey);
  const covValue = Number(cov0.covenant.value);
  console.log(`covenant ${covValue} = ${a0} + ${a1} + ${a2}`);

  // player 0 cooperatively withdraws their whole balance.
  const p0 = players[0];
  const destAddr = cli('getnewaddress');
  const bal0 = a0; // balance == claim here (fresh genesis, no gameplay)
  const wsh = tag256('Cube/sighash/arcade/withdraw', cat(hexToBytes(p0.accountKey), u64le(bal0), enc.encode(destAddr)));
  const wsig = bytesToHex(blsSign(p0.secp, wsh));
  // decode dest to spk so this tab's cosign permits exactly this payout.
  const spk = (() => { let w; try { w = bech32m.decode(destAddr, 1023).words; } catch { w = bech32.decode(destAddr, 1023).words; } const v = w[0]; const prog = bech32.fromWords(w.slice(1)); return bytesToHex(Uint8Array.from([v === 0 ? 0 : 0x50 + v, prog.length, ...prog])); })();
  setPendingWithdrawSpk(spk);

  const w = await post('/api/withdraw', { account_key: p0.accountKey, bls_key: p0.blsKey, bls_signature: wsig, address: destAddr, amount: bal0 });
  if (!w.ok) fail('withdraw', JSON.stringify(w));
  cli('-generate 1');
  const wtx = cliJSON(`getrawtransaction ${w.refresh_txid || w.txid} true`);

  // assertions
  const fee = Number(w.fee ?? (covValue - wtx.vout.reduce((s, o) => s + Math.round(o.value * 1e8), 0)));
  const payoutOut = wtx.vout.find((o) => o.scriptPubKey.hex === spk);
  if (!payoutOut) fail('no payout output to dest', JSON.stringify(wtx.vout));
  const gotPayout = Math.round(payoutOut.value * 1e8);
  const onchainFee = covValue - wtx.vout.reduce((s, o) => s + Math.round(o.value * 1e8), 0);

  const cov1 = await (await fetch(`${BASE}/api/covenant`)).json();
  const newCov = Number(cov1.covenant.value);
  const na1 = Number((cov1.covenant.allocations.find(([h]) => h.toLowerCase() === players[1].accountKey.toLowerCase()) || [, 0])[1]);
  const na2 = Number((cov1.covenant.allocations.find(([h]) => h.toLowerCase() === players[2].accountKey.toLowerCase()) || [, 0])[1]);

  console.log(`leaver got ${gotPayout} (claim ${a0} − fee ${onchainFee} = ${a0 - onchainFee})`);
  console.log(`new covenant ${newCov} ; remaining claims ${na1} + ${na2} = ${na1 + na2}`);

  if (gotPayout !== a0 - onchainFee) fail('leaver did not pay their own fee', `${gotPayout} != ${a0 - onchainFee}`);
  if (newCov !== a1 + a2) fail('remaining members were CHARGED the fee', `newCov ${newCov} != ${a1 + a2}`);
  if (na1 !== a1 || na2 !== a2) fail('remaining members’ claims changed', `${na1}/${na2} vs ${a1}/${a2}`);

  console.log('\nPASS — the leaver alone pays the exit fee; the other members’ pot is untouched.');
  for (const p of players) p.ws.close();
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
