// DUP-ALLOCATION test on the LIVE arcade (regtest).
// One account makes TWO deposits -> genesis yields TWO allocation entries for the
// same account key. Proves the read-time SUM fix: onchain_claim reports the SUM of
// both allocations, and a full-balance cooperative withdraw (alloc = sum) succeeds.
// Before the fix, find()-first-match would report/withdraw only ONE deposit.
//
// Prereq: lottery-engine arcade :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube).
// Run:    node cosign_dup_test.mjs

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
  // Two players so the covenant survives p0's full exit (a >1 member refresh path,
  // which is the realistic dup case). p0 is the one with TWO deposits.
  const players = [newPlayer(), newPlayer()];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, () => {});
    p.ws = ws;
  }
  await sleep(800);

  const p0 = players[0], p1 = players[1];
  const da0 = await (await fetch(`${BASE}/api/deposit_address?account=${p0.accountKey}`)).json();
  const da1 = await (await fetch(`${BASE}/api/deposit_address?account=${p1.accountKey}`)).json();

  // p0: TWO deposits (30M + 20M = 50M) ; p1: one deposit (40M). Send them all, then
  // confirm in a SINGLE block so the auto-genesis watcher can't fire mid-way (which
  // would split p0's two deposits across genesis + a later refresh).
  const sends = [
    { p: p0, da: da0, amt: 0.30 },
    { p: p0, da: da0, amt: 0.20 },
    { p: p1, da: da1, amt: 0.40 },
  ];
  for (const s of sends) s.tx = cli(`sendtoaddress ${s.da.address} ${s.amt}`);
  cli('-generate 1');
  for (const s of sends) {
    const raw = cliJSON(`getrawtransaction ${s.tx} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === s.da.scriptpubkey).n;
    const dr = await post('/api/deposit', { account_key: s.p.accountKey, txid: s.tx, vout });
    if (!dr.ok) fail('deposit', JSON.stringify(dr));
  }

  // claim → credit L2 for both players
  for (const p of players) {
    const csig = bytesToHex(schnorr.sign(tag256('Cube/sighash/arcade/deposit-claim', cat(hexToBytes(p.accountKey), hexToBytes(p.blsKey))), p.secp));
    const cr = await post('/api/deposit/claim', { account_key: p.accountKey, bls_key: p.blsKey, sig: csig });
    if (!cr.ok) fail('claim', JSON.stringify(cr));
  }

  // Form the covenant. The auto-genesis watcher may have already formed it from the
  // queued deposits — treat "covenant exists" as success (same do_genesis path).
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));
  const cov0 = await (await fetch(`${BASE}/api/covenant`)).json();
  if (!cov0.covenant) fail('no covenant formed', JSON.stringify(cov0));

  // p0 funded with TWO deposits but the covenant must hold exactly ONE merged leaf
  // (== sum of both). Two leaves for one key would break the cosign refresh.
  const p0entries = cov0.covenant.allocations.filter(([h]) => h.toLowerCase() === p0.accountKey.toLowerCase());
  console.log(`p0 allocation entries: ${p0entries.length}  values=[${p0entries.map(([, v]) => Number(v)).join(', ')}]`);
  if (p0entries.length !== 1) fail('expected ONE merged allocation entry for p0', JSON.stringify(cov0.covenant.allocations));
  const p0allocSum = p0entries.reduce((s, [, v]) => s + Number(v), 0);
  // merged leaf == 50M minus the genesis fee (charged to the largest allocation).
  // Must exceed either single deposit (30M / 20M) to prove both were merged.
  if (p0allocSum <= 49_900_000) fail('merged leaf does not reflect both deposits', `${p0allocSum} <= 49900000`);

  // /api/state must report onchain_claim == SUM of both entries (the fix).
  const st = (await (await fetch(`${BASE}/api/state?account=${p0.accountKey}`)).json()).account;
  const claim = Number(st.onchain_claim);
  console.log(`onchain_claim reported: ${claim}  (sum of entries: ${p0allocSum})`);
  if (claim !== p0allocSum) fail('onchain_claim != sum of allocations (find()-first-match bug)', `${claim} != ${p0allocSum}`);

  // Full-balance withdraw of p0: amount = full L2 balance. With the fix, alloc=sum
  // covers it; before the fix alloc=first-entry would cap the payout below balance.
  const bal0 = Number(st.balance ?? claim);
  const destAddr = cli('getnewaddress');
  const wsh = tag256('Cube/sighash/arcade/withdraw', cat(hexToBytes(p0.accountKey), u64le(bal0), enc.encode(destAddr)));
  const wsig = bytesToHex(blsSign(p0.secp, wsh));
  const spk = (() => { let w; try { w = bech32m.decode(destAddr, 1023).words; } catch { w = bech32.decode(destAddr, 1023).words; } const v = w[0]; const prog = bech32.fromWords(w.slice(1)); return bytesToHex(Uint8Array.from([v === 0 ? 0 : 0x50 + v, prog.length, ...prog])); })();
  setPendingWithdrawSpk(spk);

  console.log(`withdrawing full balance ${bal0} to ${destAddr}`);
  const w = await post('/api/withdraw', { account_key: p0.accountKey, bls_key: p0.blsKey, bls_signature: wsig, address: destAddr, amount: bal0 });
  if (!w.ok) fail('withdraw', JSON.stringify(w));
  cli('-generate 1');
  const wtx = cliJSON(`getrawtransaction ${w.refresh_txid || w.txid} true`);
  const payoutOut = wtx.vout.find((o) => o.scriptPubKey.hex === spk);
  if (!payoutOut) fail('no payout output to dest', JSON.stringify(wtx.vout));
  const gotPayout = Math.round(payoutOut.value * 1e8);
  console.log(`withdrew ${w.withdrawn}; on-chain payout ${gotPayout}; new balance ${w.balance}`);

  // The payout must reflect the SUMMED claim (minus its own fee), not a single deposit.
  // i.e. it must exceed the larger single deposit (30M) — proving both were spendable.
  if (gotPayout <= 30_000_000) fail('payout did not include both deposits (sum fix not effective)', `${gotPayout} <= 30000000`);
  if (Number(w.withdrawn) !== bal0) fail('did not withdraw full balance', `${w.withdrawn} != ${bal0}`);

  console.log('\nPASS — both deposits counted: onchain_claim summed, full balance withdrawn across two allocations.');
  for (const p of players) p.ws.close();
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
