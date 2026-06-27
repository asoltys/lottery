// LIFECYCLE RECONCILE e2e: after the auto-settle of a WIN, the engine reconciles
// the on-chain covenant to the players' new L2 balances, so a WINNER can
// cooperatively withdraw their winnings (the covenant otherwise tracks only the
// genesis stake). Flow: 2 players deposit+claim+genesis -> both bet part of their
// balance -> wait for the lifecycle to close+settle+reconcile -> assert the
// covenant now matches balances -> the winner withdraws their full balance.
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest (wallet cube).
// Run:    node reconcile_test.mjs   (takes ~2.5 min: a 120s round)

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { attachCosign, setPendingWithdrawSpk } from './cosign_client.mjs';
import { deriveJackpot, nsecToSecret } from './jackpot.mjs';
import { bech32, bech32m } from '@scure/base';
import { bytesToHex, hexToBytes } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const ENGINE_NSEC = process.env.CUBE_ENGINE_NSEC || 'nsec1xk47aue7hnjvugkr9yrgefnag28paggumqaer4pexadnvzg4ut7qhvwsu2';
const DD = '/tmp/cube-regtest';
const Fr = bls.fields.Fr;
const enc = new TextEncoder();
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
const get = async (p) => (await fetch(`${BASE}${p}`)).json();
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

const cat = (...a) => { const arr = a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))); const n = arr.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of arr) { o.set(x, i); i += x.length; } return o; };
const u16le = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const beToBig = (u) => { let x = 0n; for (const c of u) x = (x << 8n) | BigInt(c); return x; };
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };
const tag512 = (t, m) => { const x = sha512(enc.encode(t)); return sha512(cat(x, x, m)); };
const blsScalar = (secp) => beToBig(tag512('Cube/bls/secretkey', secp).slice(0, 48)) % Fr.ORDER;
const blsPub = (secp) => bls.G1.Point.BASE.multiply(blsScalar(secp)).toBytes();
const blsSign = (secp, h) => bls.G2.hashToCurve(h, { DST: enc.encode('Cube/bls/message') }).multiply(blsScalar(secp)).toBytes();

// call encoding (mirrors app.mjs encCall) for an `enter` (method 0) payable bet.
function encCall(c) {
  const account = cat([0x02], hexToBytes(c.accountKey), u64le(c.registeryIndex), hexToBytes(c.blsKey));
  const contract = cat(hexToBytes(c.contractId), u64le(c.contractRegisteryIndex));
  let cd = u32le(1); cd = cat(cd, [0x09], u32le(c.amount));
  return cat([0x01], u32le(account.length), account, u32le(contract.length), contract, u16le(0), u32le(cd.length), cd, [0x00], u64le(c.opsPrice), u64le(c.target));
}
const callSighash = (c) => tag256('Cube/sighash/entry/call', encCall(c));

const newPlayer = () => { const s = new Uint8Array(32); crypto.getRandomValues(s); return { secpHex: bytesToHex(s), secp: s, accountKey: bytesToHex(schnorr.getPublicKey(s)), blsKey: bytesToHex(blsPub(s)) }; };
const spkOf = (addr) => { let w; try { w = bech32m.decode(addr, 1023).words; } catch { w = bech32.decode(addr, 1023).words; } const v = w[0]; const prog = bech32.fromWords(w.slice(1)); return bytesToHex(Uint8Array.from([v === 0 ? 0 : 0x50 + v, prog.length, ...prog])); };

async function main() {
  const players = [newPlayer(), newPlayer()];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, () => {});
    p.ws = ws;
  }
  await sleep(800);

  // connect the headless JACKPOT cosigner in-process (the accumulating jackpot is a
  // covenant participant owned by the operator-derived jackpot account; allowClaimLoss
  // so it cosigns even when its allocation drops to 0 on a strike).
  const jk = deriveJackpot(nsecToSecret(ENGINE_NSEC));
  {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, jk.secpHex, jk.accountHex, (k, d) => { if (k === 'reject') console.log('  jackpot reject', JSON.stringify(d)); }, { allowClaimLoss: true });
  }
  await sleep(400);

  // deposit 0.50 each, claim -> L2 balance; genesis -> covenant = deposits (Σ = 1.0).
  for (const p of players) {
    const da = await get(`/api/deposit_address?account=${p.accountKey}`);
    const tx = cli(`sendtoaddress ${da.address} 0.50`);
    cli('-generate 1');
    const vout = cliJSON(`getrawtransaction ${tx} true`).vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
    if (!(await post('/api/deposit', { account_key: p.accountKey, txid: tx, vout })).ok) fail('deposit');
    const csig = bytesToHex(schnorr.sign(tag256('Cube/sighash/arcade/deposit-claim', cat(hexToBytes(p.accountKey), hexToBytes(p.blsKey))), p.secp));
    const cr = await post('/api/deposit/claim', { account_key: p.accountKey, bls_key: p.blsKey, sig: csig });
    if (!cr.ok) fail('claim', JSON.stringify(cr));
  }
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));
  const cov0 = (await get('/api/covenant')).covenant;
  console.log(`genesis covenant ${cov0.value} (${cov0.allocations.length} stakes)`);

  // each player bets 0.30, keeping 0.20 unbet (so neither drops to 0 on a loss).
  const st0 = await get('/api/state');
  for (const p of players) {
    const acct = (await get(`/api/state?account=${p.accountKey}`)).account;
    const call = { accountKey: p.accountKey, registeryIndex: acct.registery_index, blsKey: p.blsKey, contractId: st0.contract_id, contractRegisteryIndex: st0.contract_registery_index, amount: sat(0.30), opsPrice: 100, target: st0.batch_height_tip + 1 };
    const sig = bytesToHex(blsSign(p.secp, callSighash(call)));
    const r = await post('/api/call', { account_key: p.accountKey, registery_index: call.registeryIndex, bls_key: p.blsKey, method_index: 0, calldata: [{ type: 'payable', value: sat(0.30) }], ops_price: 100, target: call.target, bls_signature: sig });
    if (!r.ok) fail('enter', JSON.stringify(r));
  }
  console.log('both entered 0.30; mining + waiting for the WIN (players stay connected so the reconcile can cosign)…');

  // Wait for the lifecycle to close+settle this round into a WIN, mining steadily so
  // the batch/close targets advance. Keep the WS open so the post-settle reconcile
  // (N-of-N over the covenant members) can cosign.
  let won = false;
  for (let i = 0; i < 80; i++) {
    cli('-generate 2'); // advance the chain so close/settle apply
    await sleep(3000);
    const st = await get('/api/state');
    if (st.last_winner) { won = true; console.log(`  won after ~${i * 3}s: winner ${String(st.last_winner).slice(0, 12)}…`); break; }
  }
  if (!won) fail('round did not produce a win in time');

  // the reconcile fires right after the settle; wait for the covenant txid to change.
  let cov1 = cov0;
  for (let i = 0; i < 20; i++) {
    cli('-generate 1'); await sleep(2000);
    const c = (await get('/api/covenant')).covenant;
    if (c && c.txid !== cov0.txid) { cov1 = c; break; }
    cov1 = c || cov1;
  }

  // after settle+reconcile, the covenant should match the players' (+operator) balances.
  if (!cov1) fail('covenant gone after reconcile');
  console.log(`reconciled covenant ${cov1.value} (${cov1.allocations.length} claimants)`);
  if (cov1.txid === cov0.txid) fail('covenant was NOT reconciled (txid unchanged) — reconcile did not run');

  // v5: the JACKPOT account carries the accumulated 4% as a covenant allocation
  // (cosigned by the headless jackpot cosigner). round pot 0.60 -> jackpot ~0.024.
  const jkClaim = cov1.allocations.filter(([h]) => h.toLowerCase() === jk.accountHex.toLowerCase()).reduce((s, [, v]) => s + Number(v), 0);
  const stJackpot = (await get('/api/state')).jackpot;
  console.log(`  JACKPOT accumulator: state=${stJackpot} covenant_alloc=${jkClaim} (expect ~${sat(0.024)})`);
  if (jkClaim <= 0) fail('jackpot NOT carried as a covenant allocation (headless cosigner / reconcile broken)', String(jkClaim));
  if (Math.abs(jkClaim - stJackpot) > 5000) fail('covenant jackpot alloc != /api/state jackpot', `${jkClaim} vs ${stJackpot}`);
  if (Math.abs(jkClaim - sat(0.024)) > 60000) fail('jackpot != ~4% of the round pot', String(jkClaim));

  // each player's covenant claim should equal their L2 balance (the whole point).
  for (const p of players) {
    const acct = (await get(`/api/state?account=${p.accountKey}`)).account;
    const claim = cov1.allocations.filter(([h]) => h.toLowerCase() === p.accountKey.toLowerCase()).reduce((s, [, v]) => s + Number(v), 0);
    console.log(`  ${p.accountKey.slice(0, 12)}… balance ${acct.balance} onchain_claim ${claim}`);
    // claim should be within a small fee of the balance (fee comes off the largest).
    if (claim > 0 && Math.abs(claim - acct.balance) > 8000) fail('covenant claim != balance after reconcile', `${claim} vs ${acct.balance}`);
  }

  // the winner (balance grew above their 0.20 unbet) withdraws their full balance.
  const winner = (await Promise.all(players.map(async (p) => ({ p, b: (await get(`/api/state?account=${p.accountKey}`)).account.balance })))).sort((a, b) => b.b - a.b)[0].p;
  const wbal = (await get(`/api/state?account=${winner.accountKey}`)).account.balance;
  const dest = cli('getnewaddress');
  const spk = spkOf(dest);
  setPendingWithdrawSpk(spk);
  const wsh = tag256('Cube/sighash/arcade/withdraw', cat(hexToBytes(winner.accountKey), u64le(wbal), enc.encode(dest)));
  const wsig = bytesToHex(blsSign(winner.secp, wsh));
  console.log(`winner ${winner.accountKey.slice(0, 12)}… withdrawing full balance ${wbal}…`);
  const w = await post('/api/withdraw', { account_key: winner.accountKey, bls_key: winner.blsKey, bls_signature: wsig, address: dest, amount: wbal });
  if (!w.ok) fail('winner withdraw', JSON.stringify(w));
  cli('-generate 1');
  console.log(`withdrew ${w.withdrawn} to ${dest} (tx ${String(w.txid).slice(0, 12)}…)`);
  if (Number(w.withdrawn) < sat(0.20)) fail('winner withdrew too little — winnings not backed', String(w.withdrawn));

  for (const p of players) p.ws.close();
  console.log('\nPASS — v5: a round paid a winner 95%, accumulated 4% to the jackpot, and the headless jackpot cosigner let reconcile carry that accumulator as a covenant allocation; winner withdrew cooperatively.');
  process.exit(0);
}
main().catch((e) => fail('exception', e.stack || String(e)));
