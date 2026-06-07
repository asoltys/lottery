// LIVE ARCADE smoke test: drives the full non-custodial covenant lifecycle through
// the running lottery-engine arcade (port 8090) over its real /cosign WebSocket +
// bitcoind, on regtest. deposit -> genesis -> refresh -> unroll -> unilateral exit.
//
// Prereq: lottery-engine running on regtest (arcade :8090), regtest bitcoind at
//         /tmp/cube-regtest (wallet 'cube').
// Run:    node cosign_arcade_smoke.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { compactSize } from './covenant.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { taggedHash, hexToBytes, bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reverseHex = (h) => h.match(/../g).reverse().join('');
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();

const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), (() => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; })()]));
const HX = (h) => Buffer.from(h, 'hex');
function serializeSweep({ inTxidInternal, vout, sequence, witnessItems, outValue, outSpk }) {
  const vin = Buffer.concat([HX(inTxidInternal), u32le(vout), Buffer.from([0x00]), u32le(sequence)]);
  const out = Buffer.concat([u64le(outValue), varint(HX(outSpk).length), HX(outSpk)]);
  const wit = Buffer.concat([varint(witnessItems.length), ...witnessItems.map((w) => Buffer.concat([varint(HX(w).length), HX(w)]))]);
  return Buffer.concat([u32le(2), Buffer.from([0x00, 0x01]), varint(1), vin, varint(1), out, wit, u32le(0)]).toString('hex');
}

function newPlayer() {
  const s = new Uint8Array(32);
  globalThis.crypto.getRandomValues(s);
  return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) };
}

async function main() {
  const players = [newPlayer(), newPlayer(), newPlayer()];
  const sockets = [];
  const events = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, (k, d) => events.push({ who: p.accountKey.slice(0, 6), k, ...d }));
    sockets.push(ws);
  }
  await sleep(800); // let the cosign hellos register on the arcade

  // 1) DEPOSIT: fund a LiftV2 address per player, register the UTXO.
  const amounts = [0.30, 0.40, 0.50];
  for (let i = 0; i < players.length; i++) {
    const da = await (await fetch(`${BASE}/api/deposit_address?account=${players[i].accountKey}`)).json();
    if (!da.address) fail('deposit_address', JSON.stringify(da));
    const fundTxid = cli(`sendtoaddress ${da.address} ${amounts[i]}`);
    cli('-generate 1');
    const raw = cliJSON(`getrawtransaction ${fundTxid} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
    const dr = await post('/api/deposit', { account_key: players[i].accountKey, txid: fundTxid, vout });
    if (!dr.ok) fail('register deposit', JSON.stringify(dr));
    players[i].deposit = { fundTxid, vout, value: dr.value };
  }
  console.log('deposits registered:', players.map((p) => p.deposit.value).join(', '));

  // 2) GENESIS via the live arcade (it cosigns over /cosign + broadcasts).
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok) fail('genesis', JSON.stringify(g));
  console.log(`GENESIS: covenant ${g.txid.slice(0, 16)}… value ${g.covenant_value} (${g.participants} participants)`);
  const cov = await (await fetch(`${BASE}/api/covenant`)).json();
  if (!cov.covenant) fail('covenant not recorded', JSON.stringify(cov));

  // 3) REFRESH (no-op mirror, minus fee) — proves the covenant moves on-chain + re-presigns the unroll.
  const r = await post('/api/covenant/refresh', {});
  if (!r.ok) fail('refresh', JSON.stringify(r));
  console.log(`REFRESH: new covenant ${r.refresh_txid.slice(0, 16)}… value ${r.covenant_value}; unroll pre-signed ${r.unroll_txid.slice(0, 16)}…`);
  const leaves = r.leaves || [];

  // 4) UNROLL: broadcast the pre-signed unroll (forced/cooperative exit).
  const u = await post('/api/covenant/unroll', {});
  if (!u.ok) fail('unroll', JSON.stringify(u));
  const unrollTx = cliJSON(`getrawtransaction ${u.unroll_txid} true`);
  console.log(`UNROLL broadcast: ${u.unroll_txid.slice(0, 16)}… (${unrollTx.vout.length} VTXO leaves, ${unrollTx.confirmations} conf)`);

  // 5) UNILATERAL EXIT: player 0 CSV-sweeps its leaf with only its key.
  const p0 = players[0];
  const leaf = leaves.find((l) => l.account.toLowerCase() === p0.accountKey.toLowerCase());
  if (!leaf) fail('no leaf for player 0', JSON.stringify(leaves));
  cli(`-generate ${leaf.exit_delay}`); // mature the CSV
  const destAddr = cli('getnewaddress');
  const destSpk = cliJSON(`getaddressinfo ${destAddr}`).scriptPubKey;
  const outValue = leaf.value - 500;
  const tapleafHash = bytesToHex(taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), compactSize(HX(leaf.exit_script).length), HX(leaf.exit_script)])));
  const inTxidInternal = reverseHex(u.unroll_txid);
  const sighashHex = scriptPathSighash({
    version: 2, lockTime: 0, inputIndex: 0,
    inputs: [{ txid: inTxidInternal, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey, sequence: leaf.exit_delay }],
    outputs: [{ value: outValue, spk: destSpk }],
  }, tapleafHash);
  const sig = bytesToHex(schnorr.sign(hexToBytes(sighashHex), hexToBytes(p0.secpHex)));
  const sweepHex = serializeSweep({ inTxidInternal, vout: leaf.vout, sequence: leaf.exit_delay, witnessItems: [sig, leaf.exit_script, leaf.control_block], outValue, outSpk: destSpk });
  let sweepTxid;
  try { sweepTxid = cli(`sendrawtransaction ${sweepHex}`); } catch (e) { fail('leaf sweep rejected', String(e.stderr || e)); }
  cli('-generate 1');
  const sweepTx = cliJSON(`getrawtransaction ${sweepTxid} true`);
  console.log(`EXIT: player 0 swept ${outValue} sat to ${destAddr.slice(0, 14)}… (${sweepTx.confirmations} conf)`);

  for (const ws of sockets) ws.close();
  if (sweepTx.confirmations >= 1 && !events.some((e) => e.k === 'reject')) {
    console.log('\nPASS — full non-custodial lifecycle through the LIVE arcade: deposit -> genesis -> refresh -> unroll -> unilateral exit.');
    process.exit(0);
  }
  fail('lifecycle incomplete', JSON.stringify(events.filter((e) => e.k === 'reject')));
}

main().catch((e) => { console.error(e); process.exit(1); });
