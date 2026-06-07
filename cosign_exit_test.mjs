// UNILATERAL EXIT on regtest: deposit -> genesis -> UNROLL (covenant -> VTXO
// leaves) -> a holder CSV-sweeps its own leaf with ONLY its key. Proves the
// no-liveness exit: the pre-signed unroll is broadcastable by anyone, and each
// leaf is then unilaterally spendable via its tapscript exit path.
//
// Prereq: regtest bitcoind at /tmp/cube-regtest (wallet 'cube') + cosign server.
// Run:    node cosign_exit_test.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { attachCosign } from './cosign_client.mjs';
import { liftV2Spk, compactSize } from './covenant.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { taggedHash, hexToBytes, bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8099';
const WS = 'ws://127.0.0.1:8099/cosign';
const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
const reverseHex = (h) => h.match(/../g).reverse().join('');
const mine = (n = 1) => cli(`-generate ${n}`);
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), (() => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; })()]));
const H = (h) => Buffer.from(h, 'hex');

// minimal segwit tx serializer for 1 taproot script-path input -> 1 output.
function serializeSweep({ inTxidInternal, vout, sequence, witnessItems, outValue, outSpk }) {
  const vin = Buffer.concat([H(inTxidInternal), u32le(vout), Buffer.from([0x00]), u32le(sequence)]);
  const out = Buffer.concat([u64le(outValue), varint(H(outSpk).length), H(outSpk)]);
  const wit = Buffer.concat([
    varint(witnessItems.length),
    ...witnessItems.map((w) => Buffer.concat([varint(H(w).length), H(w)])),
  ]);
  return Buffer.concat([
    u32le(2),               // version
    Buffer.from([0x00, 0x01]), // segwit marker+flag
    varint(1), vin,
    varint(1), out,
    wit,
    u32le(0),               // locktime
  ]).toString('hex');
}

function newPlayer() {
  const s = new Uint8Array(32);
  globalThis.crypto.getRandomValues(s);
  return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) };
}

async function main() {
  const engineKey = (await (await fetch(`${BASE}/engine`)).json()).engine_key;
  const players = [newPlayer(), newPlayer()];
  const sockets = [];
  const events = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, (k, d) => events.push({ who: p.accountKey.slice(0, 6), k, ...d }));
    sockets.push(ws);
  }
  for (let i = 0; i < 40; i++) {
    const r = await (await fetch(`${BASE}/connected`)).json();
    if (players.every((p) => (r.connected || []).includes(p.accountKey))) break;
    await sleep(100);
  }

  // fund deposits + genesis (same as the on-chain test).
  const amounts = [0.40, 0.60];
  const deposits = players.map((p, i) => {
    const spk = liftV2Spk(p.accountKey, engineKey).spk;
    const addr = cliJSON(`decodescript ${spk}`).address;
    const fundTxid = cli(`sendtoaddress ${addr} ${amounts[i]}`);
    return { account: p.accountKey, spk, fundTxid, value: sat(amounts[i]) };
  });
  mine(1);
  for (const d of deposits) {
    const raw = cliJSON(`getrawtransaction ${d.fundTxid} true`);
    d.prev_vout = raw.vout.find((o) => o.scriptPubKey.hex === d.spk).n;
    d.prev_txid = reverseHex(d.fundTxid);
  }
  const GEN_FEE = 1000;
  const gres = await (await fetch(`${BASE}/genesis`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deposits: deposits.map((d) => ({ account: d.account, prev_txid: d.prev_txid, prev_vout: d.prev_vout, prev_value: d.value })), fee: GEN_FEE }),
  })).json();
  if (!gres.ok) fail('genesis', gres.error);
  const genTxid = cli(`sendrawtransaction ${gres.signed_tx}`);
  mine(1);
  const genTx = cliJSON(`getrawtransaction ${genTxid} true`);
  const allocs = gres.covenant_allocations;
  const covValue = gres.covenant_value;
  const covVout = genTx.vout.findIndex((o) => o.value && sat(o.value) === covValue);
  console.log(`genesis covenant: ${genTxid.slice(0, 16)}… vout ${covVout} = ${covValue} sat`);

  // UNROLL the covenant into VTXO leaves.
  const EXIT_DELAY = 6;
  const ures = await (await fetch(`${BASE}/unroll`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ allocations: allocs, prev_txid: reverseHex(genTxid), prev_vout: covVout, prev_value: covValue, exit_delay: EXIT_DELAY, fee: 1000 }),
  })).json();
  if (!ures.ok || !ures.valid) fail('unroll cosign', ures.error);
  let unrollTxid;
  try { unrollTxid = cli(`sendrawtransaction ${ures.signed_tx}`); }
  catch (e) { fail('unroll broadcast rejected', String(e.stderr || e)); }
  mine(1);
  const unrollTx = cliJSON(`getrawtransaction ${unrollTxid} true`);
  console.log(`UNROLL confirmed: ${unrollTxid.slice(0, 16)}…  (covenant -> ${unrollTx.vout.length} VTXO leaves, ${unrollTx.confirmations} conf)`);

  // pick player 0's leaf and unilaterally sweep it with only player 0's key.
  const p0 = players[0];
  const leaf = ures.leaves.find((l) => l.account.toLowerCase() === p0.accountKey.toLowerCase());
  if (!leaf) fail('no leaf for player 0');

  // CSV must mature: leaf needs EXIT_DELAY confirmations.
  mine(EXIT_DELAY);

  const destAddr = cli('getnewaddress');
  const destSpk = cliJSON(`getaddressinfo ${destAddr}`).scriptPubKey;
  const sweepFee = 500;
  const outValue = leaf.value - sweepFee;

  const exitScript = leaf.exit_script;
  const tapleafHash = bytesToHex(taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), compactSize(H(exitScript).length), H(exitScript)])));
  const inTxidInternal = reverseHex(unrollTxid);
  const sighashHex = scriptPathSighash({
    version: 2, lockTime: 0, inputIndex: 0,
    inputs: [{ txid: inTxidInternal, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey, sequence: EXIT_DELAY }],
    outputs: [{ value: outValue, spk: destSpk }],
  }, tapleafHash);

  const sig = bytesToHex(schnorr.sign(hexToBytes(sighashHex), hexToBytes(p0.secpHex)));
  const sweepHex = serializeSweep({
    inTxidInternal, vout: leaf.vout, sequence: EXIT_DELAY,
    witnessItems: [sig, exitScript, leaf.control_block],
    outValue, outSpk: destSpk,
  });

  let sweepTxid;
  try { sweepTxid = cli(`sendrawtransaction ${sweepHex}`); }
  catch (e) { fail('leaf sweep rejected by bitcoind', String(e.stderr || e)); }
  mine(1);
  const sweepTx = cliJSON(`getrawtransaction ${sweepTxid} true`);
  console.log(`LEAF SWEEP confirmed: ${sweepTxid.slice(0, 16)}…  (player 0 exited ${outValue} sat with only its key, ${sweepTx.confirmations} conf)`);

  for (const ws of sockets) ws.close();
  if (unrollTx.confirmations >= 1 && sweepTx.confirmations >= 1 && !events.some((e) => e.k === 'reject')) {
    console.log('\nPASS — unilateral exit proven on regtest: pre-signed unroll + CSV leaf sweep.');
    process.exit(0);
  }
  fail('exit did not complete');
}

main().catch((e) => { console.error(e); process.exit(1); });
