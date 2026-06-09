// WINNER-SWEEP end-to-end on the LIVE arcade, on the REAL covenant — native JS.
// The settle-enforced reattribution leg: on an HONEST settle the engine pre-signs
// the covenant's UNROLL with every LOSER leaf carrying a winner-sweep lock keyed to
// the round's garbled VALID label + the winner's key. The winner derives the valid
// label in JS (winnerLabel), broadcasts the pre-signed unroll, and SWEEPS every
// loser leaf to itself — taking the whole pot with NO cooperation from the losers.
// No WASM, no engine trust beyond the cut-and-choose check.
//
// Prereq: lottery-engine on :8090 (with /api/settle) + regtest bitcoind /tmp/cube-regtest.
// Run:    node enforce_winner_sweep.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { compactSize } from './covenant.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { winnerLabel, challenge, verifyCutChoose } from './garble.mjs';
import { taggedHash, hexToBytes, bytesToHex } from './musig.mjs';

const BASE = 'http://127.0.0.1:8090';
const WS = 'ws://127.0.0.1:8090/cosign';
const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sat = (b) => Math.round(b * 1e8);
const reverseHex = (h) => h.match(/../g).reverse().join('');
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), (() => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; })()]));
const HX = (h) => Buffer.from(h, 'hex');
function serialize({ inTxidInternal, vout, witnessItems, outValue, outSpk }) {
  const vin = Buffer.concat([HX(inTxidInternal), u32le(vout), Buffer.from([0x00]), u32le(0xffffffff)]);
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
  const SEED = 1; // public draw seed; rg = SEED % space is tiny -> lands in entry 0's band (a WIN)
  const players = [newPlayer(), newPlayer(), newPlayer()];
  const sockets = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey);
    sockets.push(ws);
  }
  await sleep(800);

  // deposit (via the arcade's deposit-address so the spk matches the engine) + genesis.
  const amounts = [0.30, 0.40, 0.50]; // pot ~1.2 BTC; bands sorted by account key
  for (let i = 0; i < players.length; i++) {
    const da = await (await fetch(`${BASE}/api/deposit_address?account=${players[i].accountKey}`)).json();
    const fundTxid = cli(`sendtoaddress ${da.address} ${amounts[i]}`);
    cli('-generate 1');
    const raw = cliJSON(`getrawtransaction ${fundTxid} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
    await post('/api/deposit', { account_key: players[i].accountKey, txid: fundTxid, vout });
    players[i].value = sat(amounts[i]);
  }
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));

  // SETTLE (honest): the engine asserts the true winner and pre-signs the unroll
  // with a winner-sweep lock on every loser leaf.
  const settle = await post('/api/settle', { seed: SEED });
  if (!settle.ok) fail('settle', JSON.stringify(settle));
  const total = Number(settle.total);
  const ODDS_DENOM = 4n; // must match the contract/engine (win region is 1/(DENOM+1))
  const trueRg = Number(BigInt(SEED) % (BigInt(total) * (ODDS_DENOM + 1n)));
  if (trueRg !== Number(settle.rg)) fail('rg recompute mismatch', `${trueRg} != ${settle.rg}`);
  if (settle.honest_winner === null || settle.honest_winner === undefined) fail('draw rolled over — pick a winning seed', JSON.stringify(settle));
  console.log(`settle: winner index ${settle.claimed_winner} (honest ${settle.honest_winner}); winner_key ${settle.winner_key.slice(0, 16)}…; pot ${total}`);

  // independent checks: cut-and-choose honest, and the winner-sweep secret IS derivable.
  const opened = verifyCutChoose(settle);
  if (challenge(settle.assertion, trueRg) !== null) fail('honest settle was disprovable!');
  const validLabel = winnerLabel(settle.assertion, trueRg);
  if (!validLabel) fail('honest settle did not expose the winner-sweep (valid) label');
  console.log(`cut-and-choose: re-garbled ${opened}/${settle.k} opened; challenge() -> no disprove secret; winnerLabel() -> valid label derived in JS.`);

  // the winner is the player whose account == winner_key.
  const winner = players.find((p) => p.accountKey.toLowerCase() === settle.winner_key.toLowerCase());
  if (!winner) fail('winner_key is not one of our players', settle.winner_key);
  const winnerLeaf = settle.leaves.find((l) => l.account.toLowerCase() === winner.accountKey.toLowerCase());
  const loserLeaves = settle.leaves.filter((l) => l.account.toLowerCase() !== winner.accountKey.toLowerCase());
  // the winner's own leaf must NOT be sweepable; every loser leaf MUST be.
  if (winnerLeaf.winner_sweep_script) fail('winner leaf is sweepable (should not be)');
  if (!loserLeaves.every((l) => l.winner_sweep_script)) fail('a loser leaf has no winner-sweep path');

  // broadcast the pre-signed unroll -> the real leaves materialize on-chain.
  let unrollTxid;
  try { unrollTxid = cli(`sendrawtransaction ${settle.unroll_tx_hex}`); } catch (e) { fail('unroll broadcast', String(e.stderr || e)); }
  cli('-generate 1');
  const inTxidInternal = reverseHex(unrollTxid);
  console.log(`unroll broadcast ${unrollTxid.slice(0, 16)}… — ${settle.leaves.length} leaves on-chain.`);

  // THE WINNER SWEEPS EVERY LOSER LEAF with the valid label + its own key. No loser
  // signs anything here; the winner alone takes the pot.
  let swept = 0;
  for (const leaf of loserLeaves) {
    const destAddr = cli('getnewaddress');
    const destSpk = cliJSON(`getaddressinfo ${destAddr}`).scriptPubKey;
    const outValue = leaf.value - 600;
    const script = leaf.winner_sweep_script;
    const cb = leaf.winner_sweep_control_block;
    const tapleafHash = bytesToHex(taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), compactSize(HX(script).length), HX(script)])));
    const sighashHex = scriptPathSighash({
      version: 2, lockTime: 0, inputIndex: 0,
      inputs: [{ txid: inTxidInternal, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey, sequence: 0xffffffff }],
      outputs: [{ value: outValue, spk: destSpk }],
    }, tapleafHash);
    // winner-sweep witness: [winner_sig, valid_label, winner_sweep_script, control_block]
    const sig = bytesToHex(schnorr.sign(hexToBytes(sighashHex), hexToBytes(winner.secpHex)));
    const sweepTx = serialize({ inTxidInternal, vout: leaf.vout, witnessItems: [sig, validLabel, script, cb], outValue, outSpk: destSpk });
    let txid;
    try { txid = cli(`sendrawtransaction ${sweepTx}`); } catch (e) { fail(`winner-sweep of loser leaf ${leaf.account.slice(0, 12)} rejected`, String(e.stderr || e)); }
    swept += outValue;
    console.log(`  swept loser leaf ${leaf.account.slice(0, 12)}… (${leaf.value} sat) -> winner, tx ${txid.slice(0, 12)}…`);
  }
  cli('-generate 1');

  // the winner also owns its own leaf (exitable via CSV) — so winner now controls
  // its own leaf + every swept loser leaf == the entire pot.
  const winnerOwn = winnerLeaf.value;
  const losersTotal = loserLeaves.reduce((s, l) => s + l.value, 0);
  console.log(`\nwinner controls: own leaf ${winnerOwn} + swept ${swept} (of ${losersTotal} loser leaves) = pot reattributed on-chain.`);

  for (const ws of sockets) ws.close();
  if (loserLeaves.length > 0 && swept > 0) {
    console.log('\nPASS — WINNER-SWEEP on the REAL covenant: an HONEST settle lets the proven winner');
    console.log('sweep every loser leaf to itself with the garbled VALID label — the whole pot, with NO');
    console.log('loser cooperation. Settle-enforced reattribution, end-to-end in native JS.');
    process.exit(0);
  }
  fail('nothing swept');
}
main().catch((e) => { console.error(e); process.exit(1); });
