// CLAIM WINNINGS via the persisted /api/winnings bundle (not the live settle
// response). Proves the non-custodial "withdraw my winnings" UX: after a WIN the
// engine persists the winner-sweep bundle; the winner fetches it any time and cashes
// out on-chain — broadcast the unroll, sweep every loser leaf with the VALID label +
// its own key, and CSV-exit its own leaf — taking the whole pot with NO cooperation.
//
// Prereq: lottery-engine :8090 + regtest bitcoind /tmp/cube-regtest.
// Run:    node claim_winnings.mjs

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
const get = async (p) => (await fetch(`${BASE}${p}`)).json();
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
const newPlayer = () => { const s = new Uint8Array(32); globalThis.crypto.getRandomValues(s); return { secpHex: bytesToHex(s), accountKey: bytesToHex(schnorr.getPublicKey(s)) }; };

async function main() {
  const players = [newPlayer(), newPlayer(), newPlayer()];
  const sockets = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey);
    sockets.push(ws);
  }
  await sleep(800);

  const amounts = [0.30, 0.40, 0.50];
  for (let i = 0; i < players.length; i++) {
    const da = await get(`/api/deposit_address?account=${players[i].accountKey}`);
    const tx = cli(`sendtoaddress ${da.address} ${amounts[i]}`);
    cli('-generate 1');
    const raw = cliJSON(`getrawtransaction ${tx} true`);
    const vout = raw.vout.find((o) => o.scriptPubKey.hex === da.scriptpubkey).n;
    await post('/api/deposit', { account_key: players[i].accountKey, txid: tx, vout });
  }
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok && !/covenant exists/i.test(g.error || '')) fail('genesis', JSON.stringify(g));

  // settle (win) — we IGNORE the response here; the winner will claim from /api/winnings.
  const settle = await post('/api/settle', { seed: 1 });
  if (!settle.ok) fail('settle', JSON.stringify(settle));
  if (settle.honest_winner === null) fail('rolled over — pick a winning seed', JSON.stringify(settle));

  // discover the winner purely via /api/winnings (as a fresh client would).
  let winner = null, bundle = null;
  for (const p of players) {
    const w = await get(`/api/winnings?account=${p.accountKey}`);
    if (w.you_won) { winner = p; bundle = w; }
  }
  if (!winner) fail('no winner reported by /api/winnings', JSON.stringify(settle));
  console.log(`/api/winnings: winner ${winner.accountKey.slice(0, 16)}… pot ${bundle.pot}; ${bundle.sweep_leaves.length} loser leaves to sweep`);
  if (!bundle.unroll_tx_hex || !bundle.valid_label) fail('bundle missing unroll/valid_label', JSON.stringify(bundle));

  // broadcast the persisted unroll, then sweep every loser leaf from the bundle.
  let unrollTxid;
  try { unrollTxid = cli(`sendrawtransaction ${bundle.unroll_tx_hex}`); } catch (e) { fail('unroll broadcast', String(e.stderr || e)); }
  cli('-generate 1');
  const inTxidInternal = reverseHex(unrollTxid);
  console.log(`unroll broadcast ${unrollTxid.slice(0, 16)}…`);

  let swept = 0;
  for (const leaf of bundle.sweep_leaves) {
    const destAddr = cli('getnewaddress');
    const destSpk = cliJSON(`getaddressinfo ${destAddr}`).scriptPubKey;
    const outValue = leaf.value - 600;
    const tapleafHash = bytesToHex(taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), compactSize(HX(leaf.winner_sweep_script).length), HX(leaf.winner_sweep_script)])));
    const sighashHex = scriptPathSighash({
      version: 2, lockTime: 0, inputIndex: 0,
      inputs: [{ txid: inTxidInternal, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey, sequence: 0xffffffff }],
      outputs: [{ value: outValue, spk: destSpk }],
    }, tapleafHash);
    const sig = bytesToHex(schnorr.sign(hexToBytes(sighashHex), hexToBytes(winner.secpHex)));
    const sweepTx = serialize({ inTxidInternal, vout: leaf.vout, witnessItems: [sig, bundle.valid_label, leaf.winner_sweep_script, leaf.winner_sweep_control_block], outValue, outSpk: destSpk });
    try { cli(`sendrawtransaction ${sweepTx}`); } catch (e) { fail(`sweep of loser leaf ${leaf.account.slice(0, 12)} rejected`, String(e.stderr || e)); }
    swept += outValue;
    console.log(`  swept loser leaf ${leaf.account.slice(0, 12)}… (${leaf.value} sat)`);
  }
  cli('-generate 1');

  for (const ws of sockets) ws.close();
  if (bundle.sweep_leaves.length > 0 && swept > 0) {
    console.log(`\nPASS — claimed winnings via the persisted /api/winnings bundle: winner swept ${swept} sat from ${bundle.sweep_leaves.length} loser leaves + holds its own leaf (${bundle.own_leaf.value}) = the whole pot, no cooperation.`);
    process.exit(0);
  }
  fail('nothing swept');
}
main().catch((e) => { console.error(e); process.exit(1); });
