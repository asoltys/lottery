// FULL enforced settle on the LIVE arcade, on the REAL covenant — native JS only.
// Participants deposit + cosign a covenant; the engine settles (asserting a winner)
// and pre-signs the covenant's UNROLL with every leaf carrying the round's disprove
// lock. On a WRONG winner a participant (challenger) derives the disprove secret in
// the browser/node via garble.mjs, broadcasts the pre-signed unroll, and reclaims
// its OWN on-chain VTXO leaf through the leaf's disprove path. No WASM, no engine
// trust, no challenger-funded stand-in — the contested funds are the real covenant.
//
// Prereq: lottery-engine on :8090 (with /api/settle) + regtest bitcoind /tmp/cube-regtest.
// Run:    node enforce_live.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { compactSize } from './covenant.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { challenge } from './garble.mjs';
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
  const SEED = 5000; // public draw seed; lands on entry 0
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
  const amounts = [0.30, 0.40, 0.50];
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
  if (!g.ok) fail('genesis', JSON.stringify(g));
  console.log(`covenant ${g.txid.slice(0, 16)}… value ${g.covenant_value} (${g.participants} stakes)`);

  // SETTLE: engine asserts a WRONG winner and pre-signs the disprove-locked unroll.
  const total = g.covenant_value;
  const trueRg = Number(BigInt(SEED) % (BigInt(total) * 476n)); // challenger recomputes the draw
  const honest = await post('/api/settle', { seed: SEED });     // honest first (sanity)
  if (!honest.ok) fail('settle(honest)', JSON.stringify(honest));
  if (challenge(honest.assertion, trueRg) !== null) fail('honest settle was disprovable!');
  console.log(`honest settle: winner ${honest.honest_winner}; challenger finds NO disprove secret.`);

  const wrongIdx = honest.honest_winner === 1 ? 2 : 1;
  const settle = await post('/api/settle', { seed: SEED, winner: wrongIdx });
  if (!settle.ok) fail('settle(wrong)', JSON.stringify(settle));
  const secret = challenge(settle.assertion, trueRg);
  if (!secret) fail('wrong settle did not yield a disprove secret');
  console.log(`WRONG settle: claimed winner ${wrongIdx} (honest ${settle.honest_winner}); challenger derived the disprove secret in JS.`);

  // broadcast the pre-signed disprove-locked unroll -> the real leaves go on-chain.
  let unrollTxid;
  try { unrollTxid = cli(`sendrawtransaction ${settle.unroll_tx_hex}`); } catch (e) { fail('unroll broadcast', String(e.stderr || e)); }
  cli('-generate 1');
  console.log(`unroll broadcast ${unrollTxid.slice(0, 16)}… — covenant leaves materialized with the round lock.`);

  // reclaim player 0's OWN on-chain VTXO leaf via its disprove path with the secret.
  const p0 = players[0];
  const leaf = settle.leaves.find((l) => l.account.toLowerCase() === p0.accountKey.toLowerCase());
  if (!leaf || !leaf.disprove_script) fail('no disprove-locked leaf for player 0');
  cli(`-generate ${leaf.exit_delay}`); // not required for disprove path, but advances chain
  const destAddr = cli('getnewaddress');
  const destSpk = cliJSON(`getaddressinfo ${destAddr}`).scriptPubKey;
  const outValue = leaf.value - 600;
  const tapleafHash = bytesToHex(taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), compactSize(HX(leaf.disprove_script).length), HX(leaf.disprove_script)])));
  const inTxidInternal = reverseHex(unrollTxid);
  const sighashHex = scriptPathSighash({
    version: 2, lockTime: 0, inputIndex: 0,
    inputs: [{ txid: inTxidInternal, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey, sequence: 0xffffffff }],
    outputs: [{ value: outValue, spk: destSpk }],
  }, tapleafHash);
  const sig = bytesToHex(schnorr.sign(hexToBytes(sighashHex), hexToBytes(p0.secpHex)));
  // disprove witness: [sig, secret(preimage), disprove_script, disprove_control_block]
  const sweep = serialize({ inTxidInternal, vout: leaf.vout, witnessItems: [sig, secret, leaf.disprove_script, leaf.disprove_control_block], outValue, outSpk: destSpk });
  let reclaimTxid;
  try { reclaimTxid = cli(`sendrawtransaction ${sweep}`); } catch (e) { fail('disprove reclaim rejected', String(e.stderr || e)); }
  cli('-generate 1');
  const tx = cliJSON(`getrawtransaction ${reclaimTxid} true`);
  console.log(`RECLAIM confirmed ${reclaimTxid.slice(0, 16)}… player 0 took back ${outValue} sat (${tx.confirmations} conf)`);

  for (const ws of sockets) ws.close();
  if (tx.confirmations >= 1) {
    console.log('\nPASS — live enforced settle on the REAL covenant: a wrong winner lets a participant');
    console.log('reclaim its own on-chain VTXO leaf via the garbled disprove path, derived in native JS.');
    process.exit(0);
  }
  fail('reclaim not confirmed');
}
main().catch((e) => { console.error(e); process.exit(1); });
