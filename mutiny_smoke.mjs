// LIVE MUTINYNET smoke: full non-custodial covenant lifecycle through the public
// arcade at lotto.adamsoltys.com (engine on real Mutinynet), over wss /cosign +
// the mut node. deposit -> genesis -> refresh -> unroll -> unilateral CSV exit.
// Self-funded from the engine's own "mutiny" wallet; the exit reclaims the funds.
//
// bitcoin-cli runs in the mut container on cs via ssh; no mining (Mutinynet makes
// ~30s blocks) — we wait for real confirmations. Run from the lottery dir locally.
//   node mutiny_smoke.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { attachCosign } from './cosign_client.mjs';
import { compactSize } from './covenant.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { taggedHash, hexToBytes, bytesToHex } from './musig.mjs';

const BASE = 'https://lotto.adamsoltys.com';
const WS = 'wss://lotto.adamsoltys.com/cosign';
const RPC = 'docker exec mut bitcoin-cli -rpcuser=user -rpcpassword=password -rpcwallet=mutiny';
const cli = (a) => execSync(`ssh cs "${RPC} ${a}"`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reverseHex = (h) => h.match(/../g).reverse().join('');
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };
const post = async (p, b) => (await fetch(`${BASE}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) })).json();

const blockCount = () => parseInt(cli('getblockcount'), 10);
async function waitBlocks(n, label) {
  const start = blockCount();
  const target = start + n;
  process.stdout.write(`  waiting ${n} block(s)${label ? ' (' + label + ')' : ''} from ${start}…`);
  while (blockCount() < target) await sleep(5000);
  process.stdout.write(` now ${blockCount()}\n`);
}
// The mut node has NO txindex, so getrawtransaction can't see confirmed txs.
// gettransaction works for WALLET txs (deposits, the exit sweep paying a wallet
// address); gettxout works for any unspent output (covenant + leaf outputs).
const walletTx = (txid) => cliJSON(`gettransaction ${txid} true`);
async function waitWalletConf(txid, label) {
  process.stdout.write(`  waiting for ${label} ${txid.slice(0, 12)}… to confirm`);
  for (;;) {
    try { const c = walletTx(txid).confirmations; if (c >= 1) { process.stdout.write(` (${c} conf)\n`); return; } } catch (_e) {}
    await sleep(5000);
  }
}
async function waitOutConf(txid, vout, label) {
  process.stdout.write(`  waiting for ${label} ${txid.slice(0, 12)}…:${vout} to confirm`);
  for (;;) {
    const o = cli(`gettxout ${txid} ${vout}`);
    if (o && o !== 'null') { try { const j = JSON.parse(o); if (j && j.confirmations >= 1) { process.stdout.write(` (${j.confirmations} conf)\n`); return; } } catch (_e) {} }
    await sleep(5000);
  }
}
// Locate the vout paying a known scriptpubkey via gettxout (no txindex needed).
function findVout(txid, spkHex) {
  for (let v = 0; v < 4; v++) {
    const o = cli(`gettxout ${txid} ${v}`);
    if (o && o !== 'null') { try { const j = JSON.parse(o); if (j.scriptPubKey && j.scriptPubKey.hex === spkHex) return v; } catch (_e) {} }
  }
  throw new Error(`vout for ${spkHex.slice(0, 16)}… not found in ${txid}`);
}

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
  console.log(`Mutinynet tip ${blockCount()}; engine balance ${cli('getbalance')} BTC`);
  const players = [newPlayer(), newPlayer(), newPlayer()];
  const sockets = [];
  const events = [];
  for (const p of players) {
    const ws = new WebSocket(WS);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    attachCosign(ws, p.secpHex, p.accountKey, (k, d) => events.push({ who: p.accountKey.slice(0, 6), k, ...d }));
    sockets.push(ws);
  }
  await sleep(1200);

  // 1) DEPOSIT: fund a LiftV2 address per player, then register each UTXO.
  const amounts = [0.0003, 0.0004, 0.0005];
  for (let i = 0; i < players.length; i++) {
    const da = await (await fetch(`${BASE}/api/deposit_address?account=${players[i].accountKey}`)).json();
    if (!da.address) fail('deposit_address', JSON.stringify(da));
    players[i].fundTxid = cli(`sendtoaddress ${da.address} ${amounts[i].toFixed(8)}`);
    players[i].da = da;
    console.log(`  funded player ${i} ${amounts[i]} BTC -> ${da.address.slice(0, 16)}… (${players[i].fundTxid.slice(0, 12)}…)`);
  }
  for (const p of players) await waitWalletConf(p.fundTxid, 'deposit');
  for (let i = 0; i < players.length; i++) {
    const vout = findVout(players[i].fundTxid, players[i].da.scriptpubkey);
    const dr = await post('/api/deposit', { account_key: players[i].accountKey, txid: players[i].fundTxid, vout });
    if (!dr.ok) fail('register deposit', JSON.stringify(dr));
    players[i].deposit = { vout, value: dr.value };
  }
  console.log('deposits registered (sat):', players.map((p) => p.deposit.value).join(', '));

  // 2) GENESIS (arcade cosigns over /cosign + broadcasts).
  const g = await post('/api/covenant/genesis', {});
  if (!g.ok) fail('genesis', JSON.stringify(g));
  console.log(`GENESIS: covenant ${g.txid.slice(0, 16)}… value ${g.covenant_value} (${g.participants} participants)`);
  await waitOutConf(g.txid, 0, 'genesis');

  // 3) REFRESH (mirror minus fee) — moves the covenant on-chain + re-presigns unroll.
  const r = await post('/api/covenant/refresh', {});
  if (!r.ok) fail('refresh', JSON.stringify(r));
  console.log(`REFRESH: new covenant ${r.refresh_txid.slice(0, 16)}… value ${r.covenant_value}; unroll pre-signed ${r.unroll_txid.slice(0, 16)}…`);
  await waitOutConf(r.refresh_txid, 0, 'refresh');
  const leaves = r.leaves || [];

  // player 0's leaf (needed to wait on the unroll's confirmation + to exit).
  const p0 = players[0];
  const leaf = leaves.find((l) => l.account.toLowerCase() === p0.accountKey.toLowerCase());
  if (!leaf) fail('no leaf for player 0', JSON.stringify(leaves));

  // 4) UNROLL: broadcast the pre-signed unroll (cooperative/forced exit).
  const u = await post('/api/covenant/unroll', {});
  if (!u.ok) fail('unroll', JSON.stringify(u));
  console.log(`UNROLL broadcast: ${u.unroll_txid.slice(0, 16)}…`);
  await waitOutConf(u.unroll_txid, leaf.vout, 'unroll');

  // 5) UNILATERAL EXIT: player 0 CSV-sweeps its own leaf with only its key.
  await waitBlocks(leaf.exit_delay, `CSV maturity ${leaf.exit_delay}`); // mature the relative timelock
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
  console.log(`EXIT: player 0 broadcast sweep ${sweepTxid.slice(0, 16)}… (${outValue} sat -> ${destAddr.slice(0, 14)}…)`);
  await waitWalletConf(sweepTxid, 'exit sweep');

  for (const ws of sockets) ws.close();
  const rejects = events.filter((e) => e.k === 'reject');
  if (!rejects.length) {
    console.log('\nPASS — full non-custodial lifecycle on LIVE MUTINYNET through the public arcade:');
    console.log('deposit -> genesis -> refresh -> unroll -> unilateral CSV exit. No operator custody.');
    process.exit(0);
  }
  fail('lifecycle had cosign rejects', JSON.stringify(rejects));
}

main().catch((e) => { console.error(e); process.exit(1); });
