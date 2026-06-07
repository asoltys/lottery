// ENFORCEMENT on regtest: prove that the garbled winner-verifier's "invalid"
// label actually spends the VTXO disprove leaf on Bitcoin (a wrong-winner claim
// is punishable), while the honest "valid" label is REJECTED by Bitcoin Core (an
// honest engine is safe). Values come from cube/tests/lottery_enforcement.rs.
//
// Prereq: regtest bitcoind at /tmp/cube-regtest (wallet 'cube').
// Run:    node enforcement_regtest.mjs

import { execSync } from 'node:child_process';
import { schnorr } from '@noble/curves/secp256k1.js';
import { compactSize } from './covenant.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { taggedHash, hexToBytes, bytesToHex } from './musig.mjs';

const DD = '/tmp/cube-regtest';
const cli = (a) => execSync(`bitcoin-cli -datadir=${DD} -rpcwallet=cube ${a}`, { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();
const cliJSON = (a) => JSON.parse(cli(a));
const reverseHex = (h) => h.match(/../g).reverse().join('');
const fail = (m, x) => { console.error('FAIL —', m, x ?? ''); process.exit(1); };

// from cube/tests/lottery_enforcement.rs (deterministic):
const LEAF_SPK = '51206a83ca67f3dbf95949766fe8d8e70e82fa6d3b555431f98e27bc8201caf4e084';
const DISPROVE_SCRIPT = 'a914e86378d0f39f4719b2d990894f476b6c294b70238820cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455ac';
const CONTROL_BLOCK = 'c0840aec4841caf87ddb0ba6659ea8506dcb55219a682f3325469c0bbf227094a49852fcd99619e78be8cf44ab15eebbbcfdcdb812409bb7671af86110e71744c4';
const INVALID_LABEL = 'b44b072c726421812d33d3989de3d4711ed9ce51003b8880c1bffbaffe5720f6'; // wrong-winner secret
const VALID_LABEL = '1c3620b54cd64007f7b887ad616f9605fc3c374f2b64e8c0296f6a5142434db6';   // honest output
const ACCOUNT_SK = '1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da';

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

// build a disprove punishment spend of a funded leaf, using `preimage` as the
// hashlock opener.
function buildDisprove(fundTxid, vout, value, preimage) {
  const destAddr = cli('getnewaddress');
  const destSpk = cliJSON(`getaddressinfo ${destAddr}`).scriptPubKey;
  const outValue = value - 500;
  const tapleafHash = bytesToHex(taggedHash('TapLeaf', Buffer.concat([Buffer.from([0xc0]), compactSize(HX(DISPROVE_SCRIPT).length), HX(DISPROVE_SCRIPT)])));
  const inTxidInternal = reverseHex(fundTxid);
  const sighash = scriptPathSighash({
    version: 2, lockTime: 0, inputIndex: 0,
    inputs: [{ txid: inTxidInternal, vout, value, spk: LEAF_SPK, sequence: 0xffffffff }],
    outputs: [{ value: outValue, spk: destSpk }],
  }, tapleafHash);
  const sig = bytesToHex(schnorr.sign(hexToBytes(sighash), hexToBytes(ACCOUNT_SK)));
  // witness: [sig, preimage, script, control_block]  (preimage on top for OP_HASH160)
  return serialize({ inTxidInternal, vout, witnessItems: [sig, preimage, DISPROVE_SCRIPT, CONTROL_BLOCK], outValue, outSpk: destSpk });
}

function fundLeaf() {
  const addr = cliJSON(`decodescript ${LEAF_SPK}`).address;
  const txid = cli(`sendtoaddress ${addr} 0.001`);
  cli('-generate 1');
  const raw = cliJSON(`getrawtransaction ${txid} true`);
  const v = raw.vout.find((o) => o.scriptPubKey.hex === LEAF_SPK);
  return { txid, vout: v.n, value: Math.round(v.value * 1e8) };
}

function main() {
  // NEGATIVE: the honest "valid" label must NOT open the disprove lock.
  const f1 = fundLeaf();
  let rejected = false;
  try { cli(`sendrawtransaction ${buildDisprove(f1.txid, f1.vout, f1.value, VALID_LABEL)}`); }
  catch (e) { rejected = /EQUALVERIFY|script-verify|mandatory/.test(String(e.stderr || e)); }
  console.log(`honest 'valid' label rejected by Bitcoin Core: ${rejected}`);
  if (!rejected) fail('honest label should NOT open the disprove leaf');

  // POSITIVE: the garbled "invalid" label (wrong-winner) DOES punish on-chain.
  const f2 = fundLeaf();
  let punishTxid;
  try { punishTxid = cli(`sendrawtransaction ${buildDisprove(f2.txid, f2.vout, f2.value, INVALID_LABEL)}`); }
  catch (e) { fail('disprove punishment rejected', String(e.stderr || e)); }
  cli('-generate 1');
  const tx = cliJSON(`getrawtransaction ${punishTxid} true`);
  console.log(`disprove punishment confirmed: ${punishTxid.slice(0, 16)}… (${tx.confirmations} conf)`);

  if (rejected && tx.confirmations >= 1) {
    console.log("\nPASS — on regtest: an honest winner claim cannot open the disprove leaf, but a");
    console.log("wrong-winner claim's garbled 'invalid' label spends it. Loser-forfeit is enforced");
    console.log('by Bitcoin consensus — no loser signature required, lying is punished.');
    process.exit(0);
  }
  fail('enforcement not demonstrated');
}

main();
