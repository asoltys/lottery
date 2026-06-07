// Shared dispute+reclaim for the enforced settle — runs identically in the browser
// and in node. Given a settle (assertion + pre-signed disprove-locked unroll) and
// the tab's own leaf, it: garble-challenges the assertion; if the engine asserted a
// WRONG winner, broadcasts the unroll (materializing the real VTXO leaves) and then
// spends the tab's OWN leaf via its disprove path with the derived secret — taking
// the contested funds back. `broadcast(txHex) -> Promise<txid>` is injected (POST
// /api/broadcast in-browser; bitcoin-cli in tests). No WASM.

import { schnorr } from '@noble/curves/secp256k1.js';
import { challenge } from './garble.mjs';
import { scriptPathSighash } from './sighash.mjs';
import { compactSize } from './covenant.mjs';
import { taggedHash, hexToBytes, bytesToHex } from './musig.mjs';

const cat = (...arrs) => { const t = arrs.reduce((n, a) => n + a.length, 0); const o = new Uint8Array(t); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const varint = (n) => (n < 0xfd ? Uint8Array.from([n]) : Uint8Array.from([0xfd, n & 0xff, (n >> 8) & 0xff]));
const reverseHex = (h) => h.match(/../g).reverse().join('');

// minimal segwit serializer: 1 taproot script-path input -> 1 output.
function serializeSpend({ inTxidInternal, vout, witnessItems, outValue, outSpk }) {
  const H = hexToBytes;
  const vin = cat(H(inTxidInternal), u32le(vout), Uint8Array.from([0x00]), u32le(0xffffffff));
  const out = cat(u64le(outValue), varint(H(outSpk).length), H(outSpk));
  const wit = cat(varint(witnessItems.length), ...witnessItems.map((w) => cat(varint(H(w).length), H(w))));
  return bytesToHex(cat(u32le(2), Uint8Array.from([0x00, 0x01]), varint(1), vin, varint(1), out, wit, u32le(0)));
}

// Verify a settle and, on fraud, reclaim the tab's own leaf. Returns
// { fraud:false } | { fraud:true, secret, unrollTxid, reclaimTxid, outValue }.
export async function disputeAndReclaim({ assertion, trueRg, unrollTxHex, unrollTxid, leaf, secpHex, destSpk, broadcast, fee = 600 }) {
  const secret = challenge(assertion, trueRg);
  if (!secret) return { fraud: false };

  // 1) broadcast the pre-signed disprove-locked unroll (idempotent: it may already
  //    be in the chain/mempool from another challenger).
  let utxid = unrollTxid;
  try { utxid = await broadcast(unrollTxHex); } catch (_e) { /* already broadcast */ }

  // 2) spend the tab's own leaf via the disprove path with the garbled secret.
  const outValue = leaf.value - fee;
  const tapleafHash = bytesToHex(taggedHash('TapLeaf', cat(
    Uint8Array.from([0xc0]),
    compactSize(hexToBytes(leaf.disprove_script).length),
    hexToBytes(leaf.disprove_script),
  )));
  const inTxidInternal = reverseHex(utxid);
  const sighashHex = scriptPathSighash({
    version: 2, lockTime: 0, inputIndex: 0,
    inputs: [{ txid: inTxidInternal, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey, sequence: 0xffffffff }],
    outputs: [{ value: outValue, spk: destSpk }],
  }, tapleafHash);
  const sig = bytesToHex(schnorr.sign(hexToBytes(sighashHex), hexToBytes(secpHex)));
  // disprove witness: [sig, secret(preimage), disprove_script, disprove_control_block]
  const txHex = serializeSpend({
    inTxidInternal, vout: leaf.vout,
    witnessItems: [sig, secret, leaf.disprove_script, leaf.disprove_control_block],
    outValue, outSpk: destSpk,
  });
  const reclaimTxid = await broadcast(txHex);
  return { fraud: true, secret, unrollTxid: utxid, reclaimTxid, outValue };
}
