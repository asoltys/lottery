// Shared dispute+reclaim for the enforced settle — runs identically in the browser
// and in node. Given a settle (assertion + pre-signed disprove-locked unroll) and
// the tab's own leaf, it: garble-challenges the assertion; if the engine asserted a
// WRONG winner, broadcasts the unroll (materializing the real VTXO leaves) and then
// spends the tab's OWN leaf via its disprove path with the derived secret — taking
// the contested funds back. `broadcast(txHex) -> Promise<txid>` is injected (POST
// /api/broadcast in-browser; bitcoin-cli in tests). No WASM.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { challenge } from './garble.mjs';
import { scriptPathSighash, keyPathSighash } from './sighash.mjs';
import { compactSize } from './covenant.mjs';
import { taggedHash, hexToBytes, bytesToHex, evenYSecret } from './musig.mjs';

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
export async function disputeAndReclaim({ assertion, trueRg, unrollTxHex, unrollTxid, leaf, secpHex, destSpk, broadcast, afterUnroll, fee = 600 }) {
  const secret = challenge(assertion, trueRg);
  if (!secret) return { fraud: false };

  // 1) broadcast the pre-signed disprove-locked unroll (idempotent: it may already
  //    be in the chain/mempool from another challenger).
  let utxid = unrollTxid;
  try { utxid = await broadcast(unrollTxHex); } catch (_e) { /* already broadcast */ }

  // The unroll is TRUC (v3): until it confirms it may have only its CPFP child, so
  // wait for confirmation before spending a leaf (the reclaim would be a 2nd child).
  if (afterUnroll) await afterUnroll(utxid);

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

// ---- connector-bound fork-attest reclaim (the full exit-ladder graph) ----
const P = secp256k1.Point;
const N = P.Fn.ORDER;
const mod = (a, m = N) => ((a % m) + m) % m;
const big = (u) => BigInt('0x' + bytesToHex(u));

const toHex32 = (n) => n.toString(16).padStart(64, '0');

function serialize2({ inputs, witnesses, outValue, outSpk }) {
  const H = hexToBytes;
  const vins = inputs.map((i) => cat(H(i.txidInternal), u32le(i.vout), Uint8Array.from([0x00]), u32le(0xffffffff)));
  const out = cat(u64le(outValue), varint(H(outSpk).length), H(outSpk));
  const wit = cat(...witnesses.map((items) => cat(varint(items.length), ...items.map((w) => cat(varint(H(w).length), H(w))))));
  return bytesToHex(cat(u32le(2), Uint8Array.from([0x00, 0x01]), varint(inputs.length), ...vins, varint(1), out, wit, u32le(0)));
}

// Reclaim via a connector-bound tx::fork-attest: spends [the tab's leaf disprove
// path, the exit-ladder connector]. Both signatures commit BOTH prevouts (the
// connector included), so the dispute is bound to the canonical exit-ladder — the
// engine can't dodge it onto a fork. `provideConnector(spkHex)` must fund + return
// the connector { txidInternal, vout, value } (the exit-ladder output).
export async function forkAttestReclaim({ assertion, trueRg, unrollTxHex, unrollTxid, leaf, secpHex, accountKey, destSpk, broadcast, provideConnector, afterUnroll, fee = 800 }) {
  const secret = challenge(assertion, trueRg);
  if (!secret) return { fraud: false };
  let utxid = unrollTxid;
  try { utxid = await broadcast(unrollTxHex); } catch (_e) { /* already broadcast */ }
  // TRUC: wait for the v3 unroll to confirm before spending a leaf (see disputeAndReclaim).
  if (afterUnroll) await afterUnroll(utxid);

  // the connector: a BIP86 P2TR of the challenger's own key, funded by the exit-ladder.
  const tweak = mod(big(taggedHash('TapTweak', hexToBytes(accountKey))));
  const internal = P.fromHex('02' + accountKey);
  const q = internal.add(P.BASE.multiply(tweak));
  const connSpk = '5120' + bytesToHex(q.toBytes(true).slice(1));
  const tweakedSecret = toHex32(mod(evenYSecret(secpHex) + tweak)); // BIP86 key-path secret
  const conn = await provideConnector(connSpk); // { txidInternal, vout, value }

  const leafInTxid = reverseHex(utxid);
  const inputs = [
    { txidInternal: leafInTxid, vout: leaf.vout },        // 0: contested leaf (disprove path)
    { txidInternal: conn.txidInternal, vout: conn.vout }, // 1: exit-ladder connector (key path)
  ];
  const prevs = [
    { txid: leafInTxid, vout: leaf.vout, value: leaf.value, spk: leaf.scriptpubkey },
    { txid: conn.txidInternal, vout: conn.vout, value: conn.value, spk: connSpk },
  ];
  const outValue = leaf.value + conn.value - fee;

  const tapleafHash = bytesToHex(taggedHash('TapLeaf', cat(Uint8Array.from([0xc0]), compactSize(hexToBytes(leaf.disprove_script).length), hexToBytes(leaf.disprove_script))));
  const sh0 = scriptPathSighash({ version: 2, lockTime: 0, inputIndex: 0, inputs: prevs.map((p) => ({ ...p, sequence: 0xffffffff })), outputs: [{ value: outValue, spk: destSpk }] }, tapleafHash);
  const sh1 = keyPathSighash({ version: 2, lockTime: 0, inputIndex: 1, inputs: prevs.map((p) => ({ ...p, sequence: 0xffffffff })), outputs: [{ value: outValue, spk: destSpk }] });
  const sig0 = bytesToHex(schnorr.sign(hexToBytes(sh0), hexToBytes(secpHex)));
  const sig1 = bytesToHex(schnorr.sign(hexToBytes(sh1), hexToBytes(tweakedSecret)));

  const txHex = serialize2({
    inputs,
    witnesses: [[sig0, secret, leaf.disprove_script, leaf.disprove_control_block], [sig1]],
    outValue, outSpk: destSpk,
  });
  const reclaimTxid = await broadcast(txHex);
  return { fraud: true, secret, unrollTxid: utxid, reclaimTxid, outValue, connector: connSpk };
}
