// BIP341 taproot KEY-PATH sighash (SIGHASH_DEFAULT), recomputed in the browser so
// a player signs a sighash it derived from the actual tx — never one the server
// merely asserts. Mirrors rust-bitcoin's taproot_key_spend_signature_hash with
// Prevouts::All (verified in verify_covenant.mjs).

import { taggedHash, hexToBytes } from './musig.mjs';
import { compactSize } from './covenant.mjs';

const cat = (...arrs) => {
  const t = arrs.reduce((n, a) => n + a.length, 0);
  const o = new Uint8Array(t); let i = 0;
  for (const a of arrs) { o.set(a, i); i += a.length; }
  return o;
};
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };

import { sha256 } from '@noble/hashes/sha2.js';

// tx: {
//   version, lockTime, inputIndex,
//   inputs:  [{ txid (32-byte hex, internal order), vout, value, spk (hex), sequence? }],
//   outputs: [{ value, spk (hex) }],
// }
// Returns the 32-byte sighash hex.
export function keyPathSighash(tx) {
  const hashType = 0x00; // SIGHASH_DEFAULT
  const inSeq = (i) => (i.sequence === undefined ? 0xffffffff : i.sequence);

  const shaPrevouts = sha256(cat(...tx.inputs.map((i) => cat(hexToBytes(i.txid), u32le(i.vout)))));
  const shaAmounts = sha256(cat(...tx.inputs.map((i) => u64le(i.value))));
  const shaScriptpubkeys = sha256(cat(...tx.inputs.map((i) => {
    const spk = hexToBytes(i.spk);
    return cat(compactSize(spk.length), spk);
  })));
  const shaSequences = sha256(cat(...tx.inputs.map((i) => u32le(inSeq(i)))));
  const shaOutputs = sha256(cat(...tx.outputs.map((o) => {
    const spk = hexToBytes(o.spk);
    return cat(u64le(o.value), compactSize(spk.length), spk);
  })));

  const spendType = 0x00; // key-path, no annex
  const ss = cat(
    Uint8Array.from([0x00]),       // epoch
    Uint8Array.from([hashType]),
    u32le(tx.version),
    u32le(tx.lockTime),
    shaPrevouts,
    shaAmounts,
    shaScriptpubkeys,
    shaSequences,
    shaOutputs,
    Uint8Array.from([spendType]),
    u32le(tx.inputIndex),
  );
  return Array.from(taggedHash('TapSighash', ss), (b) => b.toString(16).padStart(2, '0')).join('');
}

// BIP341 SCRIPT-path sighash (ext_flag=1, no annex) — for unilaterally sweeping a
// VTXO leaf via its tapscript (CSV exit). Same common fields as the key-path,
// plus the tapleaf hash / key version / codesep position. `tapleafHash` is hex.
export function scriptPathSighash(tx, tapleafHash) {
  const hashType = 0x00;
  const inSeq = (i) => (i.sequence === undefined ? 0xffffffff : i.sequence);
  const shaPrevouts = sha256(cat(...tx.inputs.map((i) => cat(hexToBytes(i.txid), u32le(i.vout)))));
  const shaAmounts = sha256(cat(...tx.inputs.map((i) => u64le(i.value))));
  const shaScriptpubkeys = sha256(cat(...tx.inputs.map((i) => {
    const spk = hexToBytes(i.spk);
    return cat(compactSize(spk.length), spk);
  })));
  const shaSequences = sha256(cat(...tx.inputs.map((i) => u32le(inSeq(i)))));
  const shaOutputs = sha256(cat(...tx.outputs.map((o) => {
    const spk = hexToBytes(o.spk);
    return cat(u64le(o.value), compactSize(spk.length), spk);
  })));
  const spendType = 0x02; // ext_flag=1 (script path), no annex
  const ss = cat(
    Uint8Array.from([0x00]),
    Uint8Array.from([hashType]),
    u32le(tx.version),
    u32le(tx.lockTime),
    shaPrevouts,
    shaAmounts,
    shaScriptpubkeys,
    shaSequences,
    shaOutputs,
    Uint8Array.from([spendType]),
    u32le(tx.inputIndex),
    hexToBytes(tapleafHash),       // tapleaf hash
    Uint8Array.from([0x00]),       // key version
    u32le(0xffffffff),             // codesep position (none)
  );
  return Array.from(taggedHash('TapSighash', ss), (b) => b.toString(16).padStart(2, '0')).join('');
}
