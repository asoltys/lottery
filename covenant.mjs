// Client-side reconstruction of a Cube pot COVENANT scriptpubkey (the timeout-
// tree funding output), so the browser can confirm — before co-signing a refresh
// — that the tx output really is the correct next-state covenant paying it an
// exitable claim, rather than trusting the server. Mirrors cube's
// timeout_tree::funding_taproot byte-for-byte (verified in verify_covenant.mjs).

import {
  keyAgg, aggKeyWithTweak, projectPublicKey, taggedHash, hexToBytes, bytesToHex,
} from './musig.mjs';

const cat = (...arrs) => {
  const t = arrs.reduce((n, a) => n + a.length, 0);
  const o = new Uint8Array(t); let i = 0;
  for (const a of arrs) { o.set(a, i); i += a.length; }
  return o;
};

// Bitcoin minimal CScriptNum push (matches rust-bitcoin Builder::push_int for the
// CLTV height: 0 -> OP_0; 1..16 -> OP_1..OP_16; -1 -> OP_1NEGATE; else length-
// prefixed little-endian minimal scriptint).
export function pushScriptNum(n) {
  if (n === 0) return Uint8Array.from([0x00]);
  if (n >= 1 && n <= 16) return Uint8Array.from([0x50 + n]);
  if (n === -1) return Uint8Array.from([0x4f]);
  const neg = n < 0;
  let abs = Math.abs(n);
  const bytes = [];
  while (abs > 0) { bytes.push(abs & 0xff); abs = Math.floor(abs / 256); }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1] |= 0x80;
  return Uint8Array.from([bytes.length, ...bytes]); // len prefix (script < 76 bytes)
}

// Bitcoin compact-size (varint) for lengths.
export function compactSize(n) {
  if (n < 0xfd) return Uint8Array.from([n]);
  if (n <= 0xffff) return Uint8Array.from([0xfd, n & 0xff, (n >> 8) & 0xff]);
  return Uint8Array.from([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
}

// The funding covenant's expiry script: <height> CLTV DROP <engine_x> CHECKSIG.
export function expiryScript(expiryHeight, engineXonlyHex) {
  return cat(
    pushScriptNum(expiryHeight),
    Uint8Array.from([0xb1, 0x75, 0x20]), // OP_CLTV OP_DROP OP_PUSHBYTES_32
    hexToBytes(engineXonlyHex),
    Uint8Array.from([0xac]),             // OP_CHECKSIG
  );
}

// x-only (32-byte) key -> its even-Y compressed point hex (02 || x).
const evenY33 = (xonlyHex) => '02' + xonlyHex;

// Generic taproot spk from a precomputed inner aggregate Point + a single leaf
// script. Returns { spk, outputKey } hex.
function taprootSpkFromInner(aggInner, leafScript) {
  const aggInnerHex = bytesToHex(aggInner.toBytes(true));
  const tapleafHash = taggedHash('TapLeaf', cat(Uint8Array.from([0xc0]), compactSize(leafScript.length), leafScript));
  const tapTweak = taggedHash('TapTweak', cat(hexToBytes(aggInnerHex.slice(2)), tapleafHash));
  const outputKey = aggKeyWithTweak(aggInner, bytesToHex(tapTweak));
  const outputKeyX = bytesToHex(outputKey.toBytes(true).slice(1));
  return { spk: '5120' + outputKeyX, outputKey: outputKeyX };
}

// The LiftV2 deposit scriptpubkey: P2TR with key-path = MuSig2(account, engine)
// (NO projection) and a script-path CSV-3-months account-only sweep leaf. Mirrors
// cube's return_liftv2_taproot. Lets the depositor confirm it is spending its OWN
// deposit before co-signing the lift-in.
export function liftV2Spk(accountXonlyHex, engineXonlyHex) {
  const { aggInner } = keyAgg([evenY33(accountXonlyHex), evenY33(engineXonlyHex)]);
  const sweepScript = cat(
    Uint8Array.from([0x02, 0xa0, 0x32, 0xb2, 0x75, 0x20]), // <12960> CSV DROP PUSH32
    hexToBytes(accountXonlyHex),
    Uint8Array.from([0xac]),                                // OP_CHECKSIG
  );
  return taprootSpkFromInner(aggInner, sweepScript);
}

// Build the covenant scriptpubkey for an allocation state.
//   engineXonlyHex: 32-byte engine key hex
//   allocations: [{ account: <32-byte x-only hex>, value }]  (MUST be in the same
//                canonical order the engine uses — sorted by account key)
//   expiryHeight: covenant expiry height
// Returns { spk, outputKey, aggInner, tapTweak, tapleafHash } (all hex).
export function covenantSpk(engineXonlyHex, allocations, expiryHeight) {
  const total = allocations.reduce((s, a) => s + Number(a.value), 0);
  // project each participant by (value, index), engine by (total, len).
  const projected = allocations.map((a, i) => projectPublicKey(evenY33(a.account), Number(a.value), i));
  projected.push(projectPublicKey(evenY33(engineXonlyHex), total, allocations.length));

  const { aggInner } = keyAgg(projected);
  const aggInnerHex = bytesToHex(aggInner.toBytes(true));
  const aggInnerX = aggInnerHex.slice(2); // drop 02/03 prefix

  const script = expiryScript(expiryHeight, engineXonlyHex);
  const tapleafHash = taggedHash('TapLeaf', cat(Uint8Array.from([0xc0]), compactSize(script.length), script));
  const tapTweak = taggedHash('TapTweak', cat(hexToBytes(aggInnerX), tapleafHash));

  const outputKey = aggKeyWithTweak(aggInner, bytesToHex(tapTweak));
  const outputKeyX = bytesToHex(outputKey.toBytes(true).slice(1));

  return {
    spk: '5120' + outputKeyX,
    outputKey: outputKeyX,
    aggInner: aggInnerHex,
    tapTweak: bytesToHex(tapTweak),
    tapleafHash: bytesToHex(tapleafHash),
  };
}
