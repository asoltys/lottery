// Browser-side MuSig2 (BIP327) cosign, byte-compatible with cube's
// transmutative::musig (std tags "KeyAgg list" / "KeyAgg coefficient" /
// "MuSig/noncecoef", BIP340 challenge). Lets a player co-sign covenant refreshes
// (and pre-signed unrolls) with THEIR own key — the non-custodial requirement.
// Verified against cube's ground-truth vectors (tests/musig_vectors.rs).

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const P = secp256k1.Point;
const N = P.Fn.ORDER; // curve order

// ---- bytes / scalar helpers ----
export const hexToBytes = (h) => {
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
};
export const bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const cat = (...arrs) => { const t = arrs.reduce((n, a) => n + a.length, 0); const o = new Uint8Array(t); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; };
const mod = (a, m = N) => ((a % m) + m) % m;
const bytesToBig = (b) => BigInt('0x' + bytesToHex(b));
const bigToBytes32 = (x) => hexToBytes(mod(x, N).toString(16).padStart(64, '0'));
const reduce = (b) => mod(bytesToBig(b)); // hash -> scalar mod n

// BIP340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg)
const enc = new TextEncoder();
export function taggedHash(tag, msg) {
  const th = sha256(enc.encode(tag));
  return sha256(cat(th, th, msg));
}

// ---- point helpers ----
const ptFromBytes = (b) => P.fromHex(bytesToHex(b));
const ptBytes = (pt) => pt.toBytes(true);          // 33-byte compressed
const ptXonly = (pt) => ptBytes(pt).slice(1);      // 32-byte x
const ptParity = (pt) => ptBytes(pt)[0] === 0x03;  // true = odd Y
const negIfPt = (pt, cond) => (cond ? pt.negate() : pt);
const mul = (pt, k) => { const s = mod(k); return s === 0n ? P.ZERO : pt.multiply(s); };
const negIfScalar = (s, cond) => (cond ? mod(N - mod(s)) : mod(s));

// Projector projection tweak: t = H_tag("CubeProjector", value(8B BE) || index(4B BE))
export function projectionTweak(value, index) {
  const v = new Uint8Array(8); { let x = BigInt(value); for (let i = 7; i >= 0; i--) { v[i] = Number(x & 0xffn); x >>= 8n; } }
  const idx = new Uint8Array(4); { let x = index >>> 0; for (let i = 3; i >= 0; i--) { idx[i] = x & 0xff; x >>>= 8; } }
  return reduce(taggedHash('CubeProjector', cat(v, idx)));
}
// Normalize a base secret to its EVEN-Y form (BIP340 x-only convention). The
// keyagg lifts each account's 32-byte x-only key to its even-Y point, so the
// signer's secret must correspond to that same even-Y point — negate it if the
// raw secret's point has odd Y. (A no-op for already-even-Y keys.)
export function evenYSecret(baseSkHex) {
  let d = bytesToBig(hexToBytes(baseSkHex));
  if (ptParity(mul(P.BASE, d))) d = mod(N - d);
  return d;
}
// Projected signing secret: sk' = evenY(base_sk) + t  (mod n)
export function projectedSecret(baseSkHex, value, index) {
  return mod(evenYSecret(baseSkHex) + projectionTweak(value, index));
}

// ---- key aggregation (BIP327, cube-compatible) ----
// pubkeyHexes: array of 33-byte compressed hex. Returns sorted keys + coefs + aggInner.
export function keyAgg(pubkeyHexes) {
  const keys = pubkeyHexes.map((h) => ({ hex: h.toLowerCase(), pt: ptFromBytes(hexToBytes(h)) }));
  keys.sort((a, b) => (a.hex < b.hex ? -1 : a.hex > b.hex ? 1 : 0)); // by 33-byte compressed
  const secondHex = keys.length > 1 ? keys[1].hex : null;
  const listBytes = cat(...keys.map((k) => ptBytes(k.pt)));
  const Lhash = taggedHash('KeyAgg list', listBytes);
  const coefs = new Map();
  for (const k of keys) {
    let coef;
    if (k.hex === secondHex) coef = 1n;
    else coef = reduce(taggedHash('KeyAgg coefficient', cat(Lhash, ptBytes(k.pt))));
    coefs.set(k.hex, coef);
  }
  let aggInner = P.ZERO;
  for (const k of keys) aggInner = aggInner.add(mul(k.pt, coefs.get(k.hex)));
  return { keys, coefs, aggInner };
}

// aggKey = negateIf(aggInner, aggInner.parity) + tweak*G  (tweak optional 32B hex)
export function aggKeyWithTweak(aggInner, tweakHex) {
  if (!tweakHex) return aggInner;
  const t = bytesToBig(hexToBytes(tweakHex));
  return negIfPt(aggInner, ptParity(aggInner)).add(mul(P.BASE, t));
}

// ---- nonce aggregation + challenge ----
// signers: [{ keyHex, hidingHex, bindingHex }] (33-byte compressed nonce hexes).
function nonceAgg(signers) {
  const sorted = [...signers].sort((a, b) => (a.keyHex < b.keyHex ? -1 : 1));
  let h = P.ZERO, b = P.ZERO;
  for (const s of sorted) { h = h.add(ptFromBytes(hexToBytes(s.hidingHex))); b = b.add(ptFromBytes(hexToBytes(s.bindingHex))); }
  return { hidingAgg: h, bindingAgg: b };
}

// Full session derivation from public data, then ONE participant's partial.
//   pubkeys: all signers' projected pubkey hexes (33B)
//   tweakHex: funding taproot tweak (32B) or null
//   nonces:  [{ keyHex, hidingHex, bindingHex }] for ALL signers
//   messageHex: 32B sighash
//   me: { secret: BigInt (projected), hidingSecHex, bindingSecHex }
// Returns 32-byte partial signature hex.
export function partialSign({ pubkeys, tweakHex, nonces, messageHex, me }) {
  const { coefs, aggInner } = keyAgg(pubkeys);
  const aggKey = aggKeyWithTweak(aggInner, tweakHex);
  const msg = hexToBytes(messageHex);

  const { hidingAgg, bindingAgg } = nonceAgg(nonces);
  const nonceCoef = reduce(taggedHash('MuSig/noncecoef',
    cat(ptBytes(hidingAgg), ptBytes(bindingAgg), ptXonly(aggKey), msg)));
  const aggNonce = hidingAgg.add(mul(bindingAgg, nonceCoef));
  const challenge = reduce(taggedHash('BIP0340/challenge',
    cat(ptXonly(aggNonce), ptXonly(aggKey), msg)));

  const myPub = mul(P.BASE, me.secret);
  const myPubHex = bytesToHex(ptBytes(myPub));
  const keyCoef = coefs.get(myPubHex);
  if (keyCoef === undefined) throw new Error('my projected pubkey is not in the keyagg set');

  let sk = negIfScalar(me.secret, ptParity(aggInner));
  if (tweakHex) sk = negIfScalar(sk, ptParity(aggKey));

  const hSec = negIfScalar(bytesToBig(hexToBytes(me.hidingSecHex)), ptParity(aggNonce));
  const bSec = negIfScalar(bytesToBig(hexToBytes(me.bindingSecHex)), ptParity(aggNonce));

  const partial = mod(hSec + mod(bSec * nonceCoef) + mod(mod(sk * keyCoef) * challenge));
  return bytesToHex(bigToBytes32(partial));
}

// Public nonces (compressed hex) from secret nonces — what the client commits.
export function publicNonces(hidingSecHex, bindingSecHex) {
  return {
    hidingHex: bytesToHex(ptBytes(mul(P.BASE, bytesToBig(hexToBytes(hidingSecHex))))),
    bindingHex: bytesToHex(ptBytes(mul(P.BASE, bytesToBig(hexToBytes(bindingSecHex))))),
  };
}
