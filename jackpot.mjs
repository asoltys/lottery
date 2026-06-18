// Deterministic JACKPOT account derivation — the cross-language mirror of
// CosignHub::jackpot_account (server/src/cosign.rs). The accumulating jackpot is
// carried in the covenant as an ordinary participant allocation owned by this
// operator-controlled account; a headless operator cosigner (reusing
// cosign_client.mjs) signs on its behalf, so a contract-held balance can live in
// the covenant WITHOUT any special path in the money-critical coordinator.
//
//   jk_secret  = tag256("Cube/arcade/jackpot/v1", engine_secret)   (BIP340 tagged hash)
//   jk_account = BIP340 x-only pubkey of jk_secret
//
// Matches the Rust side because the engine already relies on the identical
// tag256 <-> HashTag::CustomString equivalence for deposit-claim signatures.

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32 } from '@scure/base';
import { bytesToHex, hexToBytes } from './musig.mjs';

const enc = new TextEncoder();
const cat = (...a) => {
  const arr = a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x)));
  const n = arr.reduce((s, x) => s + x.length, 0);
  const o = new Uint8Array(n); let i = 0;
  for (const x of arr) { o.set(x, i); i += x.length; }
  return o;
};
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };

// Decode an nsec (bech32, hrp "nsec") into the 32-byte secret.
export function nsecToSecret(nsec) {
  const { prefix, words } = bech32.decode(nsec.trim(), 1023);
  if (prefix !== 'nsec') throw new Error('not an nsec');
  return Uint8Array.from(bech32.fromWords(words));
}

// engineSecret: 32-byte Uint8Array (or hex). Returns { secpHex, accountHex }.
export function deriveJackpot(engineSecret) {
  const sk = typeof engineSecret === 'string' ? hexToBytes(engineSecret) : engineSecret;
  const secp = tag256('Cube/arcade/jackpot/v1', sk);
  const account = schnorr.getPublicKey(secp);
  return { secpHex: bytesToHex(secp), accountHex: bytesToHex(account) };
}
