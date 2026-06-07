// Verify the browser MuSig2 module reproduces cube's ground-truth vector
// (tests/musig_vectors.rs). Run: node verify_musig.mjs
import {
  keyAgg, aggKeyWithTweak, partialSign, projectedSecret, publicNonces,
  bytesToHex,
} from './musig.mjs';

// --- vector (from `cargo test --test musig_vectors -- --nocapture`) ---
const V = {
  MESSAGE: '5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a',
  TAPROOT_TWEAK: '42c58887489091b1fc81e7d8ac798ec5216126e2d8dae184741d240a1ac1d63b',
  AGG_KEY: 'bff0f65e2d86473ac246d8f24a8daec148944e7b6fc7af17b1e3fea8fcae317e',
  BOB_PROJ_PUB: '0261cb2550565d2dd1228f4384f8416b33fec7409f91caf901fe54cf5aff5d00bb',
  ALICE_PROJ_PUB: '03483d3fc1a9fbfd9aed032465fa0242bc18dc3283ee01717efd2e19aca8951d4f',
  ENGINE_PROJ_PUB: '037cb4fad0dcba30f232c1605a12c5c246377b329ba2d6975bbc8f22823109c0ca',
  ALICE_BASE_SK: '1cc5906ab936b1e29db24fffe9f87b33a4c64f2d3b59aed6c3c4faeb8fcba6da',
  ALICE_PROJ_SK: '438f512a613f8870d06085d232210ecd1a987b9242a728c474e25c9c531fd038',
  ALICE_HIDING_SK: 'e2d64e2bd20d5843d03a47199f059aebdf2a9904616a01fe961ee875a7748199',
  ALICE_BINDING_SK: '4b978d3aac4135213f536194522f68fbb2ca4321a49d95560ae9726cd9d6a55d',
  ALICE_HIDING_PUB: '020f8eb9edf13c5cbca406d616d9441311906d72ea405bcb7e22b99f7e892f0d20',
  ALICE_BINDING_PUB: '031451a7f53decf60829622152e16f92b9fb7b72b4521e03510eba2469a742643f',
  BOB_HIDING_PUB: '024cb6badc87cfcad700eb028e1203f2cc0fd63a919d7c199a63b7891afd300e7c',
  BOB_BINDING_PUB: '02f963d471e593d7574451d73a748ed06edae936f62cda9b4b62aa9cdd280c1d99',
  ENGINE_HIDING_PUB: '03e7e1a1b3ea5aa793f28b6122f28b875e5f5b01d1dc8dc886c83e5c968c980ef0',
  ENGINE_BINDING_PUB: '0238469201a552f6428bf11c05c64b28022a75b848c826e30449e0b4e37523e3f7',
  EXPECTED_ALICE_PARTIAL: 'b43e598bf11d5728893740677a195312a095069d1bcdb316fd678d42dab70933',
};

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = got.toLowerCase() === want.toLowerCase();
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok) { console.log(`        got:  ${got}`); console.log(`        want: ${want}`); fail++; } else pass++;
};

// (a) projected secret derivation: sk' = base + H("CubeProjector", val||idx)
const aliceProjSk = projectedSecret(V.ALICE_BASE_SK, 30000, 1);
check('projectedSecret(alice, 30000, 1)', aliceProjSk.toString(16).padStart(64, '0'), V.ALICE_PROJ_SK);

// (b) projected nonces match (sanity on point math)
const aliceNonces = publicNonces(V.ALICE_HIDING_SK, V.ALICE_BINDING_SK);
check('publicNonces hiding', aliceNonces.hidingHex, V.ALICE_HIDING_PUB);
check('publicNonces binding', aliceNonces.bindingHex, V.ALICE_BINDING_PUB);

// (c) keyagg + taproot tweak -> aggregate output key (x-only)
const pubkeys = [V.BOB_PROJ_PUB, V.ALICE_PROJ_PUB, V.ENGINE_PROJ_PUB];
const { aggInner } = keyAgg(pubkeys);
const aggKey = aggKeyWithTweak(aggInner, V.TAPROOT_TWEAK);
check('aggKey x-only', bytesToHex(aggKey.toBytes(true).slice(1)), V.AGG_KEY);

// (d) THE keystone: alice's partial signature must match byte-for-byte
const nonces = [
  { keyHex: V.BOB_PROJ_PUB, hidingHex: V.BOB_HIDING_PUB, bindingHex: V.BOB_BINDING_PUB },
  { keyHex: V.ALICE_PROJ_PUB, hidingHex: V.ALICE_HIDING_PUB, bindingHex: V.ALICE_BINDING_PUB },
  { keyHex: V.ENGINE_PROJ_PUB, hidingHex: V.ENGINE_HIDING_PUB, bindingHex: V.ENGINE_BINDING_PUB },
];
const partial = partialSign({
  pubkeys,
  tweakHex: V.TAPROOT_TWEAK,
  nonces,
  messageHex: V.MESSAGE,
  me: { secret: aliceProjSk, hidingSecHex: V.ALICE_HIDING_SK, bindingSecHex: V.ALICE_BINDING_SK },
});
check('alice partial signature', partial, V.EXPECTED_ALICE_PARTIAL);

// (e) ODD-Y base key: the browser must normalize a raw odd-Y secret to even-Y
// before projecting. Given the raw odd secret, the partial must match the same
// expected value (half of all real browser keys are odd-Y).
const ODD = {
  RAW: 'e33a6f9546c94e1d624db000160784cb15e88db973eef164fc0d63a1406a9a67',
  EXPECTED: 'b43e598bf11d5728893740677a195312a095069d1bcdb316fd678d42dab70933',
};
const oddProjSk = projectedSecret(ODD.RAW, 30000, 1);
const oddPartial = partialSign({
  pubkeys,
  tweakHex: V.TAPROOT_TWEAK,
  nonces,
  messageHex: V.MESSAGE,
  me: { secret: oddProjSk, hidingSecHex: V.ALICE_HIDING_SK, bindingSecHex: V.ALICE_BINDING_SK },
});
check('odd-Y base normalization (partial)', oddPartial, ODD.EXPECTED);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
