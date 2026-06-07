// Verify the JS covenant-spk + BIP341 key-path sighash reproduce cube
// byte-for-byte (cube/tests/covenant_js_vectors.rs). Run: node verify_covenant.mjs

import { covenantSpk, expiryScript, liftV2Spk } from './covenant.mjs';
import { keyPathSighash } from './sighash.mjs';
import { bytesToHex } from './musig.mjs';

const ENGINE = '9611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770';
const ALICE = 'cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455';
const BOB = '51deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f';

// canonical order = sorted by account key (bob < alice).
const A0 = [{ account: BOB, value: 20000 }, { account: ALICE, value: 30000 }];
const EXPIRY0 = 800000;
const A1 = [{ account: BOB, value: 15000 }, { account: ALICE, value: 35000 }];
const EXPIRY1 = 801000;

const V = {
  EXPIRY_TAPSCRIPT: '0300350cb175209611bc66d526fa3194d0f525dce21e782dcf90cc72529ec2d5486da838d83770ac',
  AGG_INNER: '0357a17fab984c517c0abb961f3b534e534b18f2765557e4aa452385d6cc09b29d',
  TAPLEAF_HASH: 'a295fdd8ada1f4c05afd7e2f06ece1fe1a134a39502712081df77db87719bf04',
  TAP_TWEAK: '42c58887489091b1fc81e7d8ac798ec5216126e2d8dae184741d240a1ac1d63b',
  OUTPUT_KEY: 'bff0f65e2d86473ac246d8f24a8daec148944e7b6fc7af17b1e3fea8fcae317e',
  COVENANT_SPK: '5120bff0f65e2d86473ac246d8f24a8daec148944e7b6fc7af17b1e3fea8fcae317e',
  C1_SPK: '5120b0cad1ea994953cf7ea6161d03b38d4a4e4d9d51f8f5f57025bdb6a44ca91f49',
  PREV_TXID: 'c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0',
  PREV_VALUE: 50000,
  OUT_VALUE: 49800,
  KEYPATH_SIGHASH: 'b67e109007eee22760861e5aff8b4ba70b314fb08c03ae1fe666844333816b86',
};

let pass = 0, fail = 0;
const check = (name, got, want) => {
  const ok = got.toLowerCase() === want.toLowerCase();
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok) { console.log(`        got:  ${got}`); console.log(`        want: ${want}`); fail++; } else pass++;
};

check('expiry tapscript', bytesToHex(expiryScript(EXPIRY0, ENGINE)), V.EXPIRY_TAPSCRIPT);

const c0 = covenantSpk(ENGINE, A0, EXPIRY0);
check('agg inner', c0.aggInner, V.AGG_INNER);
check('tapleaf hash', c0.tapleafHash, V.TAPLEAF_HASH);
check('tap tweak', c0.tapTweak, V.TAP_TWEAK);
check('output key', c0.outputKey, V.OUTPUT_KEY);
check('covenant spk (C0)', c0.spk, V.COVENANT_SPK);

const c1 = covenantSpk(ENGINE, A1, EXPIRY1);
check('next covenant spk (C1)', c1.spk, V.C1_SPK);

const sighash = keyPathSighash({
  version: 2,
  lockTime: 0,
  inputIndex: 0,
  inputs: [{ txid: V.PREV_TXID, vout: 0, value: V.PREV_VALUE, spk: V.COVENANT_SPK, sequence: 0xffffffff }],
  outputs: [{ value: V.OUT_VALUE, spk: V.C1_SPK }],
});
check('key-path sighash', sighash, V.KEYPATH_SIGHASH);

// LiftV2 deposit spk (from cube/tests/liftv2_browser_vector.rs: account=alice,
// engine=bob's key, OUTPUT_KEY below).
const LIFT_ACCOUNT = 'cb70281face51a77d51400612196032bb12422d4c07fa42997a0ab39c2431455';
const LIFT_ENGINE = '51deb9fcf4d16b0f82c75cf71e1ffb7879beb0c6bf733b0778a81b777406574f';
const LIFT_OUTPUT_KEY = '7c54257adf4b5d035c711061c61c3216a42fd5c4e7fdc3f971b1a12c1bec446e';
check('LiftV2 deposit output key', liftV2Spk(LIFT_ACCOUNT, LIFT_ENGINE).outputKey, LIFT_OUTPUT_KEY);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
