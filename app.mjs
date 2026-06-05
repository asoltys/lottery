// Cube Lottery — browser client (v2: proportional-odds jackpot).
// Keys are generated and `enter` calls are BLS-signed entirely in the browser,
// byte-identical to the Rust engine. The engine verifies the signature and runs
// the call; rounds are closed/settled automatically by the server.

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

const Fr = bls.fields.Fr;
const enc = new TextEncoder();

// ---- byte helpers ----
const hx = (u) => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((x) => parseInt(x, 16)));
const beToBig = (u) => { let x = 0n; for (const c of u) x = (x << 8n) | BigInt(c); return x; };
const cat = (...a) => {
  const arr = a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x)));
  const n = arr.reduce((s, x) => s + x.length, 0);
  const o = new Uint8Array(n); let i = 0;
  for (const x of arr) { o.set(x, i); i += x.length; }
  return o;
};
const u16le = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const tag256 = (t, m) => { const x = sha256(enc.encode(t)); return sha256(cat(x, x, m)); };
const tag512 = (t, m) => { const x = sha512(enc.encode(t)); return sha512(cat(x, x, m)); };

// ---- keys ----
const blsScalar = (secp) => beToBig(tag512('Cube/bls/secretkey', secp).slice(0, 48)) % Fr.ORDER;
const blsPub = (secp) => bls.G1.Point.BASE.multiply(blsScalar(secp)).toBytes();
const acctKey = (secp) => schnorr.getPublicKey(secp);
function newIdentity() {
  const secp = crypto.getRandomValues(new Uint8Array(32));
  return { secp: hx(secp), accountKey: hx(acctKey(secp)), blsKey: hx(blsPub(secp)) };
}

// ---- Call SBE (matches Rust encode_sbe) ----
function encCalldata(cd) {
  let body = u32le(cd.length);
  for (const e of cd) {
    if (e.type === 'payable') body = cat(body, [0x09], u32le(e.value));
    else throw new Error('bad calldata');
  }
  return body;
}
function encCall(c) {
  const account = cat([0x02], fromHex(c.accountKey), u64le(c.registeryIndex), fromHex(c.blsKey));
  const contract = cat(fromHex(c.contractId), u64le(c.contractRegisteryIndex));
  const calldata = encCalldata(c.calldata);
  return cat(
    [0x01],
    u32le(account.length), account,
    u32le(contract.length), contract,
    u16le(c.methodIndex),
    u32le(calldata.length), calldata,
    [0x00], u64le(c.opsPrice), u64le(c.target),
  );
}
const sighash = (c) => tag256('Cube/sighash/entry/call', encCall(c));
const sign = (secp, h) => bls.G2.hashToCurve(h, { DST: enc.encode('Cube/bls/message') }).multiply(blsScalar(secp)).toBytes();

// ---- API ----
const api = async (p, b) => (await fetch(p, b ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) } : {})).json();

// ---- identity (per tab) ----
let ME = JSON.parse(sessionStorage.getItem('cube_player') || 'null');
const saveMe = () => sessionStorage.setItem('cube_player', JSON.stringify(ME));
if (!ME) { ME = newIdentity(); saveMe(); }

async function enter(amount) {
  const st = await api('/api/state', null);
  const c = {
    accountKey: ME.accountKey, registeryIndex: ME.registeryIndex, blsKey: ME.blsKey,
    contractId: st.contract_id, contractRegisteryIndex: st.contract_registery_index,
    methodIndex: 0, calldata: [{ type: 'payable', value: amount }], opsPrice: 100, target: st.batch_height_tip + 1,
  };
  const sig = sign(fromHex(ME.secp), sighash(c));
  return api('/api/call', {
    account_key: c.accountKey, registery_index: c.registeryIndex, bls_key: c.blsKey,
    method_index: 0, calldata: c.calldata, ops_price: 100, target: c.target, bls_signature: hx(sig),
  });
}

// ---- UI ----
const $ = (id) => document.getElementById(id);
const short = (h) => (h ? h.slice(0, 6) + '…' + h.slice(-4) : '—');
function flash(msg, kind) {
  const d = document.createElement('div');
  d.className = 'logline ' + (kind || '');
  d.textContent = msg;
  $('log').prepend(d);
}
function friendly(raw) {
  raw = raw || '';
  if (/BalanceWouldGoNegative|PayableAccountBalanceDown/.test(raw)) return 'not enough balance — hit the faucet';
  if (/signature/i.test(raw)) return 'signature rejected';
  return raw.length > 100 ? raw.slice(0, 100) + '…' : raw;
}

async function refresh() {
  const st = await api('/api/state?account=' + ME.accountKey, null);
  $('jackpot').textContent = st.jackpot.toLocaleString();
  const a = st.account || {};
  $('balance').textContent = (a.balance || 0).toLocaleString();
  $('registered').textContent = a.registered ? '' : ' (hit the faucet to join)';
  if (a.registered) ME.registeryIndex = a.registery_index;
  $('participants').textContent = `${st.participants} / ${st.min_participants}`;
  $('roundpot').textContent = st.round_pot.toLocaleString();
  $('yourodds').textContent = (a.odds_pct ? a.odds_pct.toFixed(1) : '0.0') + '%';
  $('yourin').textContent = (a.your_contribution || 0).toLocaleString();
  // status
  let status, cls = '';
  if (st.participants < st.min_participants) status = `waiting for players (need ${st.min_participants})`;
  else if (st.time_left > 0) status = `drawing in ${st.time_left}s`;
  else status = 'settling…';
  if (st.final_round) { status = '🔥 FINAL ROUND — guaranteed winner!'; cls = 'final'; }
  else if (st.rollover_streak > 0) status += `  ·  ${st.rollover_streak} rollover${st.rollover_streak > 1 ? 's' : ''}`;
  $('status').textContent = status;
  $('status').className = 'status ' + cls;
  $('winner').textContent = st.last_winner ? short(st.last_winner) : '—';
  $('enterbtn').disabled = !a.registered;
}

async function doFaucet() {
  $('faucetbtn').disabled = true;
  flash('Requesting 10,000 sats from the faucet…');
  try {
    const r = await api('/api/faucet', { account_key: ME.accountKey, bls_key: ME.blsKey });
    ME.registeryIndex = r.registery_index; saveMe();
    flash(`Faucet sent 10,000. Balance: ${r.balance.toLocaleString()}.`, 'ok');
  } catch (e) { flash('Faucet error: ' + e.message, 'err'); }
  await refresh();
  $('faucetbtn').disabled = false;
}

async function doEnter() {
  const amount = Math.max(1, parseInt($('amount').value || '0', 10));
  $('enterbtn').disabled = true;
  flash(`Signing entry of ${amount.toLocaleString()} in-browser (BLS)…`);
  try {
    const r = await enter(amount);
    if (r.ok) flash(`Entered ${amount.toLocaleString()} into the jackpot!`, 'ok');
    else flash('Enter failed: ' + friendly(r.error), 'err');
  } catch (e) { flash('Enter error: ' + e.message, 'err'); }
  await refresh();
}

function newPlayer() {
  ME = newIdentity(); saveMe();
  $('me').textContent = short(ME.accountKey);
  flash('New player ' + short(ME.accountKey) + ' — hit the faucet to get sats.', 'ok');
  refresh();
}

async function main() {
  $('me').textContent = short(ME.accountKey);
  $('faucetbtn').onclick = doFaucet;
  $('enterbtn').onclick = doEnter;
  $('newbtn').onclick = newPlayer;
  flash('Welcome, ' + short(ME.accountKey) + '. Keys generated in your browser.', 'ok');
  await refresh();
  setInterval(refresh, 2000);
}
main();
