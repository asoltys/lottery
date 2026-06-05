// Cube Lottery — browser client (v2: proportional-odds jackpot).
// Keys are generated and `enter` calls are BLS-signed entirely in the browser,
// byte-identical to the Rust engine. The engine verifies the signature and runs
// the call; rounds are closed/settled automatically by the server.

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bech32 } from '@scure/base';
import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

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
function identityFromSecp(secpHex) {
  const secp = fromHex(secpHex);
  return { secp: secpHex, accountKey: hx(acctKey(secp)), blsKey: hx(blsPub(secp)) };
}
function newIdentity() {
  return identityFromSecp(hx(crypto.getRandomValues(new Uint8Array(32))));
}
// Backup formats for the per-tab secret key.
const toNsec = (secpHex) => bech32.encode('nsec', bech32.toWords(fromHex(secpHex)));
const toPhrase = (secpHex) => entropyToMnemonic(fromHex(secpHex), wordlist);
function parseKey(input) {
  const t = (input || '').trim();
  if (t.toLowerCase().startsWith('nsec1')) {
    const { prefix, words } = bech32.decode(t.toLowerCase());
    if (prefix !== 'nsec') throw new Error('not an nsec');
    const bytes = Uint8Array.from(bech32.fromWords(words));
    if (bytes.length !== 32) throw new Error('bad nsec length');
    return hx(bytes);
  }
  const words = t.toLowerCase().split(/\s+/).filter(Boolean).join(' ');
  if (!validateMnemonic(words, wordlist)) throw new Error('not a valid nsec or 24-word seed phrase');
  return hx(mnemonicToEntropy(words, wordlist));
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
const api = async (p, b) => {
  const headers = { 'ngrok-skip-browser-warning': 'true' }; // harmless off-ngrok
  const opt = b
    ? { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify(b) }
    : { headers };
  return (await fetch(p, opt)).json();
};

// ---- identity (per tab) ----
let ME = JSON.parse(sessionStorage.getItem('cube_player') || 'null');
const saveMe = () => sessionStorage.setItem('cube_player', JSON.stringify(ME));
if (!ME) { ME = newIdentity(); saveMe(); }

// Uses the latest pushed state (no polling).
async function enter(amount) {
  const st = lastState;
  if (!st) throw new Error('not connected yet');
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

let lastState = null;
let displayTimeLeft = 0;

// Status line is re-derived every second from the cached state + a local
// countdown, so the timer ticks smoothly without any network traffic.
function renderStatus() {
  const st = lastState;
  if (!st) return;
  let status, cls = '';
  if (st.participants < st.min_participants) status = 'waiting for the first entry';
  else if (displayTimeLeft > 0) status = `drawing in ${displayTimeLeft}s`;
  else status = 'settling…';
  if (st.final_round) { status = '🔥 FINAL ROUND — guaranteed winner!'; cls = 'final'; }
  else if (st.rollover_streak > 0) status += `  ·  ${st.rollover_streak} rollover${st.rollover_streak > 1 ? 's' : ''}`;
  $('status').textContent = status;
  $('status').className = 'status ' + cls;
}

// Full render on each pushed state.
function render(st) {
  lastState = st;
  displayTimeLeft = st.time_left;
  $('jackpot').textContent = st.jackpot.toLocaleString();
  const a = st.account || {};
  $('balance').textContent = (a.balance || 0).toLocaleString();
  $('registered').textContent = a.registered ? '' : ' (hit the faucet to join)';
  if (a.registered) { ME.registeryIndex = a.registery_index; saveMe(); }
  $('participants').textContent = `${st.participants}`;
  $('roundpot').textContent = st.round_pot.toLocaleString();
  $('yourodds').textContent = (a.odds_pct ? a.odds_pct.toFixed(1) : '0.0') + '%';
  $('yourin').textContent = (a.your_contribution || 0).toLocaleString();
  $('winner').textContent = st.last_winner ? short(st.last_winner) : '—';
  $('enterbtn').disabled = !a.registered;
  // optional block-explorer link (set server-side via CUBE_EXPLORER_URL)
  const exp = $('explorerlink');
  if (st.explorer_url) { exp.href = st.explorer_url; exp.style.display = ''; }
  else { exp.style.display = 'none'; }
  const mine = ME.accountKey.toLowerCase();
  const feed = (st.recent_draws || []).map((dr) => {
    if (dr.kind === 'rollover')
      return `<div class="draw roll">round ${dr.round} · 🎲 no winner — ${Number(dr.amount).toLocaleString()} rolled over</div>`;
    const won = (dr.winner || '').toLowerCase() === mine;
    return `<div class="draw ${won ? 'mywin' : 'win'}">round ${dr.round} · 🏆 ${won ? 'YOU' : short(dr.winner)} won ${Number(dr.amount).toLocaleString()}</div>`;
  }).join('');
  $('draws').innerHTML = feed || '<div class="draw empty">no draws yet</div>';
  renderStatus();
}

// ---- WebSocket (push) ----
let ws = null;
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws?account=${ME.accountKey}`);
  ws.onmessage = (ev) => { try { render(JSON.parse(ev.data)); } catch (e) {} };
  ws.onclose = () => { setTimeout(connectWS, 1500); };
  ws.onerror = () => { try { ws.close(); } catch (e) {} };
}

async function doFaucet() {
  $('faucetbtn').disabled = true;
  flash('Requesting 10,000 sats from the faucet…');
  try {
    const r = await api('/api/faucet', { account_key: ME.accountKey, bls_key: ME.blsKey });
    ME.registeryIndex = r.registery_index; saveMe();
    flash(`Faucet sent 10,000. Balance: ${r.balance.toLocaleString()}.`, 'ok');
  } catch (e) { flash('Faucet error: ' + e.message, 'err'); }
  $('faucetbtn').disabled = false; // state update arrives via WS push
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
}

function hideBackup() {
  $('backupbox').style.display = 'none';
  $('exportbtn').textContent = 'show backup';
}

function newPlayer() {
  ME = newIdentity(); saveMe();
  $('me').textContent = short(ME.accountKey);
  hideBackup();
  flash('New player ' + short(ME.accountKey) + ' — hit the faucet to get sats.', 'ok');
  try { if (ws) ws.close(); } catch (e) {} // reconnect with the new account
}

function toggleExport() {
  if ($('backupbox').style.display === 'none') {
    $('nsecout').textContent = toNsec(ME.secp);
    $('phraseout').textContent = toPhrase(ME.secp);
    $('backupbox').style.display = '';
    $('exportbtn').textContent = 'hide backup';
  } else {
    hideBackup();
  }
}

function doRestore() {
  const v = $('restoreinput').value;
  if (!v.trim()) return;
  try {
    ME = identityFromSecp(parseKey(v)); saveMe();
    $('me').textContent = short(ME.accountKey);
    $('restoreinput').value = '';
    hideBackup();
    flash('Restored player ' + short(ME.accountKey) + '.', 'ok');
    try { if (ws) ws.close(); } catch (e) {} // reconnect with restored account
  } catch (e) { flash('Restore failed: ' + e.message, 'err'); }
}

async function copyText(t) {
  try { await navigator.clipboard.writeText(t); flash('copied to clipboard', 'ok'); }
  catch (e) { flash('copy failed — select the text and copy manually', 'err'); }
}

function main() {
  $('me').textContent = short(ME.accountKey);
  $('faucetbtn').onclick = doFaucet;
  $('enterbtn').onclick = doEnter;
  $('newbtn').onclick = newPlayer;
  $('exportbtn').onclick = toggleExport;
  $('restorebtn').onclick = doRestore;
  $('copynsec').onclick = () => copyText($('nsecout').textContent);
  $('copyphrase').onclick = () => copyText($('phraseout').textContent);
  flash('Welcome, ' + short(ME.accountKey) + '. Keys generated in your browser — back them up to restore later.', 'ok');
  connectWS();
  setInterval(() => { if (displayTimeLeft > 0 && lastState && lastState.participants >= lastState.min_participants) displayTimeLeft--; renderStatus(); }, 1000);
}
main();
