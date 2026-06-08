// Cube Lottery — browser client (v2: proportional-odds jackpot).
// Keys are generated and `enter` calls are BLS-signed entirely in the browser,
// byte-identical to the Rust engine. The engine verifies the signature and runs
// the call; rounds are closed/settled automatically by the server.

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { bech32, bech32m } from '@scure/base';
import qrcode from 'qrcode-generator';
import { attachCosign, setPendingWithdrawSpk } from './cosign_client.mjs';
import { unilateralExit } from './dispute.mjs';

const Fr = bls.fields.Fr;
const enc = new TextEncoder();

// ---- byte helpers ----
const hx = (u) => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/.{1,2}/g).map((x) => parseInt(x, 16)));
const beToBig = (u) => { let x = 0n; for (const c of u) x = (x << 8n) | BigInt(c); return x; };
const leToBig = (u) => { let x = 0n; for (let i = u.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(u[i]); return x; };
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
// The per-tab secret is derived from a BIP39 12-word phrase (16 bytes entropy):
// phrase -> seed -> first 32 bytes = secp secret. The phrase is the only backup.
function identityFromMnemonic(mnemonic) {
  const m = mnemonic.trim().toLowerCase().split(/\s+/).filter(Boolean).join(' ');
  const secp = mnemonicToSeedSync(m).slice(0, 32);
  return { mnemonic: m, secp: hx(secp), accountKey: hx(acctKey(secp)), blsKey: hx(blsPub(secp)) };
}
function newIdentity() {
  return identityFromMnemonic(entropyToMnemonic(crypto.getRandomValues(new Uint8Array(16)), wordlist));
}
function parseMnemonic(input) {
  const words = (input || '').trim().toLowerCase().split(/\s+/).filter(Boolean).join(' ');
  if (!validateMnemonic(words, wordlist)) throw new Error('not a valid 12-word seed phrase');
  return words;
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
// Withdraw authorization sighash: tag(account_key ‖ u64le(amount) ‖ utf8(address)).
// Must match the server's post_withdraw preimage byte-for-byte.
const withdrawSighash = (accountKeyHex, amount, address) =>
  tag256('Cube/sighash/arcade/withdraw', cat(fromHex(accountKeyHex), u64le(amount), enc.encode(address)));

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
if (!ME || !ME.mnemonic) { ME = newIdentity(); saveMe(); }
// "new player" opens a new tab with ?new — force a fresh identity there (a
// same-origin new tab otherwise inherits a COPY of this tab's sessionStorage),
// then strip the flag so a later refresh keeps the new player.
if (new URLSearchParams(location.search).has('new')) {
  ME = newIdentity(); saveMe();
  history.replaceState(null, '', location.pathname);
}

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
  if (/BalanceWouldGoNegative|PayableAccountBalanceDown/.test(raw)) return 'not enough balance — add funds';
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
  if (st.rollover_streak > 0) status += `  ·  ${st.rollover_streak} rollover${st.rollover_streak > 1 ? 's' : ''}`;
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
  // The free faucet + custodial on-chain cash-out are regtest-only. On signet/
  // mainnet there's no free money and no operator-funded payout, so hide both.
  const faucetEnabled = st.faucet_enabled !== false;
  const fbtn = $('faucetbtn');
  if (fbtn) fbtn.style.display = faucetEnabled ? '' : 'none';
  $('registered').textContent = a.registered
    ? ''
    : (faucetEnabled ? ' (hit the faucet to join)' : ' (add funds to play)');
  if (a.registered) { ME.registeryIndex = a.registery_index; saveMe(); }
  $('participants').textContent = `${st.participants}`;
  $('roundpot').textContent = st.round_pot.toLocaleString();
  $('yourodds').textContent = (a.odds_pct ? a.odds_pct.toFixed(1) : '0.0') + '%';
  $('yourin').textContent = (a.your_contribution || 0).toLocaleString();
  $('winner').textContent = st.last_winner ? short(st.last_winner) : '—';
  if ($('betchips')) $('betchips').classList.toggle('disabled', !a.registered);
  // optional block-explorer link (set server-side via CUBE_EXPLORER_URL)
  const exp = $('explorerlink');
  if (st.explorer_url) { exp.href = st.explorer_url; exp.style.display = ''; }
  else { exp.style.display = 'none'; }
  const lnb = $('lndepositbtn'); if (lnb) lnb.style.display = st.ln_enabled ? '' : 'none';
  const mine = ME.accountKey.toLowerCase();
  const feed = (st.recent_draws || []).map((dr) => drawRow(dr, mine)).join('');
  $('draws').innerHTML = feed || '<div class="draw empty">no draws yet</div>';
  const showall = $('showall'); if (showall) showall.style.display = (st.recent_draws || []).length ? '' : 'none';
  renderStatus();
  renderDeposit(a.deposit);
  maybeClaimDeposit(a.deposit);
  // Withdraw / force-exit / exit-kit all act on your on-chain claim. With no claim
  // (no covenant, or you're not in it) there's nothing to exit — say so plainly
  // instead of erroring after the click.
  const claim = a.onchain_claim || 0;
  const noticeEl = $('wdnotice');
  if (noticeEl) {
    if (claim > 0) { noticeEl.style.display = 'none'; }
    else {
      noticeEl.textContent = 'No on-chain funds to withdraw or exit yet. Deposit and play — once your funds are pooled in the on-chain jackpot, you can withdraw or force-exit them with your key.';
      noticeEl.style.display = '';
    }
    ['withdrawbtn', 'forceexitbtn', 'downloadkitbtn'].forEach((id) => { const b = $(id); if (b) b.disabled = claim <= 0; });
  }
}

// ---- betting: clicking a chip (5k/10k/25k/ALL IN) places that bet immediately ----
let betting = false;
// The VM keeps a small fixed per-call reserve, so you can't stake your very last
// sats (measured at ~12; we leave a safe margin). Cap every bet — including
// "ALL IN" — at balance − reserve so it never fails with "balance would go below
// zero".
const BET_RESERVE = 50;
async function doEnterBet(betSpec) {
  if (betting) return;
  const bal = (lastState && lastState.account && lastState.account.balance) || 0;
  const maxBet = Math.max(0, bal - BET_RESERVE);
  const amount = betSpec === 'all' ? maxBet : Math.min(betSpec, maxBet);
  if (amount < 1) return flash('not enough balance — add funds first', 'err');
  betting = true;
  const chips = $('betchips'); if (chips) chips.classList.add('busy');
  try {
    const r = await enter(amount);
    if (r.ok) flash(`Entered ${amount.toLocaleString()} into the jackpot!`, 'ok');
    else flash('Enter failed: ' + friendly(r.error), 'err');
  } catch (e) { flash('Enter error: ' + e.message, 'err'); }
  betting = false;
  if (chips) chips.classList.remove('busy');
}

// When a confirmed deposit hasn't been credited to the in-game balance yet,
// auto-claim it: schnorr-sign (account_key ‖ bls_key) with the account key (which
// the deposit address derives from) so the server credits only the depositor.
let claiming = false;
async function maybeClaimDeposit(d) {
  if (!d || !(d.claimable_sats > 0) || claiming || !ME.secp) return;
  claiming = true;
  try {
    const sighash = tag256('Cube/sighash/arcade/deposit-claim', cat(fromHex(ME.accountKey), fromHex(ME.blsKey)));
    const sig = hx(schnorr.sign(sighash, fromHex(ME.secp)));
    const r = await api('/api/deposit/claim', { account_key: ME.accountKey, bls_key: ME.blsKey, sig });
    if (r.ok && r.credited > 0) {
      if (r.registery_index !== undefined) { ME.registeryIndex = r.registery_index; saveMe(); }
      flash(`Deposit credited — ${Number(r.credited).toLocaleString()} sats added to your balance.`, 'ok');
    }
  } catch (e) { /* a later push will retry */ }
  claiming = false;
}

// A stable identity for the current deposit state, so a dismissal sticks until the
// deposit actually changes (a new payment) rather than reappearing on every push.
const depositKey = (d) => (d ? `${d.txid || ''}|${d.confirmed_sats || 0}|${d.pending_sats || 0}` : '');
let depositDismissKey = null;
// Hide the current deposit status (called when the player clicks a deposit button —
// the "x sat received & added" confirmation shouldn't linger into a new deposit).
function dismissDepositStatus() {
  depositDismissKey = depositKey(lastState && lastState.account && lastState.account.deposit);
  const el = $('depositstatus'); if (el) el.style.display = 'none';
}

// Live deposit-address status, pushed over the same /ws as the rest of state:
// unconfirmed (mempool) -> confirmed -> joined the pot covenant.
function renderDeposit(d) {
  const el = $('depositstatus');
  if (!el) return;
  if (d && depositKey(d) === depositDismissKey) { el.style.display = 'none'; return; }
  const sat = (n) => Number(n || 0).toLocaleString();
  const parts = [];
  if (d) {
    // Only TRANSIENT states show: incoming (unconfirmed) and the brief crediting
    // window (claimable). A fully-credited deposit shows nothing — the balance
    // already reflects it (and a toast confirmed it), so it doesn't linger or
    // reappear on refresh.
    if (d.pending_sats > 0) parts.push(`⏳ <b>${sat(d.pending_sats)}</b> sats incoming — waiting for confirmation…`);
    if (d.claimable_sats > 0) parts.push(`✅ <b>${sat(d.claimable_sats)}</b> sats received — adding to your balance…`);
  }
  if (!parts.length) { el.style.display = 'none'; return; }
  el.innerHTML = parts.join('<br>');
  el.style.display = '';
}

// Register our deposit address with the server (so it starts watching the chain
// for deposits to it) without necessarily revealing the address in the UI.
async function ensureDepositWatch() {
  if (!ME.accountKey) return;
  try { await api(`/api/deposit_address?account=${ME.accountKey}`); } catch (e) {}
}

// Show the player's deposit address (fund it to add money to play with).
// Render a QR for a string as an SVG on a white tile (scannable on the dark theme).
function qrSvg(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text.toUpperCase()); // uppercase = compact alphanumeric QR; wallets lowercase it
  qr.make();
  // fixed pixel dims (no `scalable` — that collapses to a tiny blob with no width)
  const svg = qr.createSvgTag({ cellSize: 4, margin: 2 }).replace('<svg ', '<svg style="display:block;width:100%;height:auto" ');
  return `<div style="background:#fff;padding:8px;border-radius:8px;display:inline-block;max-width:260px">${svg}</div>`;
}

// Lightning deposit: create an invoice; the server swaps it on-chain into the
// player's LiftV2 claim once paid, and the normal deposit flow credits the balance.
async function lnDeposit() {
  const amt = parseInt(($('lnamount').value || '').trim(), 10);
  if (!amt || amt < 5000) return flash('enter at least 5,000 sats', 'err');
  $('lncreatebtn').disabled = true;
  flash('Creating a Lightning invoice…');
  try {
    const r = await api('/api/ln/deposit', { account_key: ME.accountKey, amount: amt });
    if (!r.ok) { flash('Lightning deposit: ' + friendly(r.error), 'err'); $('lncreatebtn').disabled = false; return; }
    const bolt11 = r.bolt11;
    const res = $('lnresult');
    res.innerHTML = `${qrSvg(bolt11)}
      <div style="margin-top:8px;font-size:11px;color:#6b7689">pay this ${amt.toLocaleString()}-sats invoice from any Mutinynet Lightning wallet — your balance updates automatically when it arrives.</div>
      <div class="kv" style="margin-top:8px"><div class="kvv" style="text-align:left">${bolt11}</div><button class="mini" id="lncopy">copy</button></div>
      <a href="lightning:${bolt11}" class="rlink" style="font-size:12px;color:#6b8cff">open in wallet →</a>`;
    res.style.display = '';
    $('lncopy').onclick = () => copyText(bolt11);
    flash('Invoice ready — pay it to deposit.', 'ok');
  } catch (e) { flash('Lightning error: ' + e.message, 'err'); }
  $('lncreatebtn').disabled = false;
}

async function showDepositAddress() {
  const el = $('depositaddr');
  if (!el) return;
  try {
    const d = await api(`/api/deposit_address?account=${ME.accountKey}`);
    if (d.address) {
      el.innerHTML = `Send BTC to this address to add funds:<br><code>${d.address}</code>`;
      el.style.display = '';
    } else { el.textContent = d.error || 'unavailable'; el.style.display = ''; }
  } catch (e) { el.textContent = 'error: ' + e.message; el.style.display = ''; }
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

// ---- cosign WebSocket (non-custodial covenant participation) ----
// The tab holds a second socket on /cosign and auto-co-signs covenant refreshes,
// lift-ins, and unrolls with ITS OWN key — verifying every tx before signing
// (musig.mjs/covenant.mjs/sighash.mjs). The server never sees the key.
let cosignWs = null;
let cosignDetach = null;
function connectCosign() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  cosignWs = new WebSocket(`${proto}://${location.host}/cosign`);
  cosignWs.addEventListener('open', () => {
    cosignDetach = attachCosign(cosignWs, ME.secp, ME.accountKey, (kind, detail) => {
      if (kind === 'nonce') flash('🔑 co-signing the pot covenant…');
      else if (kind === 'complete') flash('✅ covenant co-signed', 'ok');
      else if (kind === 'reject') flash('🛑 refused to sign (verification failed): ' + (detail.errors || []).join('; '), 'err');
    });
  });
  cosignWs.addEventListener('close', () => { if (cosignDetach) { cosignDetach(); cosignDetach = null; } setTimeout(connectCosign, 1500); });
  cosignWs.addEventListener('error', () => { try { cosignWs.close(); } catch (e) {} });
}
function switchCosign() {
  if (cosignWs) { try { cosignWs.onclose = null; cosignWs.close(); } catch (e) {} }
  if (cosignDetach) { cosignDetach(); cosignDetach = null; }
  connectCosign();
}

// Switch the live connection to the current ME right away. Used after
// restore/new-player so the balance updates instantly instead of waiting for
// the 1.5s auto-reconnect (and we don't double-connect via the old onclose).
function switchAccount() {
  if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} }
  connectWS();
  switchCosign();
  ensureDepositWatch();
  // Belt-and-suspenders: also pull state over HTTP in case the socket is slow.
  api(`/api/state?account=${ME.accountKey}`).then(render).catch(() => {});
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

// Decode a bech32/bech32m address to its scriptPubKey hex (so we can verify the
// withdraw payout goes to exactly this address before our key co-signs it).
function addressToSpk(addr) {
  let words;
  try { words = bech32m.decode(addr, 1023).words; }
  catch { words = bech32.decode(addr, 1023).words; }
  const ver = words[0];
  const prog = bech32.fromWords(words.slice(1));
  const op = ver === 0 ? 0x00 : (0x50 + ver);
  return hx(Uint8Array.from([op, prog.length, ...prog]));
}

// Withdraw your whole (not-in-play) balance to a Bitcoin address — NON-CUSTODIAL:
// a cooperative covenant refresh pays you out from your own on-chain claim. We tell
// the cosign client the exact destination spk so our key won't sign a redirected payout.
async function doWithdraw() {
  const address = ($('wdaddr').value || '').trim();
  const amount = (lastState && lastState.account && lastState.account.balance) || 0;
  if (!address) return flash('enter a destination address', 'err');
  if (amount < 1) return flash('nothing to withdraw', 'err');
  let spk;
  try { spk = addressToSpk(address); } catch (e) { return flash('invalid Bitcoin address', 'err'); }
  $('withdrawbtn').disabled = true;
  flash(`Withdrawing to ${address.slice(0, 16)}… (co-signing your exit)`);
  setPendingWithdrawSpk(spk);
  try {
    const sig = sign(fromHex(ME.secp), withdrawSighash(ME.accountKey, amount, address));
    const r = await api('/api/withdraw', {
      account_key: ME.accountKey, bls_key: ME.blsKey, address, amount, bls_signature: hx(sig),
    });
    if (r.ok) { flash(`Withdrew ${Number(r.withdrawn || amount).toLocaleString()} sats to your address! tx ${short(r.txid)}`, 'ok'); $('wdaddr').value = ''; $('withdrawbox').style.display = 'none'; }
    else flash('Withdraw failed: ' + friendly(r.error), 'err');
  } catch (e) { flash('Withdraw error: ' + e.message, 'err'); }
  setPendingWithdrawSpk(null);
  $('withdrawbtn').disabled = false;
}

// UNILATERAL escape hatch: broadcast your pre-signed unroll and sweep your own VTXO
// leaf with only your key — works with no other players (and, once cached, even if
// the operator vanishes). Disincentivized by the CSV wait + self-paid fees.
async function doForceExit() {
  const address = ($('wdaddr').value || '').trim();
  if (!address) return flash('enter a destination address', 'err');
  let destSpk;
  try { destSpk = addressToSpk(address); } catch (e) { return flash('invalid Bitcoin address', 'err'); }
  $('forceexitbtn').disabled = true;
  try {
    // fetch the exit kit (and cache it for an operator-gone future); fall back to cache.
    let kit = null;
    try { kit = await api(`/api/exit_kit?account=${ME.accountKey}`); if (kit && kit.ok) localStorage.setItem('exitkit:' + ME.accountKey, JSON.stringify(kit)); } catch (e) {}
    if (!kit || !kit.ok) { const c = localStorage.getItem('exitkit:' + ME.accountKey); if (c) kit = JSON.parse(c); }
    if (!kit || !kit.ok || !kit.leaf) return flash((kit && kit.error) || 'no exit kit available yet', 'err');
    const mp = (kit.mempool_api || '').replace(/\/$/, ''); // public broadcaster, if any
    // Broadcast: prefer the operator's node; if it's gone, push straight to the
    // public mempool API (esplora /tx accepts a raw-hex body, returns the txid).
    const broadcast = async (hex) => {
      try { const r = await api('/api/broadcast', { tx_hex: hex }); if (r && r.ok) return r.txid; if (r && r.error) throw new Error(r.error); } catch (e) {}
      if (!mp) throw new Error('operator broadcast failed and no public broadcaster for this network');
      const res = await fetch(mp + '/tx', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: hex });
      const txt = (await res.text()).trim();
      if (!res.ok || !/^[0-9a-f]{64}$/i.test(txt)) throw new Error('public broadcast rejected: ' + txt.slice(0, 200));
      return txt;
    };
    // Confirmation depth of utxid: try the operator first, else esplora
    // (confirmations = tip_height - block_height + 1).
    const confirmations = async (utxid) => {
      try { const st = await api(`/api/txstatus?txid=${utxid}&vout=${kit.leaf.vout}`); if (typeof st.confirmations === 'number') return st.confirmations; } catch (e) {}
      if (!mp) return 0;
      try {
        const st = await (await fetch(`${mp}/tx/${utxid}/status`)).json();
        if (!st || !st.confirmed) return 0;
        const tip = parseInt(await (await fetch(`${mp}/blocks/tip/height`)).text(), 10);
        return Number.isFinite(tip) && st.block_height ? tip - st.block_height + 1 : 1;
      } catch (e) { return 0; }
    };
    flash('Force exit: broadcasting your unroll, waiting for the CSV delay…');
    const afterUnroll = async (utxid) => {
      for (let i = 0; i < 240; i++) {
        await new Promise((r) => setTimeout(r, 4000));
        if (await confirmations(utxid) >= kit.leaf.exit_delay) return;
      }
    };
    let fee = 600;
    try { const fr = await api('/api/feerate'); if (fr && fr.exit_sweep_fee > 0) fee = fr.exit_sweep_fee; } catch (e) {}
    const res = await unilateralExit({ unrollTxHex: kit.unroll_tx_hex, unrollTxid: kit.unroll_txid, leaf: kit.leaf, secpHex: ME.secp, destSpk, broadcast, afterUnroll, fee });
    // best-effort: tidy the operator's ledger (no-op / irrelevant if it's gone).
    try { const sig = hx(sign(fromHex(ME.secp), tag256('Cube/sighash/arcade/exit-done', fromHex(ME.accountKey)))); await api('/api/exit_done', { account_key: ME.accountKey, bls_key: ME.blsKey, bls_signature: sig }); } catch (e) {}
    flash(`Force-exited ${Number(res.outValue).toLocaleString()} sats to your address! sweep ${short(res.sweepTxid)}`, 'ok');
    $('wdaddr').value = ''; $('withdrawbox').style.display = 'none';
  } catch (e) { flash('Force exit error: ' + e.message, 'err'); }
  $('forceexitbtn').disabled = false;
}

// Download a self-contained HTML escape hatch: bakes in the current exit kit + this
// tab's base secret + the bundled exit tool, so the player can force-exit later from
// their local disk with NO server, NO DNS, NO operator. The file holds a secret key —
// treat it like a wallet backup.
async function downloadExitKit() {
  try {
    let kit = null;
    try { kit = await api(`/api/exit_kit?account=${ME.accountKey}`); if (kit && kit.ok) localStorage.setItem('exitkit:' + ME.accountKey, JSON.stringify(kit)); } catch (e) {}
    if (!kit || !kit.ok) { const c = localStorage.getItem('exitkit:' + ME.accountKey); if (c) kit = JSON.parse(c); }
    if (!kit || !kit.ok || !kit.leaf) return flash((kit && kit.error) || 'no exit kit available to download yet', 'err');
    if (!kit.mempool_api) return flash('this network has no public broadcaster — the offline tool needs one', 'err');
    if (!confirm('This file contains your SECRET KEY in plain text — anyone who opens it can move your exited funds. Save it somewhere private (like a password manager or encrypted drive). Download it?')) return;
    const tool = await (await fetch('/exit-tool.bundle.js', { headers: { 'ngrok-skip-browser-warning': 'true' } })).text();
    const payload = JSON.stringify({ kit, secp: ME.secp });
    const html = exitToolHtml(payload, tool, ME.accountKey);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `cube-exit-${ME.accountKey.slice(0, 8)}.html`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    flash('Exit kit downloaded — keep it private. It can recover your funds even if this site disappears.', 'ok');
  } catch (e) { flash('Download error: ' + e.message, 'err'); }
}

// Assemble the standalone HTML around the injected payload + bundled tool.
function exitToolHtml(payloadJson, toolJs, account) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cube — Force Exit (${account.slice(0, 8)})</title>
<style>
  body { margin:0; background:#0b0e14; color:#d7dce5; font-family:ui-monospace,Menlo,monospace; display:flex; justify-content:center; }
  .wrap { width:100%; max-width:560px; padding:28px 20px 60px; }
  h1 { color:#fff; font-size:20px; } .sub { color:#6b7689; font-size:12px; margin-bottom:16px; line-height:1.5; }
  .warn { color:#f3b6ae; background:#2a1518; border:1px solid #5a2a2a; border-radius:8px; padding:10px 12px; font-size:12px; margin-bottom:16px; line-height:1.5; }
  input { width:100%; background:#0f141d; border:1px solid #2b3545; border-radius:10px; color:#fff; font-family:inherit; font-size:15px; padding:12px 14px; box-sizing:border-box; }
  button { margin-top:12px; width:100%; padding:13px; font-size:15px; font-weight:600; border:0; border-radius:10px; cursor:pointer; background:#ffd75e; color:#1a1300; font-family:inherit; }
  button:disabled { opacity:.4; cursor:not-allowed; }
  #summary { color:#8a94a6; font-size:12px; margin:14px 0 8px; line-height:1.5; }
  #log { margin-top:16px; font-size:12px; }
  .line { padding:6px 10px; border-left:2px solid #2b3545; margin-bottom:4px; color:#9aa4b5; background:#0f141d; border-radius:0 6px 6px 0; word-break:break-all; }
  .line.ok { border-color:#5ee08a; color:#bfe9cd; } .line.err { border-color:#f6614f; color:#f3b6ae; }
</style></head><body><div class="wrap">
<h1>🎲 Cube — Force Exit</h1>
<div class="sub">Standalone, offline escape hatch for account <b>${account.slice(0, 8)}…</b>. It broadcasts your pre-signed unroll, waits out the CSV delay, then sweeps your VTXO leaf to your address — with your key alone, no operator needed.</div>
<div class="warn">⚠️ This file contains your secret key. Anyone who opens it controls your exit. Keep it private.</div>
<div id="summary">loading…</div>
<input id="addr" placeholder="your Bitcoin address (tb1…)" autocomplete="off" autocapitalize="off" spellcheck="false" />
<button id="go">Broadcast &amp; exit</button>
<div id="log"></div>
</div>
<script>window.CUBE_EXIT = ${payloadJson};</script>
<script>${toolJs}</script>
</body></html>`;
}

// ---- round details (provably-fair page, hash-routed: #round/<n>) ----
function bandRow(label, lo, hi, space, cls, note) {
  const pct = space > 0 ? Math.max(0.5, ((hi - lo) * 100) / space) : 0;
  return `<div class="seg ${cls || ''}">
    <div class="segbar" style="width:${pct.toFixed(2)}%"></div>
    <div class="seginfo"><span>${label}</span><span class="segrange">[${lo.toLocaleString()}, ${hi.toLocaleString()})${note ? ' · ' + note : ''}</span></div>
  </div>`;
}
function renderRound(d) {
  if (d.error) return `<div class="card"><a class="back" href="#">← back</a><p>${d.error}</p></div>`;
  const mine = ME.accountKey.toLowerCase();
  // Client-side recompute of the draw from the public seed (LE, as the VM reads it).
  let recomputed = null, ok = false;
  try {
    const r = leToBig(fromHex(d.seed_hex)) % BigInt(d.space);
    recomputed = r.toString();
    ok = Number(r) === d.r;
  } catch (e) {}
  const odds = d.space > 0 ? (d.round_total * 100) / d.space : 0;
  const rakePct = d.rake_percent != null ? d.rake_percent : 1;
  const rake = Math.floor((d.amount || 0) * rakePct / 100);
  const winnerAmt = (d.amount || 0) - rake;
  const winnerName = (d.winner || '').toLowerCase() === mine ? 'You' : short(d.winner);
  const outcome = d.rollover
    ? `🎲 <b>No winner</b> — the draw missed every entry, so the entire ${Number(d.amount).toLocaleString()}-sats jackpot rolled into the next round.`
    : `🏆 <b>${winnerName}</b> won the round. The ${Number(d.amount).toLocaleString()}-sats pot paid out <b>${Number(winnerAmt).toLocaleString()}</b> to the winner and a ${rakePct}% operator rake of <b>${Number(rake).toLocaleString()}</b>.`;
  return `<div class="card round">
    <a class="back" href="#">← back to the jackpot</a>
    <h2>Round ${d.round}</h2>
    <p class="rsum">${outcome}</p>
    <div class="feedtitle">how the winner was chosen — provably fair</div>
    <p class="rexp">Every entry claims a slice of the number line sized to its contribution. At close, the contract
    snapshots a <b>Bitcoin block hash</b> as the random seed — nobody (not even the operator) can predict or
    pick it. The draw is <code>r = seed mod space</code>; whichever slice contains <code>r</code> wins the pot
    (minus a ${rakePct}% operator rake). A large <b>house zone</b> past the entries makes the per-round win
    chance about <b>${odds.toFixed(2)}%</b>, so most rounds miss and roll the pot forward into a bigger
    jackpot. You can recompute it all yourself from the values below.</p>
    <div class="kv"><span class="kvk">seed</span><code class="kvv">${d.seed_hex}</code></div>
    <div class="rmath">
      <div>round contributions = <b>${Number(d.round_total).toLocaleString()}</b></div>
      <div>house zone = <b>${Number(d.house).toLocaleString()}</b></div>
      <div>space = contributions + house = <b>${Number(d.space).toLocaleString()}</b> → win chance <b>${odds.toFixed(2)}%</b></div>
      <div>draw <code>r = seed mod space</code> = <b>${Number(d.r).toLocaleString()}</b>
        ${recomputed !== null ? `<span class="${ok ? 'okv' : 'errv'}">${ok ? '✓ recomputed in your browser' : '✗ recompute=' + recomputed}</span>` : ''}</div>
    </div>
  </div>`;
}
// One draw-feed row (shared by the home feed and the full-history page).
function drawRow(dr, mine) {
  const rlink = `<a class="rlink" href="#round/${dr.round}">round ${dr.round}</a>`;
  if (dr.kind === 'rollover')
    return `<div class="draw roll">${rlink} · 🎲 no winner — ${Number(dr.amount).toLocaleString()} rolled over</div>`;
  const won = (dr.winner || '').toLowerCase() === mine;
  return `<div class="draw ${won ? 'mywin' : 'win'}">${rlink} · 🏆 ${won ? 'YOU' : short(dr.winner)} won ${Number(dr.amount).toLocaleString()}</div>`;
}

// Full jackpot history page (#history): every persisted round, newest first.
async function showHistory() {
  if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} ws = null; } // pause home updates
  $('home').style.display = 'none';
  const help = $('help'); if (help) help.style.display = 'none';
  const el = $('round'); el.style.display = '';
  el.innerHTML = `<div class="card">loading jackpot history…</div>`;
  try {
    const h = await api('/api/history');
    const mine = ME.accountKey.toLowerCase();
    const rows = (h.draws || []).map((dr) => drawRow(dr, mine)).join('');
    el.innerHTML = `<div class="card"><a class="back" href="#">← back</a>
      <div class="feedtitle" style="margin-top:8px">all draws (${h.count || 0})</div>
      ${rows || '<div class="draw empty">no draws yet</div>'}</div>`;
    window.scrollTo(0, 0);
  } catch (e) {
    el.innerHTML = `<div class="card"><a class="back" href="#">← back</a><p>failed to load history</p></div>`;
  }
}

async function showRound(n) {
  if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} ws = null; } // pause home updates
  $('home').style.display = 'none';
  const help = $('help'); if (help) help.style.display = 'none';
  const el = $('round'); el.style.display = '';
  el.innerHTML = `<div class="card">loading round ${n}…</div>`;
  try { el.innerHTML = renderRound(await api('/api/round/' + n)); }
  catch (e) { el.innerHTML = `<div class="card"><a class="back" href="#">← back</a><p>failed to load round ${n}</p></div>`; }
}
function showHelp() {
  if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} ws = null; }
  $('home').style.display = 'none';
  $('round').style.display = 'none';
  const help = $('help'); if (help) { help.style.display = ''; window.scrollTo(0, 0); }
}
function showHome() {
  $('round').style.display = 'none';
  const help = $('help'); if (help) help.style.display = 'none';
  $('home').style.display = '';
  if (!ws) connectWS(); // resume push updates
}
function route() {
  const m = (location.hash || '').match(/^#round\/(\d+)/);
  if (m) showRound(parseInt(m[1], 10));
  else if ((location.hash || '') === '#help') showHelp();
  else if ((location.hash || '') === '#history') showHistory();
  else showHome();
}

function hideBackup() {
  $('backupbox').style.display = 'none';
  $('exportbtn').textContent = 'show backup';
}

function newPlayer() {
  // Open a fresh player in a NEW tab instead of wiping this tab's keys.
  window.open(location.pathname + '?new', '_blank');
  flash('Opened a new player in a new tab.', 'ok');
}

function toggleExport() {
  if ($('backupbox').style.display === 'none') {
    $('phraseout').textContent = ME.mnemonic;
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
    ME = identityFromMnemonic(parseMnemonic(v)); saveMe();
    $('me').textContent = short(ME.accountKey);
    $('restoreinput').value = '';
    hideBackup();
    flash('Restored player ' + short(ME.accountKey) + ' — loading balance…', 'ok');
    switchAccount();
  } catch (e) { flash('Restore failed: ' + e.message, 'err'); }
}

async function copyText(t) {
  try { await navigator.clipboard.writeText(t); flash('copied to clipboard', 'ok'); }
  catch (e) { flash('copy failed — select the text and copy manually', 'err'); }
}

// Install the service worker that keeps an offline copy of the app shell, so the
// unilateral "Force exit" remains reachable even if the operator's server is gone.
function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}

function main() {
  $('me').textContent = short(ME.accountKey);
  $('faucetbtn').onclick = doFaucet;
  $('newbtn').onclick = newPlayer;
  $('exportbtn').onclick = toggleExport;
  $('restorebtn').onclick = doRestore;
  $('withdrawbtn').onclick = doWithdraw;
  const dbtn = $('depositbtn'); if (dbtn) dbtn.onclick = () => {
    dismissDepositStatus();
    const s = $('fundsub'); s.style.display = s.style.display === 'none' ? '' : 'none';
  };
  const btcbtn = $('btcdepositbtn'); if (btcbtn) btcbtn.onclick = () => {
    dismissDepositStatus();
    const ln = $('lnbox'); if (ln) ln.style.display = 'none'; // Bitcoin & Lightning are mutually exclusive
    showDepositAddress();
  };
  const lnbtn = $('lndepositbtn'); if (lnbtn) lnbtn.onclick = () => {
    dismissDepositStatus();
    const da = $('depositaddr'); if (da) da.style.display = 'none';
    const box = $('lnbox'); box.style.display = box.style.display === 'none' ? '' : 'none';
  };
  const lncbtn = $('lncreatebtn'); if (lncbtn) lncbtn.onclick = lnDeposit;
  const wbtn = $('withdrawbtn2'); if (wbtn) wbtn.onclick = () => {
    const box = $('withdrawbox'); box.style.display = box.style.display === 'none' ? '' : 'none';
  };
  const febtn = $('forceexitbtn'); if (febtn) febtn.onclick = doForceExit;
  const dkbtn = $('downloadkitbtn'); if (dkbtn) dkbtn.onclick = downloadExitKit;
  document.querySelectorAll('#betchips .chip').forEach((c) => {
    c.onclick = () => doEnterBet(c.dataset.bet === 'all' ? 'all' : parseInt(c.dataset.bet, 10));
  });
  $('copyphrase').onclick = () => copyText($('phraseout').textContent);
  flash('Welcome, ' + short(ME.accountKey) + '. Keys generated in your browser — back them up to restore later.', 'ok');
  window.addEventListener('hashchange', route);
  route(); // connects the WS on the home view, or shows a round-details page
  connectCosign(); // participate in non-custodial covenant cosign for this tab
  ensureDepositWatch(); // start server-side watching of our deposit address
  registerServiceWorker(); // cache the app shell so the escape hatch survives the operator
  setInterval(() => { if (displayTimeLeft > 0 && lastState && lastState.participants >= lastState.min_participants) displayTimeLeft--; renderStatus(); }, 1000);
}
main();
