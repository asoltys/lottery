// Cube Lottery — browser client (v2: proportional-odds jackpot).
// Keys are generated and `enter` calls are BLS-signed entirely in the browser,
// byte-identical to the Rust engine. The engine verifies the signature and runs
// the call; rounds are closed/settled automatically by the server.

import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { attachCosign } from './cosign_client.mjs';

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
  const cashout = $('cashoutcard');
  if (cashout) cashout.style.display = faucetEnabled ? '' : 'none';
  $('registered').textContent = a.registered
    ? ''
    : (faucetEnabled ? ' (hit the faucet to join)' : ' (deposit to play)');
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
  const rlink = (n) => `<a class="rlink" href="#round/${n}">round ${n}</a>`;
  const feed = (st.recent_draws || []).map((dr) => {
    if (dr.kind === 'rollover')
      return `<div class="draw roll">${rlink(dr.round)} · 🎲 no winner — ${Number(dr.amount).toLocaleString()} rolled over</div>`;
    const won = (dr.winner || '').toLowerCase() === mine;
    return `<div class="draw ${won ? 'mywin' : 'win'}">${rlink(dr.round)} · 🏆 ${won ? 'YOU' : short(dr.winner)} won ${Number(dr.amount).toLocaleString()}</div>`;
  }).join('');
  $('draws').innerHTML = feed || '<div class="draw empty">no draws yet</div>';
  renderStatus();
  refreshExitProof();
  refreshCovenant();
}

// Show the player's LiftV2 deposit address (fund it to put real BTC into the pot).
async function showDepositAddress() {
  const el = $('depositaddr');
  if (!el) return;
  try {
    const d = await api(`/api/deposit_address?account=${ME.accountKey}`);
    if (d.address) {
      el.innerHTML = `send BTC here to join the pot (2-of-2 with the engine, CSV-refundable):<br><code>${d.address}</code>`;
      el.style.display = '';
    } else { el.textContent = d.error || 'unavailable'; el.style.display = ''; }
  } catch (e) { el.textContent = 'error: ' + e.message; el.style.display = ''; }
}

// Reflect the on-chain pot covenant + the tab's exitable claim in it.
async function refreshCovenant() {
  const el = $('covenantstatus');
  if (!el) return;
  try {
    const c = await api('/api/covenant');
    if (c.covenant) {
      const mine = (c.covenant.allocations || []).find((a) => (a[0] || '').toLowerCase() === ME.accountKey.toLowerCase());
      el.innerHTML = `pot covenant <b>${Number(c.covenant.value).toLocaleString()}</b> sat across <b>${(c.covenant.allocations || []).length}</b> players` +
        (mine ? ` · your claim <b>${Number(mine[1]).toLocaleString()}</b> sat (exitable${c.unroll_present ? ', unroll pre-signed' : ''})` : ' · you have no claim yet') +
        ` · ${c.cosign_connected} online to co-sign`;
    } else {
      el.textContent = 'no on-chain covenant yet — deposit and the engine forms one';
    }
  } catch (e) {}
}

// Non-custodial proof: show the player that their live stake is a unilaterally
// exitable VTXO (rendered by the engine from the contract's shadow claims).
async function refreshExitProof() {
  const el = $('exitproof');
  if (!el || !ME.accountKey) return;
  try {
    const x = await api(`/api/exit?account=${ME.accountKey}`);
    if (x.exitable) {
      el.innerHTML =
        `🔓 <b>Non-custodial</b> — your <b>${Number(x.value_sats).toLocaleString()}</b> sat stake is a ` +
        `Projector value-bound VTXO you can sweep to Bitcoin with <b>only your key</b> ` +
        `(CSV ${x.exit_delay_blocks} blocks); the operator can't hold it.` +
        `<details><summary>exit proof</summary>` +
        `<code>vtxo spk: ${x.vtxo_scriptpubkey}</code>` +
        `<code>exit script: ${x.exit_script}</code>` +
        `<code>control block: ${x.exit_control_block}</code></details>`;
    } else {
      el.innerHTML =
        `🔓 <b>Non-custodial</b> — no live stake this round. Winnings are paid to your ` +
        `exitable account balance; stake in a round and it becomes an exitable VTXO claim.`;
    }
    el.style.display = '';
  } catch (e) {}
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

async function doEnter() {
  const amount = Math.max(1, parseInt($('amount').value || '0', 10));
  $('enterbtn').disabled = true;
  try {
    const r = await enter(amount);
    if (r.ok) flash(`Entered ${amount.toLocaleString()} into the jackpot!`, 'ok');
    else flash('Enter failed: ' + friendly(r.error), 'err');
  } catch (e) { flash('Enter error: ' + e.message, 'err'); }
}

async function doWithdraw() {
  const address = ($('wdaddr').value || '').trim();
  const amount = Math.max(0, parseInt($('wdamount').value || '0', 10));
  if (!address) return flash('enter a destination address', 'err');
  if (!amount) return flash('enter an amount', 'err');
  $('withdrawbtn').disabled = true;
  flash(`Withdrawing ${amount.toLocaleString()} to ${address.slice(0, 14)}…`);
  try {
    const sig = sign(fromHex(ME.secp), withdrawSighash(ME.accountKey, amount, address));
    const r = await api('/api/withdraw', {
      account_key: ME.accountKey, bls_key: ME.blsKey, address, amount, bls_signature: hx(sig),
    });
    if (r.ok) { flash(`Withdrew ${amount.toLocaleString()}! tx ${short(r.txid)}`, 'ok'); $('wdamount').value = ''; }
    else flash('Withdraw failed: ' + friendly(r.error), 'err');
  } catch (e) { flash('Withdraw error: ' + e.message, 'err'); }
  $('withdrawbtn').disabled = false;
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
  const segs = (d.segments || []).map((s) => {
    const isMe = (s.key || '').toLowerCase() === mine;
    const who = isMe ? 'YOU' : short(s.key);
    const note = s.winner ? '🏆 winner' : '';
    return bandRow(`${who} · ${Number(s.contribution).toLocaleString()}`, s.lower, s.upper, d.space, (s.winner ? 'win' : '') + (isMe ? ' me' : ''), note);
  }).join('');
  const houseRow = d.house > 0
    ? bandRow('house / rollover zone', d.round_total, d.space, d.space, 'house', d.rollover ? '🎲 landed here → rollover' : 'no winner if r lands here')
    : '';
  const odds = d.space > 0 ? (d.round_total * 100) / d.space : 0;
  const rakePct = d.rake_percent != null ? d.rake_percent : 1;
  const rake = Math.floor((d.amount || 0) * rakePct / 100);
  const winnerAmt = (d.amount || 0) - rake;
  const winnerName = (d.winner || '').toLowerCase() === mine ? 'You' : short(d.winner);
  const outcome = d.rollover
    ? `🎲 <b>No winner</b> — the draw missed every entry, so the entire ${Number(d.amount).toLocaleString()}-sat jackpot rolled into the next round.`
    : `🏆 <b>${winnerName}</b> won the round. The ${Number(d.amount).toLocaleString()}-sat pot paid out <b>${Number(winnerAmt).toLocaleString()}</b> to the winner and a ${rakePct}% operator rake of <b>${Number(rake).toLocaleString()}</b>.`;
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
    <div class="feedtitle" style="margin-top:14px">the number line (${Number(d.space).toLocaleString()} wide)</div>
    <div class="segs">${segs}${houseRow}</div>
  </div>`;
}
async function showRound(n) {
  if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} ws = null; } // pause home updates
  $('home').style.display = 'none';
  const el = $('round'); el.style.display = '';
  el.innerHTML = `<div class="card">loading round ${n}…</div>`;
  try { el.innerHTML = renderRound(await api('/api/round/' + n)); }
  catch (e) { el.innerHTML = `<div class="card"><a class="back" href="#">← back</a><p>failed to load round ${n}</p></div>`; }
}
function showHome() {
  $('round').style.display = 'none';
  $('home').style.display = '';
  if (!ws) connectWS(); // resume push updates
}
function route() {
  const m = (location.hash || '').match(/^#round\/(\d+)/);
  if (m) showRound(parseInt(m[1], 10)); else showHome();
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

function main() {
  $('me').textContent = short(ME.accountKey);
  $('faucetbtn').onclick = doFaucet;
  $('enterbtn').onclick = doEnter;
  $('newbtn').onclick = newPlayer;
  $('exportbtn').onclick = toggleExport;
  $('restorebtn').onclick = doRestore;
  $('withdrawbtn').onclick = doWithdraw;
  const dbtn = $('depositbtn'); if (dbtn) dbtn.onclick = showDepositAddress;
  $('copyphrase').onclick = () => copyText($('phraseout').textContent);
  flash('Welcome, ' + short(ME.accountKey) + '. Keys generated in your browser — back them up to restore later.', 'ok');
  window.addEventListener('hashchange', route);
  route(); // connects the WS on the home view, or shows a round-details page
  connectCosign(); // participate in non-custodial covenant cosign for this tab
  setInterval(() => { if (displayTimeLeft > 0 && lastState && lastState.participants >= lastState.min_participants) displayTimeLeft--; renderStatus(); }, 1000);
}
main();
