// Cube Lottery — standalone unilateral-exit tool.
//
// This is bundled (build.sh -> exit-tool.bundle.js) and inlined into a single
// self-contained HTML file the player downloads from the live site ("Download
// exit kit"). That file bakes in the player's exit kit + base secret, so it keeps
// working forever from the local disk (file://) with NO server, NO DNS, NO operator
// — the ultimate operator-gone escape hatch. It broadcasts the pre-signed unroll
// through a public mempool API, waits out the CSV delay, then sweeps the player's
// own VTXO leaf with only their key.
//
// It reads its inputs from window.CUBE_EXIT = { kit, secp } injected by the wrapper.

import { unilateralExit } from './dispute.mjs';
import { bech32, bech32m } from '@scure/base';

const hx = (u) => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
const $ = (id) => document.getElementById(id);

function addressToSpk(addr) {
  let words;
  try { words = bech32m.decode(addr, 1023).words; }
  catch { words = bech32.decode(addr, 1023).words; }
  const ver = words[0];
  const prog = bech32.fromWords(words.slice(1));
  const op = ver === 0 ? 0x00 : (0x50 + ver);
  return hx(Uint8Array.from([op, prog.length, ...prog]));
}

function log(msg, cls) {
  const el = document.createElement('div');
  el.className = 'line' + (cls ? ' ' + cls : '');
  el.textContent = msg;
  $('log').prepend(el);
}

async function run() {
  const { kit, secp } = window.CUBE_EXIT || {};
  if (!kit || !kit.leaf || !secp) { log('exit kit or key missing from this file', 'err'); return; }
  const address = ($('addr').value || '').trim();
  if (!address) return log('enter a destination address first', 'err');
  let destSpk;
  try { destSpk = addressToSpk(address); } catch (e) { return log('invalid Bitcoin address', 'err'); }
  $('go').disabled = true;

  const mp = (kit.mempool_api || '').replace(/\/$/, '');
  if (!mp) { log('no public broadcaster baked into this kit — cannot exit offline', 'err'); $('go').disabled = false; return; }

  // Broadcast straight to the public mempool API (esplora /tx, raw-hex body).
  const broadcast = async (hex) => {
    const res = await fetch(mp + '/tx', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: hex });
    const txt = (await res.text()).trim();
    if (!res.ok || !/^[0-9a-f]{64}$/i.test(txt)) throw new Error('broadcast rejected: ' + txt.slice(0, 200));
    return txt;
  };
  const confirmations = async (utxid) => {
    try {
      const st = await (await fetch(`${mp}/tx/${utxid}/status`)).json();
      if (!st || !st.confirmed) return 0;
      const tip = parseInt(await (await fetch(`${mp}/blocks/tip/height`)).text(), 10);
      return Number.isFinite(tip) && st.block_height ? tip - st.block_height + 1 : 1;
    } catch (e) { return 0; }
  };

  try {
    log('Broadcasting your unroll…');
    const afterUnroll = async (utxid) => {
      log(`Unroll broadcast: ${utxid}. Waiting for the ${kit.leaf.exit_delay}-block CSV delay…`);
      for (let i = 0; i < 100000; i++) {
        await new Promise((r) => setTimeout(r, 15000));
        const c = await confirmations(utxid);
        log(`unroll confirmations: ${c} / ${kit.leaf.exit_delay}`);
        if (c >= kit.leaf.exit_delay) return;
      }
    };
    let fee = 600;
    if (kit.exit_sweep_fee > 0) fee = kit.exit_sweep_fee;
    const res = await unilateralExit({
      unrollTxHex: kit.unroll_tx_hex, unrollTxid: kit.unroll_txid, leaf: kit.leaf,
      secpHex: secp, destSpk, broadcast, afterUnroll, fee,
    });
    log(`DONE — swept ${Number(res.outValue).toLocaleString()} sats to ${address}. sweep txid ${res.sweepTxid}`, 'ok');
  } catch (e) {
    log('Exit error: ' + e.message, 'err');
  }
  $('go').disabled = false;
}

window.addEventListener('DOMContentLoaded', () => {
  const { kit, secp } = window.CUBE_EXIT || {};
  if (kit && kit.leaf) {
    $('summary').textContent = `Leaf value ≈ ${Number(kit.leaf.value).toLocaleString()} sats · network ${kit.mempool_api || '(none)'} · CSV delay ${kit.leaf.exit_delay} blocks`;
  } else {
    $('summary').textContent = 'No exit kit baked into this file.';
  }
  if (!secp) $('summary').textContent += ' · KEY MISSING';
  $('go').onclick = run;
});
