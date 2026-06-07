// Browser/Node cosign client for the live N-of-N MuSig2 refresh. Drives the
// player's half of the protocol against the engine's WebSocket coordinator
// (server/src/cosign.rs), using the verified musig.mjs primitives. The player's
// base secp secret never leaves the device — only a nonce and a partial signature
// go on the wire.

import { partialSign, projectedSecret, evenYSecret, publicNonces, bytesToHex } from './musig.mjs';
import { covenantSpk, liftV2Spk } from './covenant.mjs';
import { keyPathSighash } from './sighash.mjs';

const rand32 = () => {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return bytesToHex(b);
};

const sumAlloc = (allocs) => allocs.reduce((s, a) => s + Number(a.value), 0);

// Independently rebuild the refresh tx from the context and confirm: (1) the
// sighash matches what we'd compute (server can't lie about what we sign),
// (2) the output is the correct next-state covenant, (3) value is conserved,
// (4) we keep an exitable claim. Returns { ok, errors, mySighash, myNewValue }.
function verifyRefresh(ctx, message, myAccountHex) {
  const errors = [];
  let mySighash = null;
  try {
    const prevSpk = covenantSpk(ctx.engine, ctx.old_allocations, ctx.old_expiry).spk;
    const nextSpk = covenantSpk(ctx.engine, ctx.new_allocations, ctx.new_expiry).spk;
    mySighash = keyPathSighash({
      version: 2, lockTime: 0, inputIndex: 0,
      inputs: [{ txid: ctx.prev_txid, vout: ctx.prev_vout, value: ctx.prev_value, spk: prevSpk, sequence: 0xffffffff }],
      outputs: [{ value: ctx.out_value, spk: nextSpk }],
    });
    if (mySighash.toLowerCase() !== (message || '').toLowerCase())
      errors.push('sighash mismatch — server asserted a different tx than the one described');
    if (Number(ctx.out_value) !== sumAlloc(ctx.new_allocations))
      errors.push('covenant value != Σ new allocations (value would leak)');
    if (Number(ctx.prev_value) < Number(ctx.out_value))
      errors.push('negative fee (prev_value < out_value)');
    const mine = (ctx.new_allocations || []).find((a) => a.account.toLowerCase() === myAccountHex.toLowerCase());
    if (!mine) errors.push('no exitable claim for me in the new covenant');
    return { ok: errors.length === 0, errors, mySighash, myNewValue: mine ? Number(mine.value) : 0 };
  } catch (e) {
    return { ok: false, errors: ['verify exception: ' + e.message], mySighash };
  }
}

// Rebuild the LiftV2 lift-in: confirm we are spending OUR OWN deposit output and
// that the sighash matches. The destination (pot covenant) is supplied by ctx;
// the app should compare ctx.dest_spk to its expected pot covenant.
function verifyDeposit(ctx, message, myAccountHex) {
  const errors = [];
  let mySighash = null;
  try {
    if ((ctx.account || '').toLowerCase() !== myAccountHex.toLowerCase())
      errors.push('deposit account is not mine');
    const depositSpk = liftV2Spk(myAccountHex, ctx.engine).spk;
    mySighash = keyPathSighash({
      version: 2, lockTime: 0, inputIndex: 0,
      inputs: [{ txid: ctx.prev_txid, vout: ctx.prev_vout, value: ctx.prev_value, spk: depositSpk, sequence: 0xffffffff }],
      outputs: [{ value: ctx.out_value, spk: ctx.dest_spk }],
    });
    if (mySighash.toLowerCase() !== (message || '').toLowerCase())
      errors.push('sighash mismatch — not the deposit spend described');
    if (Number(ctx.prev_value) < Number(ctx.out_value))
      errors.push('negative fee (prev_value < out_value)');
    return { ok: errors.length === 0, errors, mySighash };
  } catch (e) {
    return { ok: false, errors: ['verify exception: ' + e.message], mySighash };
  }
}

// Attach cosign handling to an open WebSocket. `secpHex` is the player's 32-byte
// base secret; `accountKeyHex` is their 32-byte x-only account key (even-Y).
// `onEvent(kind, detail)` is an optional progress callback. Returns a function to
// detach. The client says hello immediately so the coordinator can find it.
export function attachCosign(ws, secpHex, accountKeyHex, onEvent = () => {}) {
  const sessions = new Map(); // session_id -> { pubkeys, tweak, message, me }

  const send = (obj) => ws.send(JSON.stringify(obj));
  const hello = () => send({ type: 'hello', account: accountKeyHex });
  if (ws.readyState === 1) hello();
  else ws.addEventListener('open', hello, { once: true });

  const handler = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    switch (msg.type) {
      case 'start': {
        // VERIFY what we're about to sign before committing anything. Rebuild the
        // covenant + sighash from the context; refuse (sign nothing) on mismatch.
        let mySighash = msg.message;
        if (msg.ctx && msg.ctx.kind === 'refresh') {
          const v = verifyRefresh(msg.ctx, msg.message, accountKeyHex);
          if (!v.ok) { onEvent('reject', { session: msg.session, errors: v.errors }); break; }
          mySighash = v.mySighash;
        } else if (msg.ctx && msg.ctx.kind === 'deposit') {
          const v = verifyDeposit(msg.ctx, msg.message, accountKeyHex);
          if (!v.ok) { onEvent('reject', { session: msg.session, errors: v.errors }); break; }
          mySighash = v.mySighash;
        }
        // derive my signing secret: projected (refresh) or plain even-Y (deposit
        // lift-in, a plain 2-of-2), then a fresh nonce pair, and commit the nonce.
        const secret = msg.project === false
          ? evenYSecret(secpHex)
          : projectedSecret(secpHex, msg.your_value, msg.your_index);
        const hidingSecHex = rand32();
        const bindingSecHex = rand32();
        const { hidingHex, bindingHex } = publicNonces(hidingSecHex, bindingSecHex);
        sessions.set(msg.session, {
          pubkeys: msg.pubkeys,
          tweak: msg.tweak,
          message: mySighash, // sign the sighash WE derived (== verified server's)
          myPubkey: msg.your_pubkey,
          me: { secret, hidingSecHex, bindingSecHex },
        });
        onEvent('nonce', { session: msg.session, value: msg.your_value, index: msg.your_index });
        send({ type: 'nonce', session: msg.session, pubkey: msg.your_pubkey, hiding: hidingHex, binding: bindingHex });
        break;
      }
      case 'aggnonces': {
        const s = sessions.get(msg.session);
        if (!s) return;
        const nonces = msg.nonces.map((n) => ({ keyHex: n.pubkey, hidingHex: n.hiding, bindingHex: n.binding }));
        const partial = partialSign({
          pubkeys: s.pubkeys,
          tweakHex: s.tweak,
          nonces,
          messageHex: s.message,
          me: s.me,
        });
        onEvent('partial', { session: msg.session });
        send({ type: 'partial', session: msg.session, pubkey: s.myPubkey, partial });
        break;
      }
      case 'complete':
        onEvent('complete', { session: msg.session, txid: msg.txid });
        sessions.delete(msg.session);
        break;
      case 'abort':
        onEvent('abort', { session: msg.session, reason: msg.reason });
        sessions.delete(msg.session);
        break;
    }
  };

  ws.addEventListener('message', handler);
  return () => ws.removeEventListener('message', handler);
}
