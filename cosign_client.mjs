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

// The scriptPubKey this tab authorized for a withdraw payout (set by the app before
// it asks to withdraw). When THIS tab is the leaver, its cosign refuses unless the
// payout output goes to exactly this spk — so the operator can't redirect it.
let pendingWithdrawSpk = null;
export function setPendingWithdrawSpk(spkHex) { pendingWithdrawSpk = spkHex ? spkHex.toLowerCase() : null; }

// Independently rebuild the refresh tx from the context and confirm: the sighash
// matches what we'd compute, value is conserved, and — for a normal refresh — we
// keep an exitable claim. For a cooperative WITHDRAW (extra payout output): if I'm
// the leaver, the payout must go to the address I authorized; otherwise I must keep
// my claim. Returns { ok, errors, mySighash, myNewValue }.
function verifyRefresh(ctx, message, myAccountHex) {
  const errors = [];
  let mySighash = null;
  try {
    const me = myAccountHex.toLowerCase();
    const prevSpk = covenantSpk(ctx.engine, ctx.old_allocations, ctx.old_expiry).spk;
    const isWithdraw = ctx.payout_account != null;
    const outputs = [];
    if (isWithdraw) outputs.push({ value: Number(ctx.payout_value), spk: ctx.payout_spk }); // payout is output 0
    if ((ctx.new_allocations || []).length > 0) {
      const nextSpk = covenantSpk(ctx.engine, ctx.new_allocations, ctx.new_expiry).spk;
      outputs.push({ value: Number(ctx.out_value), spk: nextSpk });
    }
    mySighash = keyPathSighash({
      version: 2, lockTime: 0, inputIndex: 0,
      inputs: [{ txid: ctx.prev_txid, vout: ctx.prev_vout, value: ctx.prev_value, spk: prevSpk, sequence: 0xffffffff }],
      outputs,
    });
    if (mySighash.toLowerCase() !== (message || '').toLowerCase())
      errors.push('sighash mismatch — server asserted a different tx than the one described');
    if (Number(ctx.out_value || 0) !== sumAlloc(ctx.new_allocations || []))
      errors.push('covenant value != Σ new allocations (value would leak)');
    const outSum = outputs.reduce((s, o) => s + Number(o.value), 0);
    if (Number(ctx.prev_value) < outSum)
      errors.push('outputs exceed input (negative fee)');
    const mine = (ctx.new_allocations || []).find((a) => a.account.toLowerCase() === me);
    if (isWithdraw && ctx.payout_account.toLowerCase() === me) {
      // I'm withdrawing — the payout MUST go to the address I authorized.
      if (!pendingWithdrawSpk || (ctx.payout_spk || '').toLowerCase() !== pendingWithdrawSpk)
        errors.push('payout does not go to the address I authorized');
    } else if (!mine) {
      errors.push('no exitable claim for me in the new covenant');
    }
    return { ok: errors.length === 0, errors, mySighash, myNewValue: mine ? Number(mine.value) : 0 };
  } catch (e) {
    return { ok: false, errors: ['verify exception: ' + e.message], mySighash };
  }
}

// Verify an UNROLL (covenant -> per-participant VTXO leaves) before pre-signing
// it: rebuild the covenant input spk, recompute the key-path sighash over the
// declared leaf outputs, confirm it matches, and confirm we get a leaf. (Leaf
// spk reconstruction in JS is a follow-up; we verify the sighash + our presence.)
function verifyUnroll(ctx, message, myAccountHex) {
  const errors = [];
  let mySighash = null;
  try {
    const me = myAccountHex.toLowerCase();
    const prevSpk = covenantSpk(ctx.engine, ctx.allocations, Number(ctx.expiry)).spk;
    const inputs = [{ txid: ctx.prev_txid, vout: ctx.prev_vout, value: ctx.prev_value, spk: prevSpk, sequence: 0xffffffff }];
    // the unroll is a self-funded v2 tx (fee baked into a leaf; no anchor).
    const outputs = (ctx.outputs || []).map((o) => ({ value: o.value, spk: o.spk }));
    mySighash = keyPathSighash({ version: 2, lockTime: 0, inputIndex: 0, inputs, outputs });
    if (mySighash.toLowerCase() !== (message || '').toLowerCase())
      errors.push('sighash mismatch — not the unroll described');
    if (!(ctx.outputs || []).some((o) => (o.account || '').toLowerCase() === me))
      errors.push('no leaf for me in the unroll');
    return { ok: errors.length === 0, errors, mySighash };
  } catch (e) {
    return { ok: false, errors: ['verify exception: ' + e.message], mySighash };
  }
}

// Rebuild a LiftV2 lift-in (possibly multi-input: a genesis tx combining several
// deposits into the pot covenant) and confirm: we are spending OUR OWN deposit at
// our input index, the sighash matches, and — if a covenant is declared — the
// output is that covenant and we keep an exitable claim in it.
function verifyDeposit(ctx, message, myAccountHex) {
  const errors = [];
  let mySighash = null;
  try {
    const me = myAccountHex.toLowerCase();
    if ((ctx.account || '').toLowerCase() !== me) errors.push('deposit account is not mine');
    const idx = Number(ctx.input_index);
    const myInput = (ctx.inputs || [])[idx];
    if (!myInput || (myInput.account || '').toLowerCase() !== me)
      errors.push('my input index does not spend my deposit');

    // every input is a LiftV2 deposit spk of (input.account, engine).
    const inputs = (ctx.inputs || []).map((i) => ({
      txid: i.txid, vout: i.vout, value: i.value,
      spk: liftV2Spk(i.account, ctx.engine).spk, sequence: 0xffffffff,
    }));
    const outputs = (ctx.outputs || []).map((o) => ({ value: o.value, spk: o.spk }));
    mySighash = keyPathSighash({ version: 2, lockTime: 0, inputIndex: idx, inputs, outputs });
    if (mySighash.toLowerCase() !== (message || '').toLowerCase())
      errors.push('sighash mismatch — not the deposit spend described');

    // value sanity: total in >= total out (non-negative fee).
    const totalIn = inputs.reduce((s, i) => s + Number(i.value), 0);
    const totalOut = outputs.reduce((s, o) => s + Number(o.value), 0);
    if (totalIn < totalOut) errors.push('negative fee (Σ inputs < Σ outputs)');

    // if the output is a declared covenant, confirm it and our exitable claim.
    if (ctx.covenant) {
      const allocs = ctx.covenant.allocations || [];
      const expected = covenantSpk(ctx.engine, allocs, Number(ctx.covenant.expiry)).spk;
      if ((outputs[0]?.spk || '').toLowerCase() !== expected.toLowerCase())
        errors.push('output is not the declared pot covenant');
      if (Number(outputs[0]?.value) !== allocs.reduce((s, a) => s + Number(a.value), 0))
        errors.push('covenant value != Σ allocations (leaves would not sum)');
      if (!allocs.find((a) => a.account.toLowerCase() === me))
        errors.push('no exitable claim for me in the pot covenant');
    }
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
        } else if (msg.ctx && msg.ctx.kind === 'unroll') {
          const v = verifyUnroll(msg.ctx, msg.message, accountKeyHex);
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
