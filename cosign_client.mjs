// Browser/Node cosign client for the live N-of-N MuSig2 refresh. Drives the
// player's half of the protocol against the engine's WebSocket coordinator
// (server/src/cosign.rs), using the verified musig.mjs primitives. The player's
// base secp secret never leaves the device — only a nonce and a partial signature
// go on the wire.

import { partialSign, projectedSecret, evenYSecret, publicNonces, bytesToHex } from './musig.mjs';

const rand32 = () => {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return bytesToHex(b);
};

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
          message: msg.message,
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
