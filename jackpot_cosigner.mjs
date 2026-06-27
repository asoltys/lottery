// Headless JACKPOT cosigner. The accumulating jackpot is carried in the covenant
// as an ordinary participant allocation owned by a dedicated operator account
// (derived from the engine secret). This process connects to the engine's cosign
// hub as that account and co-signs covenant refreshes/unrolls on its behalf — so a
// contract-held balance lives in the covenant WITHOUT any special path in the
// money-critical coordinator. The jackpot's allocation legitimately drops to 0 on a
// strike, so it cosigns with { allowClaimLoss: true } (value conservation still
// guards it). Reusable for any contract-held balance, not lottery-specific.
//
// Run:  CUBE_ENGINE_NSEC=nsec1... [COSIGN_WS=ws://127.0.0.1:8090/cosign] node jackpot_cosigner.mjs

import { attachCosign } from './cosign_client.mjs';
import { deriveJackpot, nsecToSecret } from './jackpot.mjs';

const WS = process.env.COSIGN_WS || 'ws://127.0.0.1:8090/cosign';
const nsec = (process.env.CUBE_ENGINE_NSEC || '').trim();
if (!nsec) { console.error('CUBE_ENGINE_NSEC required'); process.exit(1); }
const { secpHex, accountHex } = deriveJackpot(nsecToSecret(nsec));
console.log(`jackpot cosigner: account=${accountHex} ws=${WS}`);

let detach = null;
function connect() {
  const ws = new WebSocket(WS);
  ws.addEventListener('open', () => {
    console.log('jackpot cosigner connected');
    detach = attachCosign(ws, secpHex, accountHex, (kind, detail) => {
      if (kind === 'reject') console.log('jackpot cosign REJECT:', JSON.stringify(detail));
      else console.log('jackpot cosign:', kind);
    }, { allowClaimLoss: true });
  });
  ws.addEventListener('close', () => { if (detach) { detach(); detach = null; } setTimeout(connect, 2000); });
  ws.addEventListener('error', () => { try { ws.close(); } catch (e) {} });
}
connect();
