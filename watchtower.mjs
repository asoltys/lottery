// Watchtower — the liveness backstop. It holds the current pot covenant outpoint
// and its PRE-SIGNED unroll (which needs no secret key). It watches the chain: as
// long as the engine keeps refreshing, the covenant outpoint keeps getting spent
// and the tower stands down. If the covenant sits unspent for `staleBlocks`
// (engine silent), the tower broadcasts the unroll, forcing the pot into
// per-participant VTXO leaves so everyone can exit unilaterally. No key required.

import { execSync } from 'node:child_process';

export function makeCli(datadir, wallet) {
  return (a) => execSync(
    `bitcoin-cli -datadir=${datadir}${wallet ? ` -rpcwallet=${wallet}` : ''} ${a}`,
    { stdio: ['ignore', 'pipe', 'pipe'] },
  ).toString().trim();
}

// Watch `covenantTxid:covenantVout`. Resolves when it either broadcasts the unroll
// (engine silent past the threshold) or stands down (covenant already spent).
export async function watchAndGuard({
  cli, covenantTxid, covenantVout, unrollHex,
  staleBlocks, baselineHeight = null, pollMs = 400, maxPolls = 600, log = () => {},
}) {
  const base = baselineHeight ?? parseInt(cli('getblockcount'), 10);
  for (let i = 0; i < maxPolls; i++) {
    const utxo = cli(`gettxout ${covenantTxid} ${covenantVout}`); // "" once spent
    if (!utxo) {
      log('covenant already spent — engine is active; standing down');
      return { fired: false, reason: 'covenant-spent' };
    }
    const height = parseInt(cli('getblockcount'), 10);
    if (height - base >= staleBlocks) {
      log(`engine silent for ${height - base} blocks — broadcasting pre-signed unroll`);
      const unrollTxid = cli(`sendrawtransaction ${unrollHex}`);
      return { fired: true, unrollTxid };
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return { fired: false, reason: 'timeout' };
}
