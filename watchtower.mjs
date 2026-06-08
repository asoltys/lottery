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

// The pre-signed unroll is feeless TRUC (v3) with a P2A anchor, so it can't be sent
// alone — broadcast it as a package with a self-funded CPFP child that pays the fee.
export function packageBroadcast(cli, parentHex) {
  const pdec = JSON.parse(cli(`decoderawtransaction ${parentHex}`));
  const ptxid = pdec.txid;
  const anchor = pdec.vout.find((o) => o.scriptPubKey.hex === '51024e73');
  if (!anchor) return cli(`sendrawtransaction ${parentHex}`); // not anchored — legacy path
  const u = JSON.parse(cli('listunspent 1')).sort((a, b) => b.amount - a.amount)[0];
  if (!u) throw new Error('watchtower has no UTXO to fund the CPFP');
  const change = cli('getnewaddress');
  const feeBtc = 0.00002;
  const outBtc = Math.round((u.amount + anchor.value - feeBtc) * 1e8) / 1e8;
  const inputs = JSON.stringify([{ txid: ptxid, vout: anchor.n }, { txid: u.txid, vout: u.vout }]);
  const outputs = JSON.stringify([{ [change]: outBtc }]);
  const cv3 = '03000000' + cli(`createrawtransaction '${inputs}' '${outputs}'`).slice(8);
  const prevtxs = JSON.stringify([
    { txid: ptxid, vout: anchor.n, scriptPubKey: '51024e73', amount: anchor.value },
    { txid: u.txid, vout: u.vout, scriptPubKey: u.scriptPubKey, amount: u.amount },
  ]);
  const signed = JSON.parse(cli(`signrawtransactionwithwallet ${cv3} '${prevtxs}'`));
  const res = JSON.parse(cli(`submitpackage '${JSON.stringify([parentHex, signed.hex])}'`));
  if (res.package_msg !== 'success') throw new Error('package not accepted: ' + JSON.stringify(res));
  return ptxid;
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
      log(`engine silent for ${height - base} blocks — broadcasting pre-signed unroll (CPFP package)`);
      const unrollTxid = packageBroadcast(cli, unrollHex);
      return { fired: true, unrollTxid };
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return { fired: false, reason: 'timeout' };
}
