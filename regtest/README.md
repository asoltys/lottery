# Regtest harness for the non-custodial covenant

Brings up a local regtest `bitcoind` + the `lottery-engine` arcade so the on-chain
covenant lifecycle (deposit → genesis → refresh → unroll → unilateral exit) can be
exercised end-to-end without touching real coins.

## One-time: bake a regtest engine key

The engine refuses to start unless your nsec's pubkey equals the baked
`REGTEST_ENGINE_PUBLIC_KEY` in cube (`src/inscriptive/baked.rs`). The production
regtest key's nsec is kept out-of-band, so for local dev bake your OWN:

1. Pick/generate an nsec; derive its x-only pubkey (BIP340).
2. Set `REGTEST_ENGINE_PUBLIC_KEY` in `~/cube/src/inscriptive/baked.rs` to those
   32 bytes. **Keep this change local — do not commit it** (it's chain-specific and
   would break other builds).
3. Rebuild: `cd server && cargo build --bin lottery-engine`.

cube only uses the baked genesis payload as the initial sync default
(`unwrap_or_else(genesis_payload)`), not an on-chain requirement — so a fresh
regtest synced past height 98 boots fine; the covenant txs are broadcast through
the engine's own bitcoind RPC, independent of the genesis payload.

## Run

```sh
CUBE_ENGINE_NSEC=nsec1... regtest/up.sh     # bitcoind (daemon) + engine+arcade
# arcade: http://127.0.0.1:8090/   engine log: tail -f /tmp/engine.log
node cosign_arcade_smoke.mjs                 # full lifecycle e2e against the live arcade
regtest/down.sh                              # stop engine + regtest bitcoind
```

## Fixtures (pre-seeded scenarios)

```sh
regtest/snapshot.sh base            # save chain + cube storage under fixtures/base
regtest/restore.sh  base            # restore it, then regtest/up.sh
```

Snapshots capture the regtest chain+wallet (`/tmp/cube-regtest`) and the cube
engine storage (`~/cube/storage/regtest`). Use them to start a test from a known
state (e.g. `funded-covenant`) instead of rebuilding it each run.
