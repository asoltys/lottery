# Cube Jackpot — web client

Browser UI for the on-VM proportional-odds lottery running on a Cube engine.

- Keys are generated and `enter` calls are BLS-signed **in the browser**
  (`@noble/curves` bls12-381), byte-identical to the Rust engine.
- Talks to the engine's arcade HTTP API (`/api/state`, `/api/faucet`,
  `/api/call`). The engine serves these files when started with
  `CUBE_ARCADE_ASSETS=<this dir>`.

## Build
```
npm install
./build.sh          # -> bundle.js
```
Then point the engine at this directory:
```
CUBE_ARCADE_ASSETS=~/lottery CUBE_LOTTERY_CONTRACT=<id> ./target/debug/cube archival regtest engine ...
```
Open http://localhost:8090/ — open extra tabs to play as different people.
