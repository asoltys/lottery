# 🎰 Cube Jackpot

A browser-playable, provably-fair jackpot lottery running on a **forked Cube
engine**.

Players generate keys and BLS-sign their entries **entirely in the browser**
(`@noble/curves` bls12-381), byte-identical to the Rust engine — the server only
verifies the signature and runs the call. Unlimited players, contribute any
amount, odds proportional to your share of the pot, a ~25% no-winner **rollover**
that grows the jackpot, and a guaranteed-winner **final round** after 3 rollovers.
The winner is selected from the hash of a Bitcoin block, so no one can predict or
grind the outcome.

## Running a forked Cube engine

This runs against our fork of Cube (the upstream Bitcoin L2 is by burakimran):

**https://github.com/asoltys/cube**

The fork adds the pieces this game needs while keeping app logic out of the
engine:
- an `OP_BLOCKHASH` opcode (the draw's entropy source),
- VM fixes (`OP_SWAP`, several opcode bytecodes), and payable intake (money in),
- a generic post-init **engine hook** (`operative::runner::hook`) that this
  arcade attaches to in-process — so cube stays free of any lottery code.

## Layout

- `index.html`, `app.mjs` — the browser client. Build with `./build.sh` → `bundle.js`.
- `server/` — a Rust crate (`lottery-arcade`) that depends on the forked cube
  engine and launches it with the arcade web server attached. The arcade runs
  **inside** the engine process so it can execute calls instantly on the VM and
  run a faucet against the engine's in-memory state.

## Run (regtest)

```sh
# 1. build the browser client
npm install && ./build.sh

# 2. build the engine+arcade binary
cd server && cargo build && cd ..

# 3. launch it from the cube checkout (so it uses cube's regtest storage)
cd ~/cube
CUBE_ARCADE_ASSETS=~/lottery \
  ~/lottery/server/target/debug/lottery-engine \
  archival regtest engine http://127.0.0.1:18443 <rpc-user> <rpc-pass> false
# (enter the engine nsec when prompted)
```

Open **http://localhost:8090/** — open extra tabs to play as different people.

Config via env: `CUBE_ARCADE_PORT` (8090), `CUBE_LOTTERY_CONTRACT`,
`CUBE_MINE_ADDRESS`, `CUBE_ARCADE_ASSETS`.

The lottery contract itself (`tests/lottery_v2.rs` in the cube fork) is the
source of truth for the rules; this repo is the UI + the engine launcher.
