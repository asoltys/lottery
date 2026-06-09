# Building on Cube — a field report

What we learned shipping a **non-custodial Bitcoin jackpot** ([lotto.adamsoltys.com](https://lotto.adamsoltys.com), Mutinynet) on top of the Cube engine — a covenant-emulation / BitVM3-style L2 for Bitcoin. This is the honest version: what worked, where the abstraction leaks, and what those leaks imply for Cube as a general-purpose protocol. It's written for whoever builds the next thing on Cube (very possibly us, later).

---

## 1. What we built

A parimutuel lottery where **your odds are your share of the pot**:

- Players deposit BTC to a per-account **LiftV2 deposit address** (2-of-2: player + engine, with a ~3-month CSV unilateral-exit script path).
- Deposits are pooled into an on-chain **covenant** (a value-bound Projector MuSig2 output over `(account, value)` pairs) via *genesis* (first pool), *join* (absorb later deposits), or *epoch reform* (see §3.1).
- Gameplay runs as an **L2 contract** (lottery v4, shadow-ledger): entering a round `shadow_up`s your stake as an exitable claim; a round draws when it's ripe; the winner takes the pot minus a 1% rake; with 20% win odds the round usually **rolls over** and the jackpot grows.
- Every balance is meant to be **exitable without the operator** — cooperatively (a covenant refresh/withdraw), or unilaterally (pre-signed unroll → per-account VTXO leaf → CSV sweep with your key alone).
- Fraud is bounded by **garbled BitVM3 proofs**: the winner-verifier's two output labels gate two mutually-exclusive on-chain paths — an honest winner sweeps the whole pot (winner-sweep), or on fraud losers reclaim via the disprove path.

As a proof-of-concept it exercises nearly the whole Cube stack at once: deposits → covenant lifecycle → stateful contract execution → settlement → unilateral exit → fraud proofs. That breadth is exactly why it was a good demo — and why it surfaced so many leaks.

---

## 2. What works well

- **The core non-custodial claim is real.** A pooled player can walk their funds back to L1 with only their key (pre-signed unroll + CSV leaf sweep). We proved the winner-sweep on-chain cryptographically (a winner takes the pot with no loser cooperation).
- **Trustless client-side verification.** Every cosign the browser performs is independently re-derived and checked before signing (`cosign_client.mjs`: `verifyRefresh`/`verifyJoin`/`verifyDeposit`/`verifyUnroll`/`verifyDepositWithdraw`). The engine never sees a key, and the client refuses to sign anything whose sighash/value/claim it can't reconstruct. This pattern is the strongest part of the design and should be the template for any Cube app.
- **The covenant tracks the game.** After a win, `reconcile_covenant` refreshes allocations to match L2 balances and pays the operator rake out on-chain. Deposits made after genesis get absorbed. The pool stays coherent with the ledger (when liveness holds).
- **Low house edge.** The only edge is the 1% rake; the 20%/80% split is variance (rollover grows the pot), not skim. That's player-friendly by gambling standards.

---

## 3. The leak-map

These are the places where the clean abstraction ("non-custodial, programmable, pooled Bitcoin") strains in practice. None are fatal; all are instructive.

### 3.1 Liveness: N-of-N cooperative paths deadlock on one absent member

The covenant key-path spend is **N-of-N MuSig2**. Cooperative *join* (absorbing a new deposit) and cooperative *withdraw/refresh* therefore need **every existing covenant member online**. In a global single-covenant design, whoever deposits first "owns" the covenant; when they leave, **every later player is blocked** — can't join, can't cooperatively withdraw.

We hit this **three times** in one session (ghost members from a prior reset; three tabs whose keys were lost; a remote user who deposited first then went offline). Each time: `auto-join skipped: covenant member … offline — can't absorb yet`.

**Mitigation we built — epoch reform.** Once the covenant reaches its CLTV expiry, the engine reforms it via the **engine-only expiry script path** (`<expiry> CLTV DROP <engine> CHECKSIG`) — no member cosign — carrying every existing claim forward and absorbing online deposits. This breaks the deadlock without trusting members to be live. Cost: the expiry window is a liveness/trust dial (we run ~72 min on Mutinynet); short windows unblock fast but shorten the exit deadline before the engine's reclaim path opens.

**Residual leak.** Reform that absorbs a *live* player into a covenant containing *dead-key* members can't N-of-N pre-sign the new unroll (the dead members can't cosign), so the newly-absorbed player **loses unilateral exit** until a future refresh with everyone present. A poisoned covenant should be *reset*, not reformed.

**Lesson for Cube apps:** prefer **per-group or per-player covenants** over one global pool, or design the coordinator to form covenants only among currently-live members. N-of-N over a long-lived, growing member set is fragile; the blast radius of one absent key is everyone.

### 3.2 Key persistence: the silent footgun

Player identity (seed/mnemonic) lived in **`sessionStorage`**, which the browser wipes on tab close. Closing a tab without writing down the mnemonic or downloading the exit-kit = **funds permanently unrecoverable**. We watched real balances become orphaned this way. (We chose to leave it as-is for signet testing, but on mainnet this is unacceptable.)

**Lesson:** key management is *the* product problem for non-custodial apps, and it's easy to get catastrophically wrong with a one-line storage choice. `localStorage` + a forced, verified backup before first deposit is the floor. The exit-kit download (self-contained offline force-exit tool) is the right *idea* but must be unmissable.

### 3.3 Exit guarantees are conditional, not absolute

"You can always get your money out" is true with caveats that compound:

- **Pooled, you online + others online** → cooperative withdraw (instant, cheap). ✅
- **Pooled, others offline** → unilateral exit *if* you hold a pre-signed unroll → broadcast unroll, sweep your leaf after the CSV delay. Works, but slower and needs the unroll to have been signed while quorum was live.
- **Pooled, no pre-signed unroll** (absorbed while others were offline) → stuck until a refresh re-presigns. ⚠️
- **Un-pooled deposit, un-played** → direct 2-of-2 deposit withdrawal (we built this — `run_deposit_withdraw`). ✅
- **Un-pooled deposit, partially played** → blocked: balance < deposit, the difference is owed to the pot/rake, and there's no clean split (see §3.4). ⚠️
- **Everything fails** → the LiftV2 ~3-month CSV path, and the contract timeout-tree. Real, but slow.

So the guarantee is **"exit before the timeout, assuming you kept the right pre-signed material and the coordinator or your own liveness held."** That's meaningfully better than custodial, and meaningfully short of "your keys, always, instantly." Watchtowers move several of these ⚠️s back to ✅ but are unbuilt.

### 3.4 The deposit/stake entanglement (structural)

One indivisible deposit UTXO backs **both** your spendable balance **and** your in-contract stakes, across two separate ledgers (account balance vs. contract shadow allocations). Once you play, `balance < deposit_value` (stake + rake + fees), and "withdraw my settled balance but keep my stake in play" has **no clean on-chain expression** — you can't split the UTXO without reconciling both ledgers, and the stake's portion legitimately belongs to the pot/winners until the round resolves.

We made the direct deposit-withdraw **all-or-nothing** (only when balance fully backs the deposit) precisely to avoid silently letting a loser reclaim money owed to a winner. It's conservative and correct, but it means "deposit, play a little, withdraw the rest" doesn't work without pooling first. This isn't a bug to patch — it's the deepest design question in the app.

**Lesson:** if an app has both a spendable balance *and* committed state backed by the same UTXOs, decide *up front* how partial exit reconciles both. Retrofitting it is hard.

### 3.5 Contract-VM expressivity: the shadow ledger can't express winner-take-all

Cube's shadow ledger is **proportional and deferred**: `shadow_down_all(D)` scales every account by `(Σbase − D)/Σbase`. That makes "zero every loser while one winner stays positive" **mathematically impossible** at the contract level — losers with nonzero bases can't be driven to zero while the winner remains positive.

We discovered this the hard way trying to re-attribute winnings as shadow claims, abandoned it as infeasible, and built an entirely **separate on-chain primitive** (the garbled winner-sweep) to express winner-take-all. The contract bytecode/id never changed.

**Lesson:** Cube's contract model is real but **constrained** — it is not a general-purpose VM. Some economically-obvious operations (winner-take-all, certain redistributions) live *outside* what the shadow ledger can express and need bespoke script/fraud-proof primitives. Scope contract logic to proportional/deferred operations; expect to drop to custom Bitcoin script for anything else.

### 3.6 Single coordinator → the real throughput bottleneck

Every cooperative action funnels through one engine: it drives MuSig2 rounds, talks to one bitcoind over RPC, and serializes genesis/join/reform/settle. In practice the bottlenecks we hit were **never L1 block space** — they were the coordinator: sync stalls (blocking bitcoind RPC starving the HTTP server), cosign round-trip latency, and the N-of-N liveness barrier.

**Lesson on TPS:** Burak's high-TPS thesis (amortize many off-chain transitions into periodic on-chain batch commitments) is sound *as a protocol ceiling* — L1 only sees batch commitments, so throughput is bounded by off-chain execution + data availability. But the *practical* number is an **engine-engineering** problem (parallel cosign sessions, DA design, multiple/sharded coordinators, batch cadence) plus fraud-proof overhead — not the base layer. Treat any specific TPS figure as aspirational until it's benchmarked **under adversarial liveness**, not just happy path.

### 3.7 Operational sharp edges (for whoever runs the engine)

- The engine persists sync state in `storage/{chain}/` **relative to its cwd**; a stale height there (or a leaked process holding the sled dbs) makes boot retry a nonexistent block and the HTTP stall. Clean = kill all cube procs, wipe `storage/{chain}`, relaunch.
- Each lifecycle test needs a **fresh chain** — the engine processes blocks live but hangs re-syncing already-settled txns.
- Container state is **root-owned** (engine runs as root); wiping it from the host needs a root container, not `rm`.
- Kill engines by `/proc/PID/exe` (a rebuilt binary shows `…(deleted)`, so match by port owner), and bitcoinds by datadir/port — never a bare process-name match (you'll hit unrelated daemons).

---

## 4. How it compares — SatoshiDice and the betting landscape

- **SatoshiDice (2012, Erik Voorhees)** was provably-fair (committed server seed, revealed post-bet) and effectively **non-custodial per-bet**: you sent BTC to an odds-specific address and got paid back in one tx — no accounts, no held balances. But it had **zero programmability and zero scaling**: every bet was an L1 transaction (at peak, >half of all Bitcoin tx volume). Voorhees later settled with the **SEC (2014)** over selling *shares* in SatoshiDice for bitcoin as unregistered securities — a securities issue, not the gambling — and the site **IP-blocked US players** to avoid US gambling law.
- **This project** trades SatoshiDice's brutal simplicity for **expressiveness and scale** (pooled balances, rollover jackpot, L2 settlement) and inherits **custody complexity** as the price. It is *more* programmable and cheaper-at-scale, but *less* trivially non-custodial than SatoshiDice's one-tx-in-one-tx-out model.
- **Industry reality:** gambling is crypto's most reliably profitable, least-glamorous app category — always real demand, chronically underbuilt on **Bitcoin specifically** (most of it fled to other chains years ago). Provably-fair solved *fairness* a decade ago; the unsolved problems are **custody** (what this attacks) and **regulation** (what it doesn't — and on a US-facing mainnet, that's the real wall, per Voorhees).

---

## 5. Cube as a general-purpose L2 — verdict

**Promising architecture, early implementation, real open questions** — which is exactly where a pre-mainnet covenant L2 should be.

The Projector (value-bound MuSig2) + timeout-tree VTXOs + garbled fraud proofs is a coherent way to get **shared UTXOs with contract logic and unilateral exit** on Bitcoin without a soft fork — same family as Ark and BitVM rollups. Running a real stateful contract (deferred/proportional claims) with on-chain-backed, exitable balances shows it's more than a payments toy.

The honest caveats, in priority order:
1. **Trust model** — N-of-N liveness for cooperative paths, a single coordinating engine, and an operator/timeout reclaim backstop. Unilateral exit is the net, but it leans on watchtowers + user liveness.
2. **Contract expressivity** — proportional/deferred only; some obvious operations need bespoke primitives (§3.5).
3. **Data availability + fraud-proof machinery** — garbling + cut-and-choose is heavy and is what I'd most want independently audited before real money.

**Where Cube fits:** anything where **many users share a UTXO, need contract logic, and demand a unilateral escape hatch** — payment pools, parimutuel prediction markets/sports books (arguably a better product than a lottery), exitable token/stablecoin issuance, atomic DEX/order books, streaming micropayments. If an app doesn't need all three of {shared UTXO, contract logic, unilateral exit}, a simpler tool will beat Cube.

**The most valuable output of this PoC is not the game — it's this leak-map.** A demo that exposes where the abstraction strains (liveness, key persistence, conditional exit, VM limits, coordinator throughput) is worth more pre-mainnet than one that hides them.

---

## 6. Concrete next steps (if continuing)

- **Per-group covenants** (or live-member-only covenant formation) to kill the N-of-N deadlock at the root, rather than relying on epoch reform as a backstop.
- **Watchtower** to automate unilateral exit before expiry — converts most of §3.3's ⚠️ to ✅.
- **Key persistence + forced backup** (`localStorage`, mnemonic confirmation gate, unmissable exit-kit) before any mainnet exposure.
- **Decide the partial-exit/reconciliation model** (§3.4) deliberately — it's the deepest unsolved design question.
- **Benchmark TPS under adversarial liveness**, not happy path, before quoting any number.

---

*Built and documented June 2026 on Mutinynet (signet). Engine: forked Cube (`asoltys/cube`). App: `asoltys/lottery`.*
