// Cube Lottery arcade (v2): a localhost web server to play the on-VM jackpot
// lottery from a browser. Players generate keys and BLS-sign their `enter`
// calls entirely client-side; this server verifies the signature and executes
// the call directly on the VM. A background task drives the round lifecycle
// (close + settle) using a server-held "settler" account; settle is
// permissionless and the contract verifies the winner, so the server can't rig
// the outcome.

use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
use cube::constructive::entity::account::root_account::registered_and_configured_root_account::registered_and_configured_root_account::RegisteredAndConfiguredRootAccount;
use cube::constructive::entity::account::root_account::root_account::RootAccount;
use cube::constructive::entity::contract::contract::Contract;
use cube::constructive::core_types::method_index::method_index::MethodIndex;
use cube::constructive::core_types::ops_budget::ops_budget::OpsBudget;
use cube::constructive::core_types::ops_price::ops_price::OpsPrice;
use cube::constructive::core_types::target::target::Target;
use cube::constructive::entry::entry_kinds::call::call::Call;
use cube::executive::executable::compiler::compiler::ProgramCompiler;
use cube::executive::exec_ctx::exec_ctx::{ExecCtx, EXEC_CTX};
use cube::executive::stack::stack_item::StackItem;
use cube::executive::stack::stack_uint::{SafeConverter, StackItemUintExt, StackUint};
use cube::inscriptive::archival_manager::archival_manager::ARCHIVAL_MANAGER;
use cube::inscriptive::coin_manager::coin_manager::COIN_MANAGER;
use cube::inscriptive::flame_manager::flame_manager::FLAME_MANAGER;
use cube::inscriptive::graveyard::graveyard::GRAVEYARD;
use cube::inscriptive::params_manager::params_manager::PARAMS_MANAGER;
use cube::inscriptive::privileges_manager::privileges_manager::PRIVILEGES_MANAGER;
use cube::inscriptive::registery::registery::REGISTERY;
use cube::inscriptive::state_manager::state_manager::STATE_MANAGER;
use cube::inscriptive::sync_manager::sync_manager::SYNC_MANAGER;
use cube::inscriptive::utxo_set::utxo_set::UTXO_SET;
use cube::operative::run_args::chain::Chain;
use cube::transmutative::bls::verify::bls_verify;
use cube::transmutative::hash::{sha256, Hash, HashTag};
use cube::transmutative::secp::schnorr::{verify_xonly, SchnorrSigningMode};
use cube::transmutative::key::KeyHolder;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRef, Path, Query, Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::broadcast;
use bitcoin::hashes::Hash as _;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

pub mod cosign;
pub mod covenant_manager;

const INDEX_HTML: &str = include_str!("../../index.html");
const BUNDLE_JS: &str = include_str!("../../bundle.js");
const SW_JS: &str = include_str!("../../sw.js");
const MANIFEST_JSON: &str = include_str!("../../manifest.webmanifest");
const EXIT_TOOL_JS: &str = include_str!("../../exit-tool.bundle.js");

// Lottery v2 state keys (mirror tests/lottery_v2.rs).
const KEY_TOTAL: u8 = 0x54; // running total ever
const KEY_B: u8 = 0x42; // cum-before-current-round
const KEY_G: u8 = 0x67; // global entry count
const KEY_RS: u8 = 0x72; // round start global index
const KEY_C: u8 = 0x63; // "c"+le(i) cumulative sum after entry i
const KEY_P: u8 = 0x70; // "p"+le(i) participant at entry i
const KEY_TIME: u8 = 0x74; // round open time
const KEY_K: u8 = 0x6b; // closed-at round number
const KEY_SEED: u8 = 0x73; // seed
const KEY_D: u8 = 0x64; // completed rounds
const KEY_W: u8 = 0x77; // last-win round number

const ROUND_DURATION: u64 = 120; // seconds (must match the contract)
const MIN_PARTICIPANTS: u64 = 1; // contract requires >= 1 entrant
const FAUCET_GRANT: u64 = 10_000;
const ODDS_DENOM: u64 = 4; // house = round_total * 4 -> 1/5 = 20% per-round win odds (match contract)
const RAKE_PERCENT: u64 = 1; // operator rake taken from the pot on a win
// Exit-tree params for the /api/exit non-custodial proof (VTXO unilateral exit).
const EXIT_TREE_EXIT_DELAY: u16 = 144; // CSV blocks before a holder can sweep
const EXIT_TREE_EXPIRY_WINDOW: u64 = 12_960; // CLTV engine-reclaim window above tip

// Lottery v3 program (compiled bytecode) + operator account that accrues the
// 1% rake. The contract is registered on startup if not already present; the
// operator account is registered so the rake transfers land and the operator
// (whoever holds the phrase) can withdraw via /api/withdraw.
// Lottery v4 (non-custodial): stakes are shadow-allocated claims (exitable VTXOs)
// while the round is live; a win zeroes the claims before paying out. Same
// draw/rake rules as v3, but 20% win odds (ODDS_DENOM=4). contract_id
// 8314f710b98817f9581212f03026e21a0c309aa71773099232035d2b4b2128fd
const V3_BYTES_HEX: &str = "2470657270657475616c206a61636b706f7420763420286e6f6e2d637573746f6469616c29000305656e7465720001092a0076b975c40167ce0172ce8763bd0174cd680154ce9369760154cd01630167ce7ecd01700167ce7eb9757ccd0167ce5193690167cd6505636c6f736500001c000172ce0167ce946951a269bd0174ce01789369a269d30173cd0164ce519369016bcd6506736574746c650001028a006b016bce0164ce51936987690142ce0154ce94697654956993690173ce9669750142ce9369760154cea263750164ce5193690164cd0154ce0142cd0167ce0172cdbd0174cd676c009369766b7601637c7ece7c76008763750067517c946901637c7ece687ca569c9c70164cb96697c7576008763756720a55068222783355b755993fe7e1ac0b190d29fa2689a9ebc041ff7252617dd0400cc686c01707c7ececb7c00cc0164ce5193690164cd0154ce0142cd0167ce0172cdbd0174cd0164ce0177cd6865";
const OPERATOR_ACCOUNT_HEX: &str = "a55068222783355b755993fe7e1ac0b190d29fa2689a9ebc041ff7252617dd04";
const OPERATOR_BLS_HEX: &str = "b6b8aa94cee6ea6012dc787a11a1c6101f83fb5eb974a00b9d1defcf2be0e3afa44c09a1b7c06c9907c6f15cb9216a45";

#[derive(Clone)]
struct ArcadeState {
    chain: Chain,
    engine_key: [u8; 32],
    contract_id: [u8; 32],
    registery: REGISTERY,
    coin_manager: COIN_MANAGER,
    state_manager: STATE_MANAGER,
    flame_manager: FLAME_MANAGER,
    sync_manager: SYNC_MANAGER,
    utxo_set: UTXO_SET,
    params_manager: PARAMS_MANAGER,
    privileges_manager: PRIVILEGES_MANAGER,
    graveyard: GRAVEYARD,
    archival_manager: Option<ARCHIVAL_MANAGER>,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    btc_wallet: String, // engine fee/spending wallet name (for CPFP funding)
    mine_address: String,
    settler_account: [u8; 32],
    settler_bls: [u8; 48],
    settler_reg_index: u64,
    last_winner: Arc<tokio::sync::Mutex<Option<String>>>,
    recent_draws: Arc<tokio::sync::Mutex<Vec<Value>>>,
    // Full per-round settlement records (seed, ranges, draw) for the
    // provably-fair details page, keyed by round number.
    round_details: Arc<tokio::sync::Mutex<HashMap<u64, Value>>>,
    exec_lock: Arc<tokio::sync::Mutex<()>>,
    tx: broadcast::Sender<()>, // "state changed" signal -> WebSocket push
    cosign_hub: cosign::CosignHub, // live N-of-N covenant refresh / lift-in cosign
    covenant: covenant_manager::CovenantManager, // persisted on-chain pot covenant
    pending_deposits: Arc<tokio::sync::Mutex<Vec<PendingDeposit>>>, // confirmed deposits awaiting genesis/join
    // Per-account LiftV2 deposit address watch: detected (mempool + confirmed)
    // deposits, refreshed by the background watcher and pushed over /ws.
    deposit_watch: Arc<tokio::sync::Mutex<HashMap<[u8; 32], DepositWatch>>>,
    // Deposit outpoints ("txid:vout") already credited to an L2 game balance,
    // persisted so a restart never double-credits.
    credited_deposits: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>>,
    credited_path: std::path::PathBuf,
    // Persisted jackpot history: the full per-round settlement records survive
    // restarts so the draw feed + provably-fair pages load for any player.
    history_path: std::path::PathBuf,
    // Lightning deposits via the Mutinynet Coinos instance: API base + the lotto
    // account's Bearer token + the webhook URL Coinos calls us back on. All three
    // present => LN deposits enabled. ln_invoices maps a per-invoice secret (also
    // the webhook auth token) to the pending swap.
    coinos_url: Option<String>,
    coinos_token: Option<String>,
    coinos_webhook_url: Option<String>,
    ln_invoices: Arc<tokio::sync::Mutex<HashMap<String, LnInvoice>>>,
    // Serializes auto-genesis attempts from the watcher loop (no concurrent runs).
    auto_genesis_lock: Arc<tokio::sync::Mutex<()>>,
}

// A confirmed LiftV2 deposit UTXO awaiting inclusion in the pot covenant.
#[derive(Clone)]
struct PendingDeposit {
    account: [u8; 32],
    txid_internal: [u8; 32], // bitcoin internal byte order (for the outpoint)
    vout: u32,
    value: u64,
}

// Live view of an account's deposit address (filled by the watcher loop).
#[derive(Clone, Default)]
struct DepositWatch {
    address: String,
    scriptpubkey: String,
    pending_sats: u64,   // sum of 0-conf (mempool) deposits
    confirmed_sats: u64, // sum of >=1-conf deposits
    confirmations: i64,  // confirmations of the most-confirmed deposit
    txid: Option<String>,
    vout: Option<u32>,
    confirmed_utxos: Vec<(String, u32, u64)>, // (txid display, vout, value) of CURRENTLY-UNSPENT confirmed deposits
    seen: Vec<(String, u32, u64)>, // every confirmed deposit ever seen (durable; for L2 crediting regardless of genesis timing)
}

// bitcoind watch-only descriptor wallet that tracks players' deposit addresses
// so we can detect deposits (incl. unconfirmed) without each client polling.
const DEPOSIT_WATCH_WALLET: &str = "lotto-deposit-watch";

// Covenant lifecycle tuning (regtest-friendly small values).
const COVENANT_EXIT_DELAY: u16 = 6; // CSV blocks for the demo (vs 144 in prod)
// The covenant's CLTV epoch: after this many blocks the engine can reform it via
// the expiry path (absorb joiners / carry balances) WITHOUT any member cosigning,
// so offline/abandoned members can't deadlock new joins. Short enough to drop
// stragglers promptly; comfortably above COVENANT_EXIT_DELAY so a member can always
// force-exit before expiry. ~72 min on Mutinynet (30s blocks); ~1 day on mainnet.
const COVENANT_EXPIRY_WINDOW: u64 = 144;

// --- dynamic fee estimation (mainnet-grade) ---
// Fees are estimated from the node's estimatesmartfee × the tx's vsize, with a
// safety margin and a relay floor, instead of a flat constant — so the protocol's
// txs confirm under real fee conditions. (TRUC v3 + P2A anchors + package-relay
// CPFP for the *pre-signed* unroll/exit need a Core 28+ node; this node is v25.99,
// so those activate on capable nodes / mainnet — see fee_rate_sat_vb notes.)
const FEE_MARGIN: f64 = 1.25; // headroom over the point estimate
const FEE_CONF_TARGET: i64 = 6; // blocks
// taproot tx component vsizes (key-path spends; close enough for fee sizing).
const VB_OVERHEAD: u64 = 11;
const VB_TAPROOT_KEYPATH_IN: u64 = 58;
const VB_TAPROOT_OUT: u64 = 43;
const VB_TAPROOT_SCRIPTPATH_EXIT_IN: u64 = 110; // leaf script-path spend (sig+script+control block)
fn genesis_vsize(n_in: u64) -> u64 { VB_OVERHEAD + n_in * VB_TAPROOT_KEYPATH_IN + VB_TAPROOT_OUT }
fn refresh_vsize() -> u64 { VB_OVERHEAD + VB_TAPROOT_KEYPATH_IN + VB_TAPROOT_OUT }
fn unroll_vsize(n_out: u64) -> u64 { VB_OVERHEAD + VB_TAPROOT_KEYPATH_IN + n_out * VB_TAPROOT_OUT }
fn exit_sweep_vsize() -> u64 { VB_OVERHEAD + VB_TAPROOT_SCRIPTPATH_EXIT_IN + VB_TAPROOT_OUT }

impl ArcadeState {
    fn notify(&self) {
        let _ = self.tx.send(());
    }
}

// Let axum extract the cosign hub from the arcade state for the /cosign route.
impl FromRef<ArcadeState> for cosign::CosignHub {
    fn from_ref(s: &ArcadeState) -> Self {
        s.cosign_hub.clone()
    }
}

impl ArcadeState {
    fn exec_ctx(&self) -> EXEC_CTX {
        ExecCtx::construct(
            self.engine_key,
            Arc::clone(&self.sync_manager),
            Arc::clone(&self.utxo_set),
            Arc::clone(&self.registery),
            Arc::clone(&self.graveyard),
            Arc::clone(&self.coin_manager),
            Arc::clone(&self.flame_manager),
            Arc::clone(&self.state_manager),
            Arc::clone(&self.privileges_manager),
            Arc::clone(&self.params_manager),
            self.archival_manager.clone(),
        )
    }
    fn rpc(&self) -> Option<Client> {
        Client::new(&self.rpc_url, Auth::UserPass(self.rpc_user.clone(), self.rpc_pass.clone())).ok()
    }
    // Current fee rate in sat/vB from the node's estimator, floored at the relay
    // minimum (1 sat/vB). estimatesmartfee returns BTC/kvB; falls back to 1 if the
    // estimator has no data (e.g. an empty signet mempool).
    fn fee_rate_sat_vb(&self) -> f64 {
        self.rpc()
            .and_then(|c| c.call::<Value>("estimatesmartfee", &[json!(FEE_CONF_TARGET)]).ok())
            .and_then(|v| v.get("feerate").and_then(|f| f.as_f64()))
            .map(|btc_per_kvb| btc_per_kvb * 1e8 / 1000.0)
            .filter(|r| r.is_finite() && *r > 0.0)
            .unwrap_or(1.0)
    }
    // Estimate a tx fee (sats) for a given vsize: rate × margin × vsize, floored
    // at 1 sat/vB so we never underpay relay.
    fn estimate_fee(&self, vsize: u64) -> u64 {
        let rate = (self.fee_rate_sat_vb() * FEE_MARGIN).max(1.0);
        (((vsize as f64) * rate).ceil() as u64).max(vsize)
    }
    // A bitcoind RPC client scoped to the deposit-watch wallet.
    fn watch_rpc(&self) -> Option<Client> {
        let url = format!("{}/wallet/{}", self.rpc_url.trim_end_matches('/'), DEPOSIT_WATCH_WALLET);
        Client::new(&url, Auth::UserPass(self.rpc_user.clone(), self.rpc_pass.clone())).ok()
    }
    // Create (or load) the watch-only descriptor wallet. Idempotent.
    fn ensure_watch_wallet(&self) {
        let Some(rpc) = self.rpc() else { return };
        // createwallet(name, disable_private_keys=true, blank=true, passphrase="", avoid_reuse=false, descriptors=true)
        let created: Result<Value, _> = rpc.call("createwallet", &[
            json!(DEPOSIT_WATCH_WALLET), json!(true), json!(true), json!(""), json!(false), json!(true),
        ]);
        if created.is_err() {
            // already exists -> just load it (ignore "already loaded")
            let _: Result<Value, _> = rpc.call("loadwallet", &[json!(DEPOSIT_WATCH_WALLET)]);
        }
    }
    // Import a deposit address into the watch wallet so listunspent sees it. A
    // small rescan window (~1 day) catches deposits sent just before the import.
    fn import_watch_address(&self, address: &str, label: &str) {
        let Some(wrpc) = self.watch_rpc() else { return };
        let desc = format!("addr({})", address);
        let checksummed = match wrpc.call::<Value>("getdescriptorinfo", &[json!(desc)]) {
            Ok(v) => v.get("descriptor").and_then(|d| d.as_str()).map(|s| s.to_string()),
            Err(_) => None,
        };
        let Some(desc) = checksummed else { return };
        let ts = (Utc::now().timestamp() - 86_400).max(0);
        // NB: do NOT pass `internal: false` — Core 29 rejects an addr() descriptor
        // with `internal:false` + a label ("Internal addresses should not have a
        // label"), which silently broke all deposit detection after the v25->v29
        // upgrade. Omitting it (defaults to a receive/labeled import) works.
        let res: Result<Value, _> = wrpc.call("importdescriptors", &[json!([
            { "desc": desc, "timestamp": ts, "label": label }
        ])]);
        if let Err(e) = res { eprintln!("import_watch_address {address}: {e}"); }
    }
    // Persist the set of credited deposit outpoints (atomic temp + rename).
    async fn persist_credited(&self) {
        let set: Vec<String> = { self.credited_deposits.lock().await.iter().cloned().collect() };
        let Ok(bytes) = serde_json::to_vec(&set) else { return };
        let tmp = self.credited_path.with_extension("tmp");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &self.credited_path);
        }
    }
    // Persist the full jackpot history (every round's settlement record), atomic
    // temp + rename, so a restart/redeploy never loses the draw feed.
    async fn persist_history(&self) {
        let map: HashMap<u64, Value> = { self.round_details.lock().await.clone() };
        let Ok(bytes) = serde_json::to_vec(&map) else { return };
        let tmp = self.history_path.with_extension("tmp");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &self.history_path);
        }
    }
    // Broadcast a fully-signed tx (hex) via bitcoind; returns the display txid.
    fn broadcast(&self, tx_hex: &str) -> Result<String, String> {
        let rpc = self.rpc().ok_or("bitcoin rpc unavailable")?;
        rpc.send_raw_transaction(tx_hex).map(|t| t.to_string()).map_err(|e| format!("{e}"))
    }
    // A bitcoind RPC client scoped to the engine's fee/spending wallet.
    fn fee_wallet_rpc(&self) -> Option<Client> {
        let url = format!("{}/wallet/{}", self.rpc_url.trim_end_matches('/'), self.btc_wallet);
        Client::new(&url, Auth::UserPass(self.rpc_user.clone(), self.rpc_pass.clone())).ok()
    }
    // Broadcast, auto-CPFP'ing a feeless TRUC(v3)+P2A parent (e.g. the pre-signed
    // unroll) via package relay; otherwise a plain sendrawtransaction.
    fn smart_broadcast(&self, tx_hex: &str) -> Result<String, String> {
        if tx_hex.len() >= 8 && &tx_hex[..8] == "03000000" && tx_hex.contains("0451024e73") {
            self.cpfp_broadcast(tx_hex)
        } else {
            self.broadcast(tx_hex)
        }
    }
    // Build a CPFP child (funded from the engine wallet) that spends the parent's
    // P2A anchor + a wallet UTXO and pays the package fee, then submit [parent,
    // child] as a package. Returns the parent txid.
    fn cpfp_broadcast(&self, parent_hex: &str) -> Result<String, String> {
        let rpc = self.rpc().ok_or("bitcoin rpc unavailable")?;
        let wrpc = self.fee_wallet_rpc().ok_or("fee wallet rpc unavailable")?;
        let pdec: Value = rpc.call("decoderawtransaction", &[json!(parent_hex)]).map_err(|e| format!("decode: {e}"))?;
        let ptxid = pdec["txid"].as_str().ok_or("no parent txid")?.to_string();
        let pvsize = pdec["vsize"].as_u64().unwrap_or(200);
        let anchor = pdec["vout"].as_array()
            .and_then(|outs| outs.iter().find(|o| o["scriptPubKey"]["hex"].as_str() == Some("51024e73")))
            .ok_or("parent has no P2A anchor")?;
        let anchor_vout = anchor["n"].as_u64().ok_or("anchor vout")?;
        let anchor_amt = anchor["value"].as_f64().unwrap_or(0.0); // BTC; spent by the child
        // pick the largest confirmed wallet UTXO to fund the package fee
        let utxos: Value = wrpc.call("listunspent", &[json!(1)]).map_err(|e| format!("listunspent: {e}"))?;
        let u = utxos.as_array().and_then(|a| a.iter().max_by(|x, y|
            x["amount"].as_f64().unwrap_or(0.0).partial_cmp(&y["amount"].as_f64().unwrap_or(0.0)).unwrap()))
            .ok_or("no wallet UTXO to fund CPFP")?;
        let u_txid = u["txid"].as_str().ok_or("utxo txid")?;
        let u_vout = u["vout"].as_u64().ok_or("utxo vout")?;
        let u_amt = u["amount"].as_f64().ok_or("utxo amount")?;
        let u_spk = u["scriptPubKey"].as_str().ok_or("utxo spk")?;
        let change_addr: String = wrpc.call("getnewaddress", &[]).map_err(|e| format!("getnewaddress: {e}"))?;
        // the child pays for the whole package (feeless parent + child); it spends
        // the anchor + a wallet UTXO, so child out = anchor + utxo − package fee.
        let fee_sats = self.estimate_fee(pvsize + 150);
        let in_sats = ((u_amt + anchor_amt) * 1e8).round() as i64;
        let out_sats = in_sats - fee_sats as i64;
        if out_sats <= 330 { return Err("CPFP funding UTXO too small for fee".into()); }
        let out_btc = out_sats as f64 / 1e8;
        let inputs = json!([{ "txid": ptxid, "vout": anchor_vout }, { "txid": u_txid, "vout": u_vout }]);
        let outputs = json!([{ change_addr: out_btc }]);
        let craw: String = wrpc.call("createrawtransaction", &[inputs, outputs]).map_err(|e| format!("createrawtransaction: {e}"))?;
        let cv3 = format!("03000000{}", &craw[8..]); // TRUC v3 child
        let prevtxs = json!([
            { "txid": ptxid, "vout": anchor_vout, "scriptPubKey": "51024e73", "amount": anchor_amt },
            { "txid": u_txid, "vout": u_vout, "scriptPubKey": u_spk, "amount": u_amt },
        ]);
        let signed: Value = wrpc.call("signrawtransactionwithwallet", &[json!(cv3), prevtxs]).map_err(|e| format!("sign child: {e}"))?;
        let chex = signed["hex"].as_str().ok_or("no signed child")?;
        let res: Value = rpc.call("submitpackage", &[json!([parent_hex, chex])]).map_err(|e| format!("submitpackage: {e}"))?;
        if res["package_msg"].as_str() != Some("success") {
            return Err(format!("package not accepted: {res}"));
        }
        Ok(ptxid)
    }
    fn best_block_hash(&self) -> [u8; 32] {
        self.rpc()
            .and_then(|c| c.get_best_block_hash().ok())
            .map(|h| h.to_byte_array())
            .unwrap_or([0u8; 32])
    }
    fn mine(&self, n: u64) {
        if let (Some(rpc), Ok(addr)) = (self.rpc(), bitcoin::Address::from_str(&self.mine_address)) {
            let _ = rpc.generate_to_address(n, &addr.assume_checked());
        }
    }
    async fn read_uint(&self, key: &[u8]) -> u64 {
        let sm = self.state_manager.lock().await;
        sm.get_state_value(self.contract_id, &key.to_vec())
            .map(|v| le_uint(&v))
            .unwrap_or(0)
    }
    async fn read_cum(&self, i: u64) -> u64 {
        let mut key = vec![KEY_C];
        key.extend(minimal_le(i));
        let sm = self.state_manager.lock().await;
        sm.get_state_value(self.contract_id, &key).map(|v| le_uint(&v)).unwrap_or(0)
    }
    async fn read_participant(&self, i: u64) -> Option<Vec<u8>> {
        let mut key = vec![KEY_P];
        key.extend(minimal_le(i));
        let sm = self.state_manager.lock().await;
        sm.get_state_value(self.contract_id, &key)
    }
    async fn contract_registery_index(&self) -> u64 {
        let reg = self.registery.lock().await;
        reg.get_contract_by_contract_id(self.contract_id).map(|c| c.registery_index).unwrap_or(0)
    }
    fn settler_call(&self, contract: Contract, method_index: u16, calldata: Vec<CalldataElement>, target: u64) -> Call {
        let account = RootAccount::RegisteredAndConfiguredRootAccount(
            RegisteredAndConfiguredRootAccount::new(self.settler_account, self.settler_reg_index, self.settler_bls),
        );
        Call::new(account, contract, MethodIndex::new(method_index), calldata, OpsBudget::new(None), OpsPrice::new(100), Target::new(target))
    }
}

fn le_uint(b: &[u8]) -> u64 {
    let mut x = 0u64;
    for (i, &c) in b.iter().take(8).enumerate() {
        x |= (c as u64) << (8 * i);
    }
    x
}
fn minimal_le(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out
}
fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s.trim_start_matches("0x")).ok()?.try_into().ok()
}

fn asset(name: &str, embedded: &'static str) -> String {
    if let Ok(dir) = std::env::var("CUBE_ARCADE_ASSETS") {
        if let Ok(s) = std::fs::read_to_string(format!("{}/{}", dir, name)) {
            return s;
        }
    }
    embedded.to_string()
}
// no-store: the UI ships often and the index/bundle must stay in lockstep, so
// never let a browser serve a stale bundle against fresh HTML (or vice versa).
// (The service worker keeps its OWN offline copy via the Cache API, independent
// of this header, so the operator-gone escape hatch still loads with no server.)
const NO_CACHE: &str = "no-store, must-revalidate";
async fn serve_index() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, NO_CACHE)], Html(asset("index.html", INDEX_HTML)))
}
async fn serve_bundle() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, NO_CACHE),
        ],
        asset("bundle.js", BUNDLE_JS),
    )
}
// The service worker is served with a short revalidate (no-cache) so browsers
// re-check it on every navigation and pick up a new shell version promptly.
async fn serve_sw() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
            // allow the SW to control the whole origin even though it's served from /sw.js
            (header::HeaderName::from_static("service-worker-allowed"), "/"),
        ],
        asset("sw.js", SW_JS),
    )
}
async fn serve_manifest() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        asset("manifest.webmanifest", MANIFEST_JSON),
    )
}
// The bundled standalone exit tool — the client fetches this once (online) and
// inlines it into a self-contained, downloadable HTML escape hatch.
async fn serve_exit_tool() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, NO_CACHE),
        ],
        asset("exit-tool.bundle.js", EXIT_TOOL_JS),
    )
}

// The public mempool/REST broadcaster for this chain — the operator-gone fallback
// the browser uses to push its pre-signed unroll when /api/broadcast is dead.
// Overridable via CUBE_MEMPOOL_API; None on regtest (no public broadcaster).
fn mempool_api(s: &ArcadeState) -> Option<String> {
    if let Ok(v) = std::env::var("CUBE_MEMPOOL_API") {
        let v = v.trim().trim_end_matches('/').to_string();
        if !v.is_empty() { return Some(v); }
    }
    match s.chain {
        Chain::Mainnet => Some("https://mempool.space/api".into()),
        // this deployment's signet IS Mutinynet — its public esplora lives here.
        Chain::Signet => Some("https://mutinynet.com/api".into()),
        _ => None,
    }
}

// Commit the execution delta to permanent storage.
async fn commit(s: &ArcadeState) {
    // Surface apply_changes failures: a swallowed coin-manager error leaves a
    // PARTIAL commit (e.g. balance written but shadow allocs not), which shows up
    // as a custody gap (jackpot != Σ exitable claims) after a restart.
    if let Err(e) = s.coin_manager.lock().await.apply_changes() {
        eprintln!("arcade: coin_manager.apply_changes FAILED: {:?}", e);
    }
    if let Err(e) = s.state_manager.lock().await.apply_changes() {
        eprintln!("arcade: state_manager.apply_changes FAILED: {:?}", e);
    }
    let _ = s.registery.lock().await.apply_changes();
    let _ = s.graveyard.lock().await.apply_changes();
    let _ = s.privileges_manager.lock().await.apply_changes();
}

// Execute a single call directly on the VM (serialized via exec_lock).
async fn run_call(s: &ArcadeState, call: &Call) -> Result<(), String> {
    let _guard = s.exec_lock.lock().await;
    let block_hash = s.best_block_hash();
    let now = Utc::now().timestamp() as u64;
    let ctx = s.exec_ctx();
    {
        ctx.lock().await.pre_execution().await;
    }
    let res = {
        ctx.lock().await.execute_call(call, now, block_hash).await
    };
    drop(ctx);
    match res {
        Ok(_) => {
            commit(s).await;
            Ok(())
        }
        Err(e) => {
            s.exec_ctx().lock().await.flush().await;
            Err(format!("{:?}", e))
        }
    }
}

async fn round_view(s: &ArcadeState) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, Vec<u8>) {
    // returns (g, rs, t, k, d, w, total, b, count, seed)
    let g = s.read_uint(&[KEY_G]).await;
    let rs = s.read_uint(&[KEY_RS]).await;
    let t = s.read_uint(&[KEY_TIME]).await;
    let k = s.read_uint(&[KEY_K]).await;
    let d = s.read_uint(&[KEY_D]).await;
    let w = s.read_uint(&[KEY_W]).await;
    let total = s.read_uint(&[KEY_TOTAL]).await;
    let b = s.read_uint(&[KEY_B]).await;
    let seed = {
        let sm = s.state_manager.lock().await;
        sm.get_state_value(s.contract_id, &vec![KEY_SEED]).unwrap_or_default()
    };
    (g, rs, t, k, d, w, total, b, g - rs, seed)
}

async fn get_state(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    Json(build_state(&s, params.get("account").map(|x| x.as_str())).await)
}

// Project a full per-round settlement record down to a compact feed event
// (round, kind, winner, amount, ts) — the shape the draw feed + history serve.
fn feed_event(d: &Value) -> Value {
    let round = d["round"].as_u64().unwrap_or(0);
    let amount = d["amount"].as_u64().unwrap_or(0);
    let ts = d["ts"].as_u64().unwrap_or(0);
    if d["kind"].as_str() == Some("rollover") {
        json!({ "round": round, "kind": "rollover", "amount": amount, "ts": ts })
    } else {
        json!({ "round": round, "kind": "win", "winner": d["winner"].as_str().unwrap_or(""), "amount": amount, "ts": ts })
    }
}

async fn build_state(s: &ArcadeState, account: Option<&str>) -> Value {
    let (g, rs, t, k, d, w, total, b, count, _seed) = round_view(s).await;
    let round_total = total.saturating_sub(b);
    let treasury = { s.coin_manager.lock().await.get_contract_balance(s.contract_id).unwrap_or(0) };
    let now = Utc::now().timestamp() as u64;
    let closed = k == d + 1;
    let streak = d.saturating_sub(w); // rounds since the last win (rollover streak)
    let time_left = if count == 0 { ROUND_DURATION } else { (t + ROUND_DURATION).saturating_sub(now) };
    let tip = { s.sync_manager.lock().await.cube_batch_sync_height_tip() };
    let contract_ri = s.contract_registery_index().await;

    let mut out = json!({
        "contract_id": hex::encode(s.contract_id),
        "contract_registery_index": contract_ri,
        "batch_height_tip": tip,
        "jackpot": treasury,
        "round_pot": round_total,
        "participants": count,
        "min_participants": MIN_PARTICIPANTS,
        "round_duration": ROUND_DURATION,
        "time_left": time_left,
        "closed": closed,
        "rollover_streak": streak,
        // per-round chance that the pot is won (vs. rolls over):
        // round_total / (round_total*(ODDS_DENOM+1)) = 1/(ODDS_DENOM+1).
        "round_win_odds_pct": 100.0 / (ODDS_DENOM as f64 + 1.0),
        "rake_percent": RAKE_PERCENT,
        "last_winner": s.last_winner.lock().await.clone(),
        "recent_draws": s.recent_draws.lock().await.clone(),
        "entry_cost_hint": FAUCET_GRANT,
        "explorer_url": std::env::var("CUBE_EXPLORER_URL").ok(),
        // Free L2 faucet + custodial on-chain cash-out are regtest-only; on
        // signet/mainnet there is no free money and no operator-funded payout.
        "faucet_enabled": s.chain == Chain::Regtest,
        // Lightning deposits show in the UI iff the Coinos swap bridge is configured
        // AND the operator has flipped COINOS_LN_LIVE on (i.e. inbound liquidity is up).
        // The /api/ln/deposit endpoint itself works whenever the bridge is configured.
        "ln_enabled": s.coinos_url.is_some() && s.coinos_token.is_some() && s.coinos_webhook_url.is_some()
            && std::env::var("COINOS_LN_LIVE").map(|v| !v.is_empty()).unwrap_or(false),
        "network": s.chain.to_string(),
    });

    if let Some(acct_hex) = account {
        if let Some(account_key) = parse_hex::<32>(acct_hex) {
            let (registered, reg_index) = {
                let reg = s.registery.lock().await;
                match reg.get_account_info_by_account_key(account_key) {
                    Some((_, _, idx, _)) => (true, idx),
                    None => (false, 0),
                }
            };
            let balance = { s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0) };
            // Your contribution this round = sum over [rs, g) where participant == you.
            let mut your = 0u64;
            for i in rs..g {
                if s.read_participant(i).await.as_deref() == Some(&account_key[..]) {
                    let cur = s.read_cum(i).await;
                    let prev = if i == 0 { 0 } else { s.read_cum(i - 1).await };
                    your += cur - prev;
                }
            }
            // Live deposit-address status (mempool + confirmed), and whether the
            // deposit has already joined the on-chain pot covenant.
            let dep = { s.deposit_watch.lock().await.get(&account_key).cloned() };
            let acct_hex_lc = hex::encode(account_key);
            // SUM (not find) — an account can legitimately appear in >1 allocation
            // (e.g. two deposits); first-match undercounts.
            let joined_sats: u64 = match s.covenant.current().await {
                Some(cov) => cov.allocations.iter().filter(|(h, _)| h.eq_ignore_ascii_case(&acct_hex_lc)).map(|(_, v)| *v).sum(),
                None => 0,
            };
            // How much of the confirmed deposit hasn't been credited to the L2
            // game balance yet (so the client can auto-claim it).
            let claimable_sats: u64 = match &dep {
                Some(d) => {
                    let credited = s.credited_deposits.lock().await;
                    d.seen.iter().filter(|(t, v, _)| !credited.contains(&format!("{t}:{v}"))).map(|(_, _, val)| *val).sum()
                }
                None => 0,
            };
            let deposit_json = dep.map(|d| json!({
                "address": d.address,
                "pending_sats": d.pending_sats,
                "confirmed_sats": d.confirmed_sats,
                "confirmations": d.confirmations,
                "txid": d.txid,
                "joined_sats": joined_sats,
                "claimable_sats": claimable_sats,
            }));

            // Funds you've deposited but that AREN'T pooled into the covenant yet
            // (waiting on a join/reform) still sit at your 2-of-2 LiftV2 deposit
            // address — recoverable directly without the covenant. Only offer it
            // when your L2 balance fully backs them (no gameplay loss owed to the
            // pot), so a player can always get an un-played deposit straight back.
            let pending_dep_sum: u64 = { s.pending_deposits.lock().await.iter().filter(|d| d.account == account_key).map(|d| d.value).sum() };
            let deposit_withdrawable: u64 = if pending_dep_sum > 0 && balance >= pending_dep_sum { pending_dep_sum } else { 0 };

            out["account"] = json!({
                "registered": registered, "registery_index": reg_index, "balance": balance,
                "your_contribution": your,
                "odds_pct": if round_total > 0 { (your as f64) * 100.0 / (round_total as f64) } else { 0.0 },
                "deposit": deposit_json,
                // your spendable claim in the current on-chain pot (summed over your
                // allocations; 0 if no covenant) — gates withdraw / force-exit / exit-kit.
                "onchain_claim": joined_sats,
                // un-pooled deposits you can withdraw directly via the 2-of-2 LiftV2
                // spend (no covenant needed) — also gates the Withdraw button.
                "deposit_withdrawable": deposit_withdrawable,
            });
        }
    }
    out
}

// Access log: record the real client IP (cloudflared forwards it as
// CF-Connecting-IP) plus the path and any ?account= so we can tie an account to an
// IP — e.g. to identify who is playing. Only logs API/ws/cosign paths.
async fn access_log(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path.starts_with("/api/") || path == "/ws" || path == "/cosign" {
        let h = req.headers();
        let ip = h.get("cf-connecting-ip")
            .or_else(|| h.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("?")
            .to_string();
        let method = req.method().clone();
        let acct = req.uri().query()
            .and_then(|q| q.split('&').find(|kv| kv.starts_with("account=")))
            .map(|kv| kv.trim_start_matches("account=").chars().take(16).collect::<String>())
            .unwrap_or_default();
        let country = h.get("cf-ipcountry").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        eprintln!("[access] ip={ip} cc={country} {method} {path}{}", if acct.is_empty() { String::new() } else { format!(" account={acct}…") });
    }
    next.run(req).await
}

// WebSocket: push fresh state on every change (and a heartbeat). The client
// holds one connection instead of polling.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(s): State<ArcadeState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let account = params.get("account").cloned();
    ws.on_upgrade(move |socket| ws_loop(socket, s, account))
}

async fn ws_loop(mut socket: WebSocket, s: ArcadeState, account: Option<String>) {
    let mut rx = s.tx.subscribe();
    let acct = account.as_deref();
    // initial snapshot
    let st = build_state(&s, acct).await;
    if socket.send(Message::Text(st.to_string())).await.is_err() {
        return;
    }
    loop {
        match rx.recv().await {
            Ok(_) => {
                let st = build_state(&s, acct).await;
                if socket.send(Message::Text(st.to_string())).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

#[derive(Deserialize)]
struct FaucetReq {
    account_key: String,
    bls_key: String,
}
async fn post_faucet(State(s): State<ArcadeState>, Json(body): Json<FaucetReq>) -> Json<Value> {
    // The faucet mints free L2 play-money. Only allow it on regtest (worthless
    // coins). On signet/mainnet it's disabled so free funds can never be cashed
    // out on-chain — real funds must come from a trustless deposit.
    if s.chain != Chain::Regtest {
        return Json(json!({ "error": "faucet disabled on this network — deposit to play" }));
    }
    let (account_key, bls_key) = match (parse_hex::<32>(&body.account_key), parse_hex::<48>(&body.bls_key)) {
        (Some(a), Some(b)) => (a, b),
        _ => return Json(json!({ "error": "bad keys" })),
    };
    let now = Utc::now().timestamp() as u64;
    let _guard = s.exec_lock.lock().await;
    let already = { s.registery.lock().await.get_account_info_by_account_key(account_key).is_some() };
    if !already {
        let mut reg = s.registery.lock().await;
        let _ = reg.register_account(account_key, now, Some(bls_key), None, None, None);
        let _ = reg.apply_changes();
    }
    {
        let mut cm = s.coin_manager.lock().await;
        match cm.get_account_balance(account_key) {
            None => {
                let _ = cm.register_account(account_key, FAUCET_GRANT);
            }
            Some(_) => {
                let _ = cm.account_balance_up(account_key, FAUCET_GRANT);
            }
        }
        let _ = cm.apply_changes();
        // Non-custodial: allocate the player in the lottery contract's shadow
        // space once, so each `enter` can shadow_up their stake as an exitable
        // claim. (contract_shadow_alloc_account errors on an existing entry, so
        // only allocate when there is none — incl. after a win's down_all, which
        // leaves a zeroed entry.)
        if cm.get_shadow_alloc_value_in_satoshis(s.contract_id, account_key).is_none() {
            let _ = cm.contract_shadow_alloc_account(s.contract_id, account_key);
            let _ = cm.apply_changes();
        }
    }
    let reg_index = {
        s.registery.lock().await.get_account_info_by_account_key(account_key).map(|(_, _, idx, _)| idx).unwrap_or(0)
    };
    let balance = { s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0) };
    s.notify();
    Json(json!({ "registery_index": reg_index, "balance": balance, "granted": FAUCET_GRANT }))
}

#[derive(Deserialize)]
struct CalldataEl {
    #[serde(rename = "type")]
    kind: String,
    value: u64,
}
#[derive(Deserialize)]
struct CallReq {
    account_key: String,
    registery_index: u64,
    bls_key: String,
    method_index: u16,
    calldata: Vec<CalldataEl>,
    ops_price: u64,
    target: u64,
    bls_signature: String,
}
async fn post_call(State(s): State<ArcadeState>, Json(body): Json<CallReq>) -> Json<Value> {
    let account_key = match parse_hex::<32>(&body.account_key) { Some(a) => a, None => return Json(json!({"ok":false,"error":"bad account key"})) };
    let bls_key = match parse_hex::<48>(&body.bls_key) { Some(b) => b, None => return Json(json!({"ok":false,"error":"bad bls key"})) };
    let signature = match parse_hex::<96>(&body.bls_signature) { Some(x) => x, None => return Json(json!({"ok":false,"error":"bad signature"})) };

    let account = RootAccount::RegisteredAndConfiguredRootAccount(
        RegisteredAndConfiguredRootAccount::new(account_key, body.registery_index, bls_key),
    );
    let contract = { s.registery.lock().await.get_contract_by_contract_id(s.contract_id).unwrap_or_else(|| Contract::new(s.contract_id, 0)) };
    let calldata: Vec<CalldataElement> = body.calldata.iter().filter(|e| e.kind == "payable").map(|e| CalldataElement::Payable(e.value as u32)).collect();
    let call = Call::new(account, contract, MethodIndex::new(body.method_index), calldata, OpsBudget::new(None), OpsPrice::new(body.ops_price), Target::new(body.target));

    if call.bls_verify(signature).is_err() {
        return Json(json!({ "ok": false, "error": "signature verification failed" }));
    }
    match run_call(&s, &call).await {
        Ok(_) => {
            s.mine(1); // advance the tip so the round seed evolves
            s.notify();
            let balance = { s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0) };
            Json(json!({ "ok": true, "balance": balance }))
        }
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

// Full provably-fair breakdown for one settled round.
async fn get_round(State(s): State<ArcadeState>, Path(n): Path<u64>) -> Json<Value> {
    match s.round_details.lock().await.get(&n) {
        Some(v) => Json(v.clone()),
        None => Json(json!({ "error": "unknown or not-yet-settled round" })),
    }
}

// The WHOLE jackpot history (every persisted round) as compact feed events,
// newest first — so any player, even a brand-new one, can load all past draws.
async fn get_history(State(s): State<ArcadeState>) -> Json<Value> {
    let rd = s.round_details.lock().await;
    let mut draws: Vec<Value> = rd.values().map(feed_event).collect();
    draws.sort_by(|a, b| b["round"].as_u64().unwrap_or(0).cmp(&a["round"].as_u64().unwrap_or(0)));
    Json(json!({ "draws": draws, "count": draws.len() }))
}

// Non-custodial proof: render the contract's current shadow claims as a timeout
// tree of unilaterally-exitable VTXOs and return THIS account's leaf — the value
// it can sweep to Bitcoin with only its own key (CSV exit path), no operator
// cooperation. This is what makes the live jackpot non-custodial: your stake is
// always an exitable claim, not trusted to us.
async fn get_exit(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    let account = match params.get("account").and_then(|a| parse_hex::<32>(a)) {
        Some(a) => a,
        None => return Json(json!({ "error": "bad account" })),
    };
    let allocations = {
        s.coin_manager
            .lock()
            .await
            .get_contract_shadow_allocations_in_satoshis(s.contract_id)
            .unwrap_or_default()
    };
    let pot: u64 = allocations.iter().map(|(_, v)| v).sum();
    let tip = { s.sync_manager.lock().await.bitcoin_sync_height_tip() };
    let expiry_height = (tip + EXIT_TREE_EXPIRY_WINDOW) as u32;

    let tree = TimeoutTree::build(
        s.engine_key,
        &allocations,
        expiry_height,
        EXIT_TREE_EXIT_DELAY,
        None,
    );
    let leaf = tree
        .as_ref()
        .and_then(|t| t.leaves.iter().find(|l| l.account_key == account));

    match leaf {
        Some(leaf) => {
            let (lh, script, cb) = leaf.exit_spend_elements().unwrap_or_default();
            Json(json!({
                "account": hex::encode(account),
                "exitable": true,
                "value_sats": leaf.value_in_satoshis,
                "pot_sats": pot,
                "vtxo_scriptpubkey": hex::encode(leaf.scriptpubkey().unwrap_or_default()),
                "exit_script": hex::encode(script),
                "exit_control_block": hex::encode(cb),
                "exit_leaf_hash": hex::encode(lh),
                "exit_delay_blocks": EXIT_TREE_EXIT_DELAY,
                "expiry_height": expiry_height,
                "note": "Your stake is a Projector value-bound VTXO. After the CSV delay you can sweep it to Bitcoin with only your key — the operator cannot hold it."
            }))
        }
        None => Json(json!({
            "account": hex::encode(account),
            "exitable": false,
            "value_sats": 0,
            "pot_sats": pot,
            "note": "No live claim (not entered this round, or won/lost — winnings are paid to your exitable account balance)."
        })),
    }
}

// Background loop: watch every registered LiftV2 deposit address via a watch-only
// wallet's listunspent(0) (so mempool + confirmed are both visible), refresh each
// account's DepositWatch, auto-queue confirmed deposits for the covenant, and nudge
// /ws clients on any change. Lets the browser show a deposit (pending -> confirmed
// -> joined) live instead of the player polling or refreshing.
async fn deposit_watcher(s: ArcadeState) {
    { let s2 = s.clone(); tokio::task::spawn_blocking(move || s2.ensure_watch_wallet()).await.ok(); }
    // Rebuild the watch map from the wallet's imported addresses (label = account
    // hex), so deposits keep being tracked across restarts without the client
    // having to re-register its address.
    {
        let s2 = s.clone();
        let rebuilt = tokio::task::spawn_blocking(move || {
            let wrpc = s2.watch_rpc()?;
            let labels: Vec<String> = wrpc.call("listlabels", &[]).ok()?;
            let mut out: Vec<([u8; 32], String)> = Vec::new();
            for label in labels {
                let Some(acct) = parse_hex::<32>(&label) else { continue };
                if let Ok(Value::Object(addrs)) = wrpc.call::<Value>("getaddressesbylabel", &[json!(label)]) {
                    for addr in addrs.keys() { out.push((acct, addr.clone())); }
                }
            }
            Some(out)
        }).await.ok().flatten();
        if let Some(map) = rebuilt {
            let mut w = s.deposit_watch.lock().await;
            for (acct, addr) in map {
                let e = w.entry(acct).or_default();
                if e.address.is_empty() { e.address = addr; }
            }
        }
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let watched: Vec<([u8; 32], String)> = {
            let w = s.deposit_watch.lock().await;
            w.iter().filter(|(_, v)| !v.address.is_empty()).map(|(k, v)| (*k, v.address.clone())).collect()
        };
        if watched.is_empty() { continue; }
        let s2 = s.clone();
        let unspent = tokio::task::spawn_blocking(move || {
            let wrpc = s2.watch_rpc()?;
            wrpc.call::<Value>("listunspent", &[json!(0), json!(9_999_999)]).ok()
        }).await.ok().flatten();
        let utxos = match unspent { Some(Value::Array(a)) => a, _ => continue };

        // address -> (pending_sats, confirmed_sats, max_confs, deepest confirmed txid/vout)
        let mut agg: HashMap<String, (u64, u64, i64, Option<String>, Option<u32>)> = HashMap::new();
        // per-address list of confirmed UTXOs: (txid_display, vout, value)
        let mut addr_confirmed: HashMap<String, Vec<(String, u32, u64)>> = HashMap::new();
        // confirmed UTXOs to queue for the covenant: (address, txid_display, vout, value)
        let mut confirmed_utxos: Vec<(String, String, u32, u64)> = Vec::new();
        for u in &utxos {
            let addr = u.get("address").and_then(|x| x.as_str()).unwrap_or("");
            if addr.is_empty() { continue; }
            let sats = (u.get("amount").and_then(|x| x.as_f64()).unwrap_or(0.0) * 1e8).round() as u64;
            let confs = u.get("confirmations").and_then(|x| x.as_i64()).unwrap_or(0);
            let e = agg.entry(addr.to_string()).or_insert((0, 0, 0, None, None));
            if confs >= 1 {
                e.1 += sats;
                let txid = u.get("txid").and_then(|x| x.as_str()).map(|t| t.to_string());
                let vout = u.get("vout").and_then(|x| x.as_u64()).map(|v| v as u32);
                if e.3.is_none() || confs > e.2 { e.3 = txid.clone(); e.4 = vout; }
                if confs > e.2 { e.2 = confs; }
                if let (Some(t), Some(v)) = (txid, vout) {
                    confirmed_utxos.push((addr.to_string(), t.clone(), v, sats));
                    addr_confirmed.entry(addr.to_string()).or_default().push((t, v, sats));
                }
            } else {
                e.0 += sats;
                if e.3.is_none() && e.0 > 0 { e.3 = u.get("txid").and_then(|x| x.as_str()).map(|t| t.to_string()); }
            }
        }

        let mut changed = false;
        {
            let mut w = s.deposit_watch.lock().await;
            for (acct, addr) in &watched {
                let (p, c, confs, txid, vout) = agg.get(addr).cloned().unwrap_or((0, 0, 0, None, None));
                let cu = addr_confirmed.get(addr).cloned().unwrap_or_default();
                if let Some(e) = w.get_mut(acct) {
                    if e.pending_sats != p || e.confirmed_sats != c || e.confirmations != confs || e.confirmed_utxos != cu { changed = true; }
                    e.pending_sats = p; e.confirmed_sats = c; e.confirmations = confs; e.txid = txid; e.vout = vout;
                    e.confirmed_utxos = cu.clone();
                    // remember every confirmed deposit durably, so the L2 credit
                    // survives the deposit being spent into the covenant by genesis.
                    for (t, v, val) in cu {
                        if !e.seen.iter().any(|(st, sv, _)| st == &t && *sv == v) { e.seen.push((t, v, val)); }
                    }
                }
            }
        }

        // Auto-queue confirmed deposits into the covenant join queue (dedup by
        // outpoint). The depositor still needs to be online to co-sign genesis.
        if !confirmed_utxos.is_empty() {
            let addr_to_acct: HashMap<String, [u8; 32]> = watched.iter().map(|(a, addr)| (addr.clone(), *a)).collect();
            let mut pd = s.pending_deposits.lock().await;
            for (addr, txid_disp, vout, value) in confirmed_utxos {
                let Some(acct) = addr_to_acct.get(&addr) else { continue };
                let txid_internal = match bitcoin::Txid::from_str(&txid_disp) { Ok(t) => t.to_byte_array(), Err(_) => continue };
                if pd.iter().any(|d| d.txid_internal == txid_internal && d.vout == vout) { continue; }
                pd.push(PendingDeposit { account: *acct, txid_internal, vout, value });
                changed = true;
            }
        }

        if changed { let _ = s.tx.send(()); }

        // Auto-form the covenant once an online depositor has a confirmed deposit
        // queued (matches the UI's "deposit and the engine forms one"). Guarded so
        // only one attempt runs at a time; offline depositors are skipped.
        if let Ok(_g) = s.auto_genesis_lock.try_lock() {
            let connected: std::collections::HashSet<[u8; 32]> = s.cosign_hub.connected().await.into_iter().collect();
            let has_connected_deposit = { s.pending_deposits.lock().await.iter().any(|d| connected.contains(&d.account)) };
            if has_connected_deposit {
                if s.covenant.current().await.is_none() {
                    match do_genesis(&s).await {
                        Ok((txid, v, n)) => eprintln!("auto-genesis: covenant {txid} value {v} ({n} participants)"),
                        Err(e) => eprintln!("auto-genesis skipped: {e}"),
                    }
                } else {
                    // a covenant exists — ABSORB the new deposits into it (join), so
                    // post-genesis depositors become covenant-backed and can play +
                    // withdraw winnings. Needs every old member online (input 0 is
                    // N-of-N); skips otherwise and retries on the next tick.
                    match do_join(&s).await {
                        Ok((txid, v, n)) => eprintln!("auto-join: absorbed deposits -> covenant {txid} value {v} ({n} claimants)"),
                        Err(e) => {
                            eprintln!("auto-join skipped: {e}");
                            // Cooperative join needs every old member online (input 0 is
                            // N-of-N). If members are offline/abandoned AND the covenant has
                            // reached its epoch expiry, the engine reforms it unilaterally via
                            // the expiry script path — no member cosign required — so absent
                            // members can't deadlock new joins/withdrawals forever.
                            let tip = { s.sync_manager.lock().await.bitcoin_sync_height_tip() };
                            let reform_ready = match s.covenant.current().await {
                                Some(cov) => (tip as u32) >= cov.expiry,
                                None => false,
                            };
                            if reform_ready {
                                match do_epoch_reform(&s).await {
                                    Ok((txid, v, n)) => eprintln!("auto-reform: epoch reform -> covenant {txid} value {v} ({n} claimants)"),
                                    Err(e) => eprintln!("auto-reform skipped: {e}"),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// A pending Lightning deposit: once the invoice is paid, swap `amount` on-chain to
// the player's LiftV2 deposit address. Keyed in `ln_invoices` by a per-invoice
// secret that doubles as the webhook auth token.
#[derive(Clone)]
struct LnInvoice {
    account: [u8; 32],
    deposit_address: String,
    amount: u64,
    swapped: bool,
}

const LN_MIN_DEPOSIT: u64 = 5000; // sats — matches the minimum bet chip (5k)

// POST a JSON body to the Coinos API as the lotto account (Bearer token).
async fn coinos_post(s: &ArcadeState, path: &str, body: Value) -> Result<Value, String> {
    let url = s.coinos_url.as_ref().ok_or("Lightning deposits not configured")?;
    let token = s.coinos_token.as_ref().ok_or("Lightning deposits not configured")?;
    let resp = reqwest::Client::new()
        .post(format!("{}{}", url.trim_end_matches('/'), path))
        .bearer_auth(token)
        .json(&body)
        .send().await.map_err(|e| format!("coinos request: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text.clone()));
    if !status.is_success() { return Err(format!("coinos {status}: {v}")); }
    Ok(v)
}

// Lightning deposit: create a Coinos invoice on the lotto account, tagged with a
// webhook + a per-invoice secret. When paid, Coinos calls /api/ln/webhook and we
// swap the funds on-chain to the player's LiftV2 deposit address.
#[derive(Deserialize)]
struct LnDepositReq { account_key: String, amount: u64 }
async fn post_ln_deposit(State(s): State<ArcadeState>, Json(b): Json<LnDepositReq>) -> Json<Value> {
    let webhook = match (&s.coinos_url, &s.coinos_token, &s.coinos_webhook_url) {
        (Some(_), Some(_), Some(w)) => w.clone(),
        _ => return Json(json!({"ok":false,"error":"Lightning deposits not available"})),
    };
    let account = match parse_hex::<32>(&b.account_key) { Some(a) => a, None => return Json(json!({"ok":false,"error":"bad account"})) };
    if b.amount < LN_MIN_DEPOSIT { return Json(json!({"ok":false,"error":format!("minimum Lightning deposit is {LN_MIN_DEPOSIT} sats")})); }
    let (address, _spk) = match register_deposit_address(&s, account).await { Ok(x) => x, Err(e) => return Json(json!({"ok":false,"error":e})) };
    // per-invoice secret: identifies the invoice in the webhook AND authenticates it.
    let mut sb = [0u8; 32];
    if getrandom::getrandom(&mut sb).is_err() { return Json(json!({"ok":false,"error":"rng failure"})); }
    let secret = hex::encode(sb);
    let memo = format!("Cube Lotto deposit {}", &hex::encode(account)[..8]);
    let body = json!({ "invoice": { "amount": b.amount, "type": "lightning", "webhook": webhook, "secret": secret, "memo": memo } });
    let inv = match coinos_post(&s, "/invoice", body).await { Ok(v) => v, Err(e) => return Json(json!({"ok":false,"error":e})) };
    let bolt11 = inv["hash"].as_str().or_else(|| inv["text"].as_str()).unwrap_or_default().to_string();
    if bolt11.is_empty() { return Json(json!({"ok":false,"error":"invoice creation failed"})); }
    { s.ln_invoices.lock().await.insert(secret, LnInvoice { account, deposit_address: address.clone(), amount: b.amount, swapped: false }); }
    Json(json!({ "ok": true, "bolt11": bolt11, "amount": b.amount, "address": address }))
}

// Coinos invoice-paid webhook: authenticate by the per-invoice secret, then swap
// the received funds on-chain to the player's LiftV2 deposit address. Idempotent.
async fn post_ln_webhook(State(s): State<ArcadeState>, Json(b): Json<Value>) -> Json<Value> {
    let secret = b["secret"].as_str().unwrap_or_default().to_string();
    if secret.is_empty() { return Json(json!({"ok":false})); }
    let received = b["amount"].as_u64().unwrap_or_else(|| b["amount"].as_i64().unwrap_or(0).max(0) as u64);
    // claim the invoice (idempotent): mark swapped under the lock, copy what we need.
    let inv = {
        let mut m = s.ln_invoices.lock().await;
        match m.get_mut(&secret) {
            Some(i) if !i.swapped => { i.swapped = true; i.clone() }
            _ => return Json(json!({"ok":true})), // unknown/replayed: ack, do nothing
        }
    };
    let amount = if received > 0 { received } else { inv.amount };
    // Swap on-chain by sending from the dedicated lotto wallet straight to the
    // LiftV2 deposit address. We do this via OUR bitcoind RPC (a simple
    // sendtoaddress) rather than Coinos's /bitcoin/send, because the Mutinynet node
    // has no txindex and Coinos's send path calls getrawtransaction. The LN receipt
    // accrues in the lotto Coinos/CLN balance; the on-chain float (lotto wallet) is
    // the operator's swap liquidity (drained/refilled out of band).
    // helper: undo the idempotency claim so a webhook redelivery can retry.
    async fn revert(s: &ArcadeState, secret: &str) {
        if let Some(i) = s.ln_invoices.lock().await.get_mut(secret) { i.swapped = false; }
    }
    let addr = match bitcoin::Address::from_str(&inv.deposit_address) {
        Ok(a) => a.assume_checked(),
        Err(e) => { revert(&s, &secret).await; return Json(json!({"ok":false,"error":format!("bad deposit address: {e}")})); }
    };
    let wallet = std::env::var("COINOS_SWAP_WALLET").unwrap_or_else(|_| "lotto".to_string());
    let client = match Client::new(&format!("{}/wallet/{}", s.rpc_url.trim_end_matches('/'), wallet), Auth::UserPass(s.rpc_user.clone(), s.rpc_pass.clone())) {
        Ok(c) => c,
        Err(e) => { revert(&s, &secret).await; return Json(json!({"ok":false,"error":format!("swap wallet rpc: {e}")})); }
    };
    match client.send_to_address(&addr, bitcoin::Amount::from_sat(amount), None, None, None, None, None, None) {
        Ok(txid) => {
            eprintln!("ln-swap: sent {amount} sat on-chain to {} txid {txid}", inv.deposit_address);
            // Surface a pending status immediately (the deposit watcher reconciles
            // with the real mempool/confirmed values on its next cycle) so the LN
            // payer sees "incoming" right away, like an on-chain deposit.
            {
                let mut w = s.deposit_watch.lock().await;
                let e = w.entry(inv.account).or_default();
                if e.address.is_empty() { e.address = inv.deposit_address.clone(); }
                if e.pending_sats < amount { e.pending_sats = amount; }
                if e.txid.is_none() { e.txid = Some(txid.to_string()); }
            }
            s.notify();
            Json(json!({"ok":true,"txid":txid.to_string()}))
        }
        Err(e) => {
            eprintln!("ln-swap FAILED for {}: {e}", inv.deposit_address);
            revert(&s, &secret).await; // allow retry on a later webhook redelivery
            Json(json!({"ok":false,"error":format!("{e}")}))
        }
    }
}

// Derive a player's LiftV2 deposit address, register it for watching, and import
// it into the watch-only wallet so the deposit watcher detects funds sent to it.
// Returns (address, scriptpubkey_hex). Shared by /api/deposit_address and the
// Lightning-deposit swap (which sends the swapped on-chain funds to this address).
async fn register_deposit_address(s: &ArcadeState, account: [u8; 32]) -> Result<(String, String), String> {
    use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    // The LiftV2 taproot does point math on the account key and panics on a
    // non-curve x-only value — validate first so a bad key is a clean error.
    if bitcoin::secp256k1::XOnlyPublicKey::from_slice(&account).is_err() {
        return Err("invalid account key (not a valid x-only public key)".into());
    }
    let spk = return_liftv2_taproot(account, s.engine_key).and_then(|t| t.spk())
        .ok_or("could not derive deposit taproot")?;
    let network = match s.chain {
        Chain::Mainnet => bitcoin::Network::Bitcoin,
        Chain::Signet => bitcoin::Network::Signet,
        _ => bitcoin::Network::Regtest,
    };
    let script = bitcoin::ScriptBuf::from_bytes(spk.clone());
    let address = bitcoin::Address::from_script(script.as_script(), network)
        .map_err(|_| "address encode failed")?.to_string();
    {
        let mut w = s.deposit_watch.lock().await;
        let entry = w.entry(account).or_default();
        let first_time = entry.address.is_empty();
        entry.address = address.clone();
        entry.scriptpubkey = hex::encode(&spk);
        if first_time {
            let s2 = s.clone();
            let addr = address.clone();
            let label = hex::encode(account);
            // import off the request path (getdescriptorinfo + a small rescan).
            tokio::spawn(async move { tokio::task::spawn_blocking(move || s2.import_watch_address(&addr, &label)).await.ok(); });
        }
    }
    Ok((address, hex::encode(spk)))
}

// The LiftV2 deposit address for a player: a taproot {key-path MuSig2(account,
// engine); script-path CSV-3mo account sweep}. Funding it and lifting it in is how
// a player trustlessly puts real BTC into the pot covenant.
async fn get_deposit_address(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    let account = match params.get("account").and_then(|a| parse_hex::<32>(a)) {
        Some(a) => a,
        None => return Json(json!({ "error": "bad account" })),
    };
    match register_deposit_address(&s, account).await {
        Ok((address, spk)) => Json(json!({
            "account": hex::encode(account),
            "engine": hex::encode(s.engine_key),
            "address": address,
            "scriptpubkey": spk,
        })),
        Err(e) => Json(json!({ "error": e })),
    }
}

// Register a confirmed LiftV2 deposit UTXO (verify it exists on bitcoind and its
// spk matches LiftV2(account, engine)); queue it to join the pot covenant.
#[derive(Deserialize)]
struct DepositRegReq {
    account_key: String,
    txid: String,
    vout: u32,
}
async fn post_deposit(State(s): State<ArcadeState>, Json(b): Json<DepositRegReq>) -> Json<Value> {
    use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    let account = match parse_hex::<32>(&b.account_key) { Some(a) => a, None => return Json(json!({"ok":false,"error":"bad account"})) };
    let txid = match bitcoin::Txid::from_str(&b.txid) { Ok(t) => t, Err(_) => return Json(json!({"ok":false,"error":"bad txid"})) };
    let rpc = match s.rpc() { Some(r) => r, None => return Json(json!({"ok":false,"error":"rpc unavailable"})) };
    let txout = match rpc.get_tx_out(&txid, b.vout, Some(true)) {
        Ok(Some(o)) => o,
        Ok(None) => return Json(json!({"ok":false,"error":"utxo not found or already spent"})),
        Err(e) => return Json(json!({"ok":false,"error":format!("{e}")})),
    };
    let expected = match return_liftv2_taproot(account, s.engine_key).and_then(|t| t.spk()) {
        Some(spk) => spk,
        None => return Json(json!({"ok":false,"error":"taproot derive failed"})),
    };
    if txout.script_pub_key.hex != expected {
        return Json(json!({"ok":false,"error":"utxo spk does not match LiftV2(account, engine)"}));
    }
    let value = txout.value.to_sat();
    {
        let mut pd = s.pending_deposits.lock().await;
        if !pd.iter().any(|d| d.txid_internal == txid.to_byte_array() && d.vout == b.vout) {
            pd.push(PendingDeposit { account, txid_internal: txid.to_byte_array(), vout: b.vout, value });
        }
    }
    // Record it durably in the watch so the L2 credit (claim) works regardless of
    // when genesis spends the deposit — this explicit registration is reliable even
    // if the watch-wallet import hasn't caught up yet.
    {
        let mut w = s.deposit_watch.lock().await;
        let e = w.entry(account).or_default();
        if !e.seen.iter().any(|(t, v, _)| t == &b.txid && *v == b.vout) {
            e.seen.push((b.txid.clone(), b.vout, value));
        }
    }
    Json(json!({ "ok": true, "value": value, "pending": s.pending_deposits.lock().await.len() }))
}

// Claim confirmed deposits into the player's in-game (L2) balance so they can play.
// Authenticated by a schnorr signature from the account key (which the deposit
// address is derived from), so only the depositor can credit. Each deposit outpoint
// is credited at most once (persisted). The browser calls this automatically when
// it sees a claimable deposit, so it feels seamless. Backed by the pot covenant —
// the exit stays non-custodial.
#[derive(Deserialize)]
struct DepositClaimReq {
    account_key: String,
    bls_key: String,
    sig: String, // schnorr sig by account_key over (account_key ‖ bls_key)
}
async fn post_deposit_claim(State(s): State<ArcadeState>, Json(b): Json<DepositClaimReq>) -> Json<Value> {
    let (account_key, bls_key, sig) = match (parse_hex::<32>(&b.account_key), parse_hex::<48>(&b.bls_key), parse_hex::<64>(&b.sig)) {
        (Some(a), Some(k), Some(sg)) => (a, k, sg),
        _ => return Json(json!({"ok":false,"error":"bad params"})),
    };
    // Authenticate: schnorr by the account key over (account_key ‖ bls_key).
    let mut preimage = Vec::with_capacity(80);
    preimage.extend_from_slice(&account_key);
    preimage.extend_from_slice(&bls_key);
    let sighash = preimage.hash(Some(HashTag::CustomString("Cube/sighash/arcade/deposit-claim".to_string())));
    if !verify_xonly(account_key, sighash, sig, SchnorrSigningMode::BIP340) {
        return Json(json!({"ok":false,"error":"bad signature"}));
    }
    // Confirmed deposit UTXOs for this account, minus the already-credited ones.
    let utxos: Vec<(String, u32, u64)> = {
        match s.deposit_watch.lock().await.get(&account_key) { Some(d) => d.seen.clone(), None => Vec::new() }
    };
    let mut to_credit: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    {
        let credited = s.credited_deposits.lock().await;
        for (t, v, val) in &utxos {
            let key = format!("{t}:{v}");
            if !credited.contains(&key) { to_credit.push(key); total += *val; }
        }
    }
    if total == 0 {
        let balance = { s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0) };
        return Json(json!({"ok":true,"credited":0,"balance":balance}));
    }
    let _guard = s.exec_lock.lock().await;
    let now = Utc::now().timestamp() as u64;
    let already = { s.registery.lock().await.get_account_info_by_account_key(account_key).is_some() };
    if !already {
        let mut reg = s.registery.lock().await;
        let _ = reg.register_account(account_key, now, Some(bls_key), None, None, None);
        let _ = reg.apply_changes();
    }
    {
        let mut cm = s.coin_manager.lock().await;
        match cm.get_account_balance(account_key) {
            None => { let _ = cm.register_account(account_key, total); }
            Some(_) => { let _ = cm.account_balance_up(account_key, total); }
        }
        let _ = cm.apply_changes();
        if cm.get_shadow_alloc_value_in_satoshis(s.contract_id, account_key).is_none() {
            let _ = cm.contract_shadow_alloc_account(s.contract_id, account_key);
            let _ = cm.apply_changes();
        }
    }
    { let mut credited = s.credited_deposits.lock().await; for k in &to_credit { credited.insert(k.clone()); } }
    s.persist_credited().await;
    let (balance, reg_index) = {
        let bal = s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0);
        let idx = s.registery.lock().await.get_account_info_by_account_key(account_key).map(|(_, _, i, _)| i).unwrap_or(0);
        (bal, idx)
    };
    let _ = s.tx.send(());
    Json(json!({"ok":true,"credited":total,"balance":balance,"registery_index":reg_index}))
}

// Confirmations of an (unspent) output, via gettxout (no txindex needed). Used by
// the browser to wait for the TRUC v3 unroll to confirm before sweeping a leaf.
async fn get_txstatus(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    let txid = match params.get("txid") { Some(t) => t.clone(), None => return Json(json!({"confirmations": 0})) };
    let vout: u32 = params.get("vout").and_then(|v| v.parse().ok()).unwrap_or(0);
    let confs = s.rpc()
        .and_then(|c| c.call::<Value>("gettxout", &[json!(txid), json!(vout)]).ok())
        .and_then(|o| o.get("confirmations").and_then(|c| c.as_i64()))
        .unwrap_or(0);
    Json(json!({ "confirmations": confs }))
}

// The unilateral ESCAPE HATCH kit: the pre-signed unroll (broadcastable by anyone,
// no cosign) + this player's VTXO leaf (its CSV exit path). With this a player can
// force-exit to their own address with only their key — no operator, no other
// players. The CSV delay + self-paid fees are what discourage griefing.
async fn get_exit_kit(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    use cube::constructive::txout_types::timeout_tree::TimeoutTree;
    let account = match params.get("account").and_then(|a| parse_hex::<32>(a)) { Some(a) => a, None => return Json(json!({"ok":false,"error":"bad account"})) };
    let cov = match s.covenant.current().await { Some(c) => c, None => return Json(json!({"ok":false,"error":"no on-chain pot to exit"})) };
    let snap = s.covenant.snapshot().await;
    let unroll = match snap.unroll { Some(u) if u.covenant_txid == cov.txid => u, _ => return Json(json!({"ok":false,"error":"no pre-signed unroll for the current pot yet"})) };
    let mut allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    allocs.sort_by(|a, b| a.0.cmp(&b.0));
    let tree = match TimeoutTree::build(s.engine_key, &allocs, cov.expiry, COVENANT_EXIT_DELAY, None) { Some(t) => t, None => return Json(json!({"ok":false,"error":"tree build failed"})) };
    let leaf_idx = match tree.leaves.iter().position(|l| l.account_key == account) { Some(i) => i, None => return Json(json!({"ok":false,"error":"you have no leaf in the pot"})) };
    let leaf = &tree.leaves[leaf_idx];
    let spk = leaf.scriptpubkey().unwrap_or_default();
    let (_lh, script, cb) = leaf.exit_spend_elements().unwrap_or_default();
    // the precise on-chain leaf value (the unroll is self-funded — the last leaf
    // is reduced by the baked fee, so read the actual vout value off the tx).
    let leaf_value = s.rpc()
        .and_then(|c| c.call::<Value>("decoderawtransaction", &[json!(unroll.unroll_tx_hex)]).ok())
        .and_then(|d| d["vout"].as_array().and_then(|o| o.get(leaf_idx)).and_then(|o| o["value"].as_f64()))
        .map(|btc| (btc * 1e8).round() as u64)
        .unwrap_or(leaf.value_in_satoshis);
    Json(json!({
        "ok": true,
        "unroll_tx_hex": unroll.unroll_tx_hex,
        "unroll_txid": unroll.unroll_txid,
        // public broadcaster for an operator-gone exit (None on regtest).
        "mempool_api": mempool_api(&s),
        // a baked sweep fee for the offline standalone tool (best-effort; live
        // clients re-fetch /api/feerate instead).
        "exit_sweep_fee": s.estimate_fee(exit_sweep_vsize()),
        "leaf": {
            "vout": leaf_idx,
            "value": leaf_value,
            "scriptpubkey": hex::encode(spk),
            "exit_script": hex::encode(script),
            "control_block": hex::encode(cb),
            "exit_delay": COVENANT_EXIT_DELAY,
        },
    }))
}

// Current fee conditions, for clients that build their own txs (the unilateral
// exit / dispute sweep): the node's sat/vB estimate + a ready-to-use sweep fee.
async fn get_feerate(State(s): State<ArcadeState>) -> Json<Value> {
    Json(json!({
        "sat_vb": s.fee_rate_sat_vb(),
        "exit_sweep_fee": s.estimate_fee(exit_sweep_vsize()),
    }))
}

// GENESIS core: combine queued deposits from currently-connected depositors into
// the pot covenant via N-of-N cosign, broadcast it, and record the covenant.
// Returns (txid, covenant_value, participants). Shared by the manual endpoint and
// the auto-genesis loop. Offline/abandoned deposits are skipped (they'd block it).
async fn do_genesis(s: &ArcadeState) -> Result<(String, u64, usize), String> {
    let all_deposits = { s.pending_deposits.lock().await.clone() };
    if all_deposits.is_empty() { return Err("no pending deposits".into()); }
    if s.covenant.current().await.is_some() { return Err("covenant exists; use refresh to add".into()); }
    let connected: std::collections::HashSet<[u8; 32]> = s.cosign_hub.connected().await.into_iter().collect();
    let deposits: Vec<PendingDeposit> = all_deposits.into_iter().filter(|d| connected.contains(&d.account)).collect();
    if deposits.is_empty() { return Err("no connected depositors online to form the covenant — keep the tab open".into()); }
    let gdeposits: Vec<cosign::GenesisDeposit> = deposits.iter().map(|d| cosign::GenesisDeposit {
        account_key: d.account, prev_txid: d.txid_internal, prev_vout: d.vout, prev_value: d.value,
    }).collect();
    // Merge allocations by account: an account may fund the pot with several
    // deposits, but the covenant must hold exactly ONE leaf per account. Duplicate
    // (key,value) leaves would force a single cosign client to represent two
    // projected identities in one MuSig2 session — which it can't — so any later
    // refresh/withdraw would hang collecting partials. Inputs stay per-deposit;
    // only the output allocation ledger is consolidated.
    let mut allocs: Vec<([u8; 32], u64)> = Vec::new();
    for d in &deposits {
        match allocs.iter_mut().find(|(a, _)| a == &d.account) {
            Some(e) => e.1 += d.value,
            None => allocs.push((d.account, d.value)),
        }
    }
    let fee = s.estimate_fee(genesis_vsize(deposits.len() as u64));
    if let Some(max) = allocs.iter_mut().max_by_key(|(_, v)| *v) { max.1 = max.1.saturating_sub(fee); }
    let tip = { s.sync_manager.lock().await.bitcoin_sync_height_tip() };
    let expiry = (tip + COVENANT_EXPIRY_WINDOW) as u32;
    let res = s.cosign_hub.run_genesis(gdeposits, allocs.clone(), expiry, fee, std::time::Duration::from_secs(30)).await?;
    let txid = s.broadcast(&res.signed_tx_hex).map_err(|e| format!("broadcast: {e}"))?;
    s.mine(1);
    let mut canonical = allocs.clone();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let cov_value: u64 = canonical.iter().map(|(_, v)| v).sum();
    let alloc_pairs: Vec<(String, u64)> = canonical.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let _ = s.covenant.update(|st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: txid.clone(), vout: 0, value: cov_value, allocations: alloc_pairs, expiry });
        st.unroll = None;
        st.last_settle = None; // a fresh pot — any prior settle's cash-out is stale
    }).await;
    { s.pending_deposits.lock().await.clear(); }
    // Pre-sign the unroll now (everyone's online) so each player holds the trustless
    // escape hatch — they can force-exit their leaf later with no one's cooperation.
    presign_unroll(s, &txid, 0, cov_value, &canonical, expiry).await;
    s.notify();
    Ok((txid, cov_value, canonical.len()))
}

// Absorb pending deposits into the EXISTING covenant (a "join"): spend [covenant +
// each new deposit] into one bigger covenant that includes the new depositors, so
// post-genesis deposits become covenant-backed (otherwise they sit at separate
// LiftV2 addresses, the covenant decouples from the ledger, and the settle reconcile
// can't attribute winnings to them). Requires every OLD covenant member online
// (input 0 is N-of-N) plus the new depositors; skips otherwise.
async fn do_join(s: &ArcadeState) -> Result<(String, u64, usize), String> {
    let cov = match s.covenant.current().await { Some(c) => c, None => return Err("no covenant; use genesis".into()) };
    let all_deposits = { s.pending_deposits.lock().await.clone() };
    if all_deposits.is_empty() { return Err("no pending deposits".into()); }
    let connected: std::collections::HashSet<[u8; 32]> = s.cosign_hub.connected().await.into_iter().collect();
    // input 0 (the covenant) is N-of-N — every current member must be online to cosign.
    let old_allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    for (m, _) in &old_allocs {
        if !connected.contains(m) { return Err(format!("covenant member {} offline — can't absorb yet", &hex::encode(m)[..12])); }
    }
    // only absorb deposits whose depositor is online (they must cosign their input).
    let deposits: Vec<PendingDeposit> = all_deposits.iter().filter(|d| connected.contains(&d.account)).cloned().collect();
    if deposits.is_empty() { return Err("no connected depositors to absorb".into()); }
    let gdeposits: Vec<cosign::GenesisDeposit> = deposits.iter().map(|d| cosign::GenesisDeposit {
        account_key: d.account, prev_txid: d.txid_internal, prev_vout: d.vout, prev_value: d.value,
    }).collect();
    // new allocations = old members + each new deposit (merged by account).
    let mut new_allocs: Vec<([u8; 32], u64)> = old_allocs.clone();
    for d in &deposits {
        match new_allocs.iter_mut().find(|(a, _)| a == &d.account) {
            Some(e) => e.1 += d.value,
            None => new_allocs.push((d.account, d.value)),
        }
    }
    // fee (covenant input + N deposit inputs + one covenant output) off the largest.
    let fee = s.estimate_fee(genesis_vsize(deposits.len() as u64 + 1));
    if let Some(max) = new_allocs.iter_mut().max_by_key(|(_, v)| *v) { max.1 = max.1.saturating_sub(fee); }
    let prev_txid = match bitcoin::Txid::from_str(&cov.txid) { Ok(t) => t.to_byte_array(), Err(_) => return Err("bad covenant txid".into()) };
    let res = s.cosign_hub.run_join(old_allocs, cov.expiry, prev_txid, cov.vout, cov.value, gdeposits, new_allocs.clone(), cov.expiry, fee, std::time::Duration::from_secs(30)).await?;
    let txid = s.broadcast(&res.signed_tx_hex).map_err(|e| format!("broadcast: {e}"))?;
    s.mine(1);
    let mut canonical = new_allocs.clone();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let cov_value: u64 = canonical.iter().map(|(_, v)| v).sum();
    let alloc_pairs: Vec<(String, u64)> = canonical.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let expiry = cov.expiry;
    let st_txid = txid.clone();
    let _ = s.covenant.update(move |st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: st_txid, vout: 0, value: cov_value, allocations: alloc_pairs, expiry });
        st.unroll = None;
        st.last_settle = None;
    }).await;
    // drop the absorbed deposits from the pending queue (offline ones stay for later).
    { let absorbed: std::collections::HashSet<_> = deposits.iter().map(|d| (d.txid_internal, d.vout)).collect();
      s.pending_deposits.lock().await.retain(|d| !absorbed.contains(&(d.txid_internal, d.vout))); }
    presign_unroll(s, &txid, 0, cov_value, &canonical, expiry).await;
    s.notify();
    Ok((txid, cov_value, canonical.len()))
}

// EPOCH REFORM: the liveness-independent version of do_join. Once the covenant is at
// or past its CLTV expiry, the engine reforms it via the expiry script path (no
// member cosign) — carrying every existing claim into a fresh covenant + absorbing
// online deposits + setting a new expiry. This is what stops an offline/abandoned
// member from deadlocking new joins forever: cooperative do_join is tried first; if
// it can't run (someone offline) and the covenant has reached expiry, this takes
// over. Only the new depositors need to be online (they cosign their own inputs).
async fn do_epoch_reform(s: &ArcadeState) -> Result<(String, u64, usize), String> {
    let cov = match s.covenant.current().await { Some(c) => c, None => return Err("no covenant".into()) };
    let tip = { s.sync_manager.lock().await.bitcoin_sync_height_tip() };
    if (tip as u32) < cov.expiry {
        return Err(format!("covenant not at expiry yet (tip {} < expiry {})", tip, cov.expiry));
    }
    let all_deposits = { s.pending_deposits.lock().await.clone() };
    let connected: std::collections::HashSet<[u8; 32]> = s.cosign_hub.connected().await.into_iter().collect();
    // only depositors who are online (they must cosign their own deposit inputs).
    let deposits: Vec<PendingDeposit> = all_deposits.iter().filter(|d| connected.contains(&d.account)).cloned().collect();
    let gdeposits: Vec<cosign::GenesisDeposit> = deposits.iter().map(|d| cosign::GenesisDeposit {
        account_key: d.account, prev_txid: d.txid_internal, prev_vout: d.vout, prev_value: d.value,
    }).collect();
    // carry every existing claim, merge in the new deposits.
    let old_allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    let mut new_allocs: Vec<([u8; 32], u64)> = old_allocs.clone();
    for d in &deposits {
        match new_allocs.iter_mut().find(|(a, _)| a == &d.account) { Some(e) => e.1 += d.value, None => new_allocs.push((d.account, d.value)) }
    }
    let new_expiry = (tip + COVENANT_EXPIRY_WINDOW) as u32;
    let fee = s.estimate_fee(genesis_vsize(deposits.len() as u64 + 1));
    if let Some(max) = new_allocs.iter_mut().max_by_key(|(_, v)| *v) { max.1 = max.1.saturating_sub(fee); }
    let prev_txid = match bitcoin::Txid::from_str(&cov.txid) { Ok(t) => t.to_byte_array(), Err(_) => return Err("bad covenant txid".into()) };
    let res = s.cosign_hub.run_epoch_reform(old_allocs, cov.expiry, prev_txid, cov.vout, cov.value, gdeposits, new_allocs.clone(), new_expiry, fee, std::time::Duration::from_secs(30)).await?;
    let txid = s.broadcast(&res.signed_tx_hex).map_err(|e| format!("broadcast: {e}"))?;
    s.mine(1);
    let mut canonical = new_allocs.clone();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let cov_value: u64 = canonical.iter().map(|(_, v)| v).sum();
    let alloc_pairs: Vec<(String, u64)> = canonical.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let st_txid = txid.clone();
    let _ = s.covenant.update(move |st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: st_txid, vout: 0, value: cov_value, allocations: alloc_pairs, expiry: new_expiry });
        st.unroll = None;
        st.last_settle = None;
    }).await;
    { let absorbed: std::collections::HashSet<_> = deposits.iter().map(|d| (d.txid_internal, d.vout)).collect();
      s.pending_deposits.lock().await.retain(|d| !absorbed.contains(&(d.txid_internal, d.vout))); }
    presign_unroll(s, &txid, 0, cov_value, &canonical, new_expiry).await;
    s.notify();
    Ok((txid, cov_value, canonical.len()))
}

// Pre-sign (N-of-N) the covenant's unroll and store it, so any participant can
// later broadcast it and unilaterally exit their VTXO leaf with only their key.
// Best-effort: if cosign can't complete (someone offline), the unroll is just
// absent until the next refresh — the cooperative path still works.
async fn presign_unroll(s: &ArcadeState, cov_txid: &str, cov_vout: u32, cov_value: u64, allocs: &[([u8; 32], u64)], expiry: u32) {
    let txid_internal = match bitcoin::Txid::from_str(cov_txid) { Ok(t) => t.to_byte_array(), Err(_) => return };
    let mut canon = allocs.to_vec();
    canon.sort_by(|a, b| a.0.cmp(&b.0));
    let fee = s.estimate_fee(unroll_vsize(canon.len() as u64));
    if let Ok(u) = s.cosign_hub.run_unroll(canon, expiry, txid_internal, cov_vout, cov_value, COVENANT_EXIT_DELAY, fee, None, None, std::time::Duration::from_secs(30)).await {
        let cov_txid = cov_txid.to_string();
        let _ = s.covenant.update(|st| {
            st.unroll = Some(covenant_manager::PreSignedUnroll { covenant_txid: cov_txid, unroll_txid: u.txid, unroll_tx_hex: u.signed_tx_hex });
        }).await;
    }
}

async fn post_genesis(State(s): State<ArcadeState>) -> Json<Value> {
    match do_genesis(&s).await {
        Ok((txid, cov_value, participants)) => Json(json!({ "ok": true, "txid": txid, "covenant_value": cov_value, "participants": participants })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

// REFRESH: move the pot covenant to a new allocation state (default: mirror the
// current one) via N-of-N cosign, broadcast, then pre-sign the new unroll.
#[derive(Deserialize)]
struct AllocIn { account: String, value: u64 }
#[derive(Deserialize)]
struct RefreshReq {
    #[serde(default)]
    new_allocations: Option<Vec<AllocIn>>,
}
async fn post_refresh(State(s): State<ArcadeState>, Json(b): Json<RefreshReq>) -> Json<Value> {
    let cov = match s.covenant.current().await { Some(c) => c, None => return Json(json!({"ok":false,"error":"no covenant"})) };
    let old_allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    let old_txid_internal = match bitcoin::Txid::from_str(&cov.txid) { Ok(t) => t.to_byte_array(), Err(_) => return Json(json!({"ok":false,"error":"bad covenant txid"})) };
    let mut new_allocs: Vec<([u8; 32], u64)> = match &b.new_allocations {
        Some(v) => v.iter().filter_map(|a| parse_hex::<32>(&a.account).map(|k| (k, a.value))).collect(),
        None => old_allocs.clone(),
    };
    if new_allocs.is_empty() { return Json(json!({"ok":false,"error":"empty new allocations"})); }
    let refresh_fee = s.estimate_fee(refresh_vsize());
    let unroll_fee = s.estimate_fee(unroll_vsize(new_allocs.len() as u64));
    if let Some(max) = new_allocs.iter_mut().max_by_key(|(_, v)| *v) { max.1 = max.1.saturating_sub(refresh_fee); }
    let new_expiry = cov.expiry;
    let params = cosign::RefreshParams {
        old_allocations: old_allocs, old_expiry: cov.expiry, new_allocations: new_allocs.clone(),
        new_expiry, prev_txid: old_txid_internal, prev_vout: cov.vout, prev_value: cov.value,
        fee: refresh_fee, override_out_spk: None, payout: None,
    };
    let res = match s.cosign_hub.run_refresh(params, "arcade-refresh", std::time::Duration::from_secs(30)).await {
        Ok(r) => r, Err(e) => return Json(json!({"ok":false,"error":e})),
    };
    let refresh_txid = match s.broadcast(&res.signed_tx_hex) { Ok(t) => t, Err(e) => return Json(json!({"ok":false,"error":format!("broadcast: {e}")})) };
    s.mine(1);
    let mut canonical = new_allocs.clone();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let new_value: u64 = canonical.iter().map(|(_, v)| v).sum();
    let alloc_pairs: Vec<(String, u64)> = canonical.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let new_txid_internal = match bitcoin::Txid::from_str(&refresh_txid) { Ok(t) => t.to_byte_array(), Err(_) => return Json(json!({"ok":false,"error":"bad refresh txid"})) };
    let unroll = match s.cosign_hub.run_unroll(canonical.clone(), new_expiry, new_txid_internal, 0, new_value, COVENANT_EXIT_DELAY, unroll_fee, None, None, std::time::Duration::from_secs(30)).await {
        Ok(u) => u, Err(e) => return Json(json!({"ok":false,"error":format!("unroll presign: {e}")})),
    };
    let _ = s.covenant.update(|st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: refresh_txid.clone(), vout: 0, value: new_value, allocations: alloc_pairs, expiry: new_expiry });
        st.unroll = Some(covenant_manager::PreSignedUnroll { covenant_txid: refresh_txid.clone(), unroll_txid: unroll.txid.clone(), unroll_tx_hex: unroll.signed_tx_hex.clone() });
        st.last_settle = None;
    }).await;
    s.notify();
    Json(json!({
        "ok": true, "refresh_txid": refresh_txid, "covenant_value": new_value,
        "unroll_txid": unroll.txid,
        "leaves": serde_json::to_value(&unroll.leaves).unwrap_or(Value::Null),
    }))
}

// Broadcast the pre-signed unroll (covenant -> VTXO leaves) — the cooperative or
// forced exit path. After this, each holder unilaterally sweeps its leaf.
async fn post_unroll(State(s): State<ArcadeState>) -> Json<Value> {
    let snap = s.covenant.snapshot().await;
    let unroll = match snap.unroll { Some(u) => u, None => return Json(json!({"ok":false,"error":"no pre-signed unroll"})) };
    let txid = match s.smart_broadcast(&unroll.unroll_tx_hex) { Ok(t) => t, Err(e) => return Json(json!({"ok":false,"error":format!("broadcast: {e}")})) };
    s.mine(1);
    Json(json!({ "ok": true, "unroll_txid": txid }))
}

// ENFORCED SETTLE: the engine asserts the round winner over the pot covenant and
// publishes a garbled fraud-proof (BitVM3/ZKTLC). Bands = the covenant stakes; the
// draw rg = seed mod space (house multiplier ODDS_DENOM). Returns a SettleAssertion
// a challenger can verify off-chain: an HONEST winner yields no disprove secret; a
// WRONG winner (set `winner` to force the demo's cheat) hands the challenger the
// secret that opens the contested leaf's disprove lock. `disprove_hash` is what the
// contested covenant leaf must commit to enforce this settle.
#[derive(Deserialize)]
struct SettleAssertReq {
    #[serde(default)]
    winner: Option<u32>, // force a (possibly wrong) winner for the demo; else honest
    #[serde(default)]
    seed: Option<u64>, // override the draw seed; else derived from the best block hash
}
async fn post_settle_assertion(State(s): State<ArcadeState>, Json(b): Json<SettleAssertReq>) -> Json<Value> {
    use cube::transmutative::garble::WinnerVerifier;
    let cov = match s.covenant.current().await {
        Some(c) => c,
        None => return Json(json!({"ok":false,"error":"no covenant to settle"})),
    };
    let stakes: Vec<u64> = cov.allocations.iter().map(|(_, v)| *v).collect();
    if stakes.is_empty() {
        return Json(json!({"ok":false,"error":"covenant has no stakes"}));
    }
    let (mut lo, mut hi, mut acc) = (Vec::new(), Vec::new(), 0u64);
    for v in &stakes {
        lo.push(acc);
        acc += v;
        hi.push(acc);
    }
    let total = acc;
    let space = total.saturating_mul(ODDS_DENOM + 1).max(1);
    let seed = b.seed.unwrap_or_else(|| {
        let h = s.best_block_hash();
        u64::from_le_bytes(h[0..8].try_into().unwrap())
    });
    let rg = seed % space;
    let honest_winner = (0..stakes.len()).find(|&i| lo[i] <= rg && rg < hi[i]).map(|i| i as u32);
    let claimed = match b.winner.or(honest_winner) {
        Some(w) => w,
        None => return Json(json!({"ok":false,"error":"draw landed in the house zone (rollover) — try another seed","rg":rg,"total":total})),
    };
    let v = WinnerVerifier::new(&lo, &hi);
    let wires = v.wires(seed ^ 0x5a5a_5a5a_5a5a_5a5a);
    let tables = v.garble(&wires);
    let assertion = v.assert_settle(&wires, &tables, rg, claimed);
    let accounts: Vec<String> = cov.allocations.iter().map(|(a, _)| a.clone()).collect();
    Json(json!({
        "ok": true,
        "rg": rg, "total": total, "space": space,
        "honest_winner": honest_winner,
        "claimed_winner": claimed,
        "is_honest": Some(claimed) == honest_winner,
        "engine_key": hex::encode(s.engine_key),
        "expiry": cov.expiry,
        "exit_delay": COVENANT_EXIT_DELAY,
        "accounts": accounts,
        "stakes": stakes,
        "disprove_hash": hex::encode(assertion.disprove_hash),
        "gate_count": v.gate_count(),
        "assertion": assertion,
    }))
}

// Broadcast relay: a challenger's browser can't reach bitcoind directly, so it
// POSTs a fully-signed tx here to be relayed. The engine is only a relay — it can't
// alter a signed tx — so this is safe even though the engine is the adversary in a
// dispute (in production the browser would use its own node / a public broadcaster).
#[derive(Deserialize)]
struct BroadcastReq {
    tx_hex: String,
}
async fn post_broadcast(State(s): State<ArcadeState>, Json(b): Json<BroadcastReq>) -> Json<Value> {
    // smart_broadcast auto-CPFPs a feeless v3+P2A parent (the pre-signed unroll)
    // via package relay, so a browser/watchtower can broadcast it with no wallet.
    match s.smart_broadcast(&b.tx_hex) {
        Ok(txid) => Json(json!({ "ok": true, "txid": txid })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

// ENFORCED SETTLE on-chain: assert the round winner AND pre-sign the covenant's
// unroll with every leaf carrying THIS round's disprove lock (the garbled "invalid"
// label hash). Optimistic: the unroll isn't broadcast unless disputed — but once
// it is, each holder's real on-chain VTXO leaf is reclaimable via its disprove path
// iff the engine asserted a wrong winner. Needs the participants connected to
// /cosign (the unroll is an N-of-N covenant spend). Returns the assertion + the
// pre-signed disprove-locked unroll + per-leaf spend data.
async fn post_settle(State(s): State<ArcadeState>, Json(b): Json<SettleAssertReq>) -> Json<Value> {
    use cube::transmutative::garble::{fiat_shamir_open, InstanceCommit, WinnerVerifier};
    let cov = match s.covenant.current().await {
        Some(c) => c,
        None => return Json(json!({"ok":false,"error":"no covenant to settle"})),
    };
    let allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    if allocs.is_empty() {
        return Json(json!({"ok":false,"error":"covenant has no stakes"}));
    }
    let (mut lo, mut hi, mut acc) = (Vec::new(), Vec::new(), 0u64);
    for (_, v) in &allocs {
        lo.push(acc);
        acc += v;
        hi.push(acc);
    }
    let total = acc;
    let space = total.saturating_mul(ODDS_DENOM + 1).max(1);
    let seed = b.seed.unwrap_or_else(|| u64::from_le_bytes(s.best_block_hash()[0..8].try_into().unwrap()));
    let rg = seed % space;
    let honest_winner = (0..allocs.len()).find(|&i| lo[i] <= rg && rg < hi[i]).map(|i| i as u32);
    let claimed = match b.winner.or(honest_winner) {
        Some(w) => w,
        None => return Json(json!({"ok":false,"error":"draw landed in the house zone (rollover)","rg":rg,"total":total})),
    };
    // CUT-AND-CHOOSE: garble K independent instances and commit them; a Fiat-Shamir
    // challenge (from the commitments) opens half — those are revealed so the
    // challenger re-garbles + checks them — and the settle uses an UNOPENED instance.
    // A dishonest garbler (e.g. a disprove lock that can never open) is caught with
    // overwhelming probability, forcing honest garbling.
    let v = WinnerVerifier::new(&lo, &hi);
    const K: usize = 8;
    let mut all_wires = Vec::with_capacity(K);
    let mut all_tables = Vec::with_capacity(K);
    let mut commits = Vec::with_capacity(K);
    for i in 0..K {
        let wires = v.wires(seed ^ (0x00c0_ffee_0000_0000u64 + i as u64));
        let tables = v.garble(&wires);
        commits.push(InstanceCommit { tables_commit: v.tables_commit(&tables), disprove_hash: v.disprove_hash(&wires), valid_hash: v.valid_hash(&wires) });
        all_wires.push(wires);
        all_tables.push(tables);
    }
    let opened = fiat_shamir_open(&commits, K);
    let settle_idx = match (0..K).find(|&i| !opened[i]) {
        Some(i) => i,
        None => return Json(json!({"ok":false,"error":"cut-and-choose opened every instance; retry"})),
    };
    let assertion = v.assert_settle(&all_wires[settle_idx], &all_tables[settle_idx], rg, claimed);
    let disprove_hash = assertion.disprove_hash;
    // The winner-sweep lock for this round: the garbled VALID-label hash, plus the
    // claimed winner's account key. On an HONEST settle the winner derives the valid
    // label by evaluating the circuit and sweeps every loser leaf — no cooperation.
    // (allocs is account-sorted, matching the bands and run_unroll's leaf order, so
    // allocs[claimed] is exactly the won leaf.)
    let valid_hash = assertion.valid_hash;
    let winner_key = allocs[claimed as usize].0;
    let instances: Vec<Value> = (0..K)
        .map(|i| json!({
            "tables_commit": hex::encode(commits[i].tables_commit),
            "disprove_hash": hex::encode(commits[i].disprove_hash),
            "valid_hash": hex::encode(commits[i].valid_hash),
            "opened": opened[i],
            "wires": if opened[i] { serde_json::to_value(&all_wires[i]).ok() } else { None },
        }))
        .collect();

    // Pre-sign the covenant's unroll with every leaf locked to this round.
    let prev_txid_internal = match bitcoin::Txid::from_str(&cov.txid) {
        Ok(t) => t.to_byte_array(),
        Err(_) => return Json(json!({"ok":false,"error":"bad covenant txid"})),
    };
    let settle_unroll_fee = s.estimate_fee(unroll_vsize(allocs.len() as u64));
    let unroll = match s
        .cosign_hub
        .run_unroll(allocs.clone(), cov.expiry, prev_txid_internal, cov.vout, cov.value, COVENANT_EXIT_DELAY, settle_unroll_fee, Some(disprove_hash), Some((winner_key, valid_hash)), std::time::Duration::from_secs(30))
        .await
    {
        Ok(u) => u,
        Err(e) => return Json(json!({"ok":false,"error":format!("unroll pre-sign: {e}")})),
    };
    // The winner's cash-out secret: the garbled VALID label of the settle instance.
    // Only the winner's key can spend with it, so persisting it is safe; it lets the
    // winner fetch + execute their winner-sweep later via /api/winnings.
    let valid_label_hex = hex::encode(v.valid_label(&all_wires[settle_idx]));
    let settle_leaves: Vec<covenant_manager::SettleLeaf> = unroll.leaves.iter().map(|l| covenant_manager::SettleLeaf {
        account: l.account.clone(), value: l.value, vout: l.vout, scriptpubkey: l.scriptpubkey.clone(),
        exit_script: l.exit_script.clone(), exit_control_block: l.control_block.clone(), exit_delay: l.exit_delay,
        winner_sweep_script: l.winner_sweep_script.clone(), winner_sweep_control_block: l.winner_sweep_control_block.clone(),
        disprove_script: l.disprove_script.clone(), disprove_control_block: l.disprove_control_block.clone(),
    }).collect();
    let bundle = covenant_manager::SettleBundle {
        covenant_txid: cov.txid.clone(), winner_key: hex::encode(winner_key), valid_label: valid_label_hex,
        rg, total, unroll_txid: unroll.txid.clone(), unroll_tx_hex: unroll.signed_tx_hex.clone(),
        leaves: settle_leaves,
    };
    let _ = s.covenant.update(|st| {
        st.unroll = Some(covenant_manager::PreSignedUnroll {
            covenant_txid: cov.txid.clone(),
            unroll_txid: unroll.txid.clone(),
            unroll_tx_hex: unroll.signed_tx_hex.clone(),
        });
        st.last_settle = Some(bundle);
    }).await;
    s.notify();
    Json(json!({
        "ok": true,
        "rg": rg, "total": total, "honest_winner": honest_winner, "claimed_winner": claimed,
        "is_honest": Some(claimed) == honest_winner,
        "engine_key": hex::encode(s.engine_key),
        "expiry": cov.expiry, "exit_delay": COVENANT_EXIT_DELAY,
        "disprove_hash": hex::encode(disprove_hash),
        // winner-sweep: the claimed winner + the round's VALID-label hash. The
        // winner derives the valid label (winner_label over the assertion) and
        // sweeps each loser leaf (those leaves carry winner_sweep_* in `leaves`).
        "valid_hash": hex::encode(valid_hash),
        "winner_key": hex::encode(winner_key),
        "k": K, "settle_instance": settle_idx, "instances": instances,
        "unroll_txid": unroll.txid,
        "unroll_tx_hex": unroll.signed_tx_hex,
        "leaves": serde_json::to_value(&unroll.leaves).unwrap_or(Value::Null),
        "assertion": assertion,
    }))
}

// A WIN's winner-sweep cash-out bundle, persisted at settle so the winner can claim
// any time (not just from the live /api/settle response). For the winner it returns:
// the pre-signed unroll to broadcast, the VALID label (the sweep secret — only the
// winner's key can spend with it), each LOSER leaf's winner-sweep spend elements,
// and the winner's OWN leaf's CSV-exit elements. The winner broadcasts the unroll,
// sweeps every loser leaf, and CSV-exits its own leaf — taking the whole pot on-chain
// with NO cooperation. This is the non-custodial "withdraw my winnings": the covenant
// shadow ledger zeroes claims on a win, so winnings live in the settle bundle, not as
// a live covenant allocation. (The cooperative covenant reconcile is intentionally
// NOT used — it would force losers to surrender disprove-protected claims.)
async fn get_winnings(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    let st = s.covenant.snapshot().await;
    let bundle = match st.last_settle {
        Some(b) => b,
        None => return Json(json!({ "winnings": false, "note": "no recent win to claim" })),
    };
    // Only valid while the settle's unroll still spends the CURRENT covenant; once the
    // pot moves (a new genesis/refresh), the bundle is stale.
    let current_txid = st.covenant.as_ref().map(|c| c.txid.as_str());
    if current_txid != Some(bundle.covenant_txid.as_str()) {
        return Json(json!({ "winnings": false, "note": "the pot has moved since this settle" }));
    }
    let acct = match params.get("account") {
        Some(a) => a.to_lowercase(),
        None => return Json(json!({ "error": "bad account" })),
    };
    let winner = bundle.winner_key.to_lowercase();
    if acct != winner {
        return Json(json!({ "winnings": false, "you_won": false, "note": "not the winner of the last round" }));
    }
    // the winner: every LOSER leaf is sweepable with the valid label + the winner's key.
    let sweep_leaves: Vec<Value> = bundle.leaves.iter()
        .filter(|l| l.account.to_lowercase() != winner)
        .map(|l| json!({
            "account": l.account, "value": l.value, "vout": l.vout, "scriptpubkey": l.scriptpubkey,
            "winner_sweep_script": l.winner_sweep_script,
            "winner_sweep_control_block": l.winner_sweep_control_block,
        }))
        .collect();
    // the winner's OWN leaf is taken via the CSV exit path (their key, after the delay).
    let own_leaf = bundle.leaves.iter().find(|l| l.account.to_lowercase() == winner).map(|l| json!({
        "value": l.value, "vout": l.vout, "scriptpubkey": l.scriptpubkey,
        "exit_script": l.exit_script, "exit_control_block": l.exit_control_block, "exit_delay": l.exit_delay,
    }));
    Json(json!({
        "winnings": true, "you_won": true,
        "pot": bundle.total, "rg": bundle.rg, "winner_key": bundle.winner_key,
        "valid_label": bundle.valid_label,
        "unroll_txid": bundle.unroll_txid, "unroll_tx_hex": bundle.unroll_tx_hex,
        "own_leaf": own_leaf,
        "sweep_leaves": sweep_leaves,
        "note": "broadcast unroll_tx_hex, then spend each sweep_leaf with [your_sig, valid_label, winner_sweep_script, winner_sweep_control_block]; take your own_leaf via its CSV exit path after exit_delay.",
    }))
}

// The current on-chain pot covenant pointer (Phase 0: read-only view; populated
// by deposits/refresh in Phase 1). Lets the UI + watchtower see the live covenant
// and its pre-signed unroll.
async fn get_covenant(State(s): State<ArcadeState>) -> Json<Value> {
    let st = s.covenant.snapshot().await;
    Json(json!({
        "covenant": st.covenant,
        "unroll_present": st.unroll.is_some(),
        "pending_refresh_txid": st.pending_refresh_txid,
        "cosign_connected": s.cosign_hub.connected().await.len(),
    }))
}

// Withdraw an account's in-game balance to an arbitrary regtest address. This is
// a custodial bridge: we verify the owner's BLS signature, debit the L2 balance,
// and pay the equivalent on-chain from the engine's bitcoind wallet.
#[derive(Deserialize)]
struct WithdrawReq {
    account_key: String,
    bls_key: String,
    address: String,
    amount: u64,
    bls_signature: String,
}
// NON-CUSTODIAL withdraw: a cooperative covenant refresh that pays the player's
// not-in-play balance straight to their own Bitcoin address and re-pools the rest.
// Nothing leaves the operator wallet — the funds are the player's own on-chain
// claim, released by an N-of-N cosign of the current pot members (each verifies the
// tx before signing). Capped at the player's on-chain claim (winnings beyond it
// need a settle, not yet wired). Authorized by the player's BLS signature.
// Withdraw an UN-POOLED balance: the player deposited but hasn't been absorbed into
// the covenant yet (join blocked by an offline member, or reform not due). Their
// funds still sit at their 2-of-2 LiftV2 deposit address — spend those UTXOs
// straight to `dest_spk` with just the depositor's cosign. Only offered when the L2
// balance fully backs the deposits (no gameplay loss owed to the pot); otherwise the
// surplus belongs to the pot and the funds must be pooled (joined/reformed) first.
async fn withdraw_from_deposits(s: &ArcadeState, account_key: [u8; 32], dest_spk: &[u8]) -> Json<Value> {
    let err = |m: &str| Json(json!({ "ok": false, "error": m }));
    let deposits: Vec<PendingDeposit> = { s.pending_deposits.lock().await.iter().filter(|d| d.account == account_key).cloned().collect() };
    if deposits.is_empty() { return err("no on-chain funds to withdraw yet (deposit not confirmed, or already pooled)"); }
    let dep_sum: u64 = deposits.iter().map(|d| d.value).sum();
    let balance = s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0);
    if balance == 0 { return err("nothing to withdraw"); }
    // Refuse if there's a gameplay loss: the on-chain deposit is larger than the L2
    // balance backs, so part of it belongs to the pot — that requires pooling first.
    if balance < dep_sum { return err("you've played some of these funds — they must be pooled into the jackpot before withdrawal (wait a moment for the pot to absorb them, then try again)"); }
    let fee = s.estimate_fee(genesis_vsize(deposits.len() as u64));
    if dep_sum <= fee { return err("deposit too small to cover its on-chain exit fee"); }

    let dvec: Vec<([u8; 32], u32, u64)> = deposits.iter().map(|d| (d.txid_internal, d.vout, d.value)).collect();
    let res = match s.cosign_hub.run_deposit_withdraw(account_key, dvec, dest_spk.to_vec(), fee, std::time::Duration::from_secs(30)).await {
        Ok(r) => r, Err(e) => return err(&e),
    };
    let txid = match s.broadcast(&res.signed_tx_hex) { Ok(t) => t, Err(e) => return err(&format!("broadcast: {e}")) };
    s.mine(1);
    // drop the spent deposits from the absorb queue so they're never re-pooled.
    { let spent: std::collections::HashSet<_> = deposits.iter().map(|d| (d.txid_internal, d.vout)).collect();
      s.pending_deposits.lock().await.retain(|d| !spent.contains(&(d.txid_internal, d.vout))); }
    // debit the L2 balance by the full deposit sum (the whole UTXO left the system).
    { let mut cm = s.coin_manager.lock().await; let _ = cm.account_balance_down(account_key, dep_sum.min(balance)); let _ = cm.apply_changes(); }
    s.notify();
    let new_balance = s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0);
    Json(json!({ "ok": true, "txid": txid, "withdrawn": dep_sum - fee, "balance": new_balance }))
}

async fn post_withdraw(State(s): State<ArcadeState>, Json(body): Json<WithdrawReq>) -> Json<Value> {
    let err = |m: &str| Json(json!({ "ok": false, "error": m }));
    let account_key = match parse_hex::<32>(&body.account_key) { Some(a) => a, None => return err("bad account key") };
    let bls_key = match parse_hex::<48>(&body.bls_key) { Some(b) => b, None => return err("bad bls key") };
    let signature = match parse_hex::<96>(&body.bls_signature) { Some(x) => x, None => return err("bad signature") };
    if body.amount == 0 { return err("amount must be positive"); }
    let address = match bitcoin::Address::from_str(&body.address) { Ok(a) => a.assume_checked(), Err(_) => return err("invalid address") };
    let dest_spk = address.script_pubkey().to_bytes();

    // Authorize: BLS sig over (account_key ‖ amount ‖ address).
    let mut preimage = Vec::with_capacity(32 + 8 + body.address.len());
    preimage.extend_from_slice(&account_key);
    preimage.extend_from_slice(&body.amount.to_le_bytes());
    preimage.extend_from_slice(body.address.as_bytes());
    let sighash = preimage.hash(Some(HashTag::CustomString("Cube/sighash/arcade/withdraw".to_string())));
    if !bls_verify(&bls_key, sighash, signature) { return err("signature verification failed"); }

    let _guard = s.exec_lock.lock().await;
    let acct_hex = hex::encode(account_key);
    // Is this account pooled into the covenant? SUM over all its allocations (an
    // account can appear more than once, e.g. multiple deposits) — first-match
    // would undercount the claim.
    let cov_opt = s.covenant.current().await;
    let alloc: u64 = cov_opt.as_ref().map(|cov| cov.allocations.iter().filter(|(h, _)| h.eq_ignore_ascii_case(&acct_hex)).map(|(_, v)| *v).sum()).unwrap_or(0);
    if alloc == 0 {
        // Not pooled (deposited but not yet joined/reformed). Withdraw straight from
        // the un-absorbed LiftV2 deposit UTXOs (2-of-2) — no covenant, no other
        // members. This is what makes a freshly-deposited balance always recoverable.
        return withdraw_from_deposits(&s, account_key, &dest_spk).await;
    }
    let cov = cov_opt.unwrap();
    let balance = s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0);
    if balance == 0 { return err("nothing to withdraw"); }
    // pay out your balance, capped by your on-chain claim and the authorized amount.
    let payout = alloc.min(balance).min(body.amount);
    if payout == 0 { return err("nothing withdrawable"); }

    let old_allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    let old_txid_internal = match bitcoin::Txid::from_str(&cov.txid) { Ok(t) => t.to_byte_array(), Err(_) => return err("bad covenant txid") };
    let remaining: Vec<([u8; 32], u64)> = old_allocs.iter().cloned().filter(|(a, _)| a != &account_key).collect();
    let fee = s.estimate_fee(refresh_vsize() + VB_TAPROOT_OUT);

    // build the cosign params; compute the new covenant state to record on success.
    let (params, new_state): (cosign::RefreshParams, Option<(u64, Vec<(String, u64)>)>) = if remaining.is_empty() {
        // last member out: a payout-only tx (no new covenant) pays the whole pot
        // (minus fee) to your address.
        let out = cov.value.saturating_sub(fee);
        (cosign::RefreshParams {
            old_allocations: old_allocs.clone(), old_expiry: cov.expiry,
            new_allocations: vec![], new_expiry: cov.expiry,
            prev_txid: old_txid_internal, prev_vout: cov.vout, prev_value: cov.value,
            fee, override_out_spk: None, payout: Some((account_key, out, dest_spk.clone())),
        }, None)
    } else {
        // multi member: payout output to you + a new covenant for the rest.
        // The LEAVER pays their OWN on-chain exit fee — it comes out of your payout,
        // never out of the other members' pot. Nobody is charged for an exit they
        // didn't initiate. (The operator pays nothing either: this is a key-path
        // spend of the covenant itself, with no operator-funded input.)
        if payout <= fee { return err("withdraw amount too small to cover its on-chain exit fee"); }
        let payout_out = payout - fee; // you receive your balance minus your fee
        // The remaining covenant keeps everything else: the other members' claims
        // PLUS your gameplay losses (claim − payout), with no fee skimmed off them.
        let new_cov_value = cov.value - payout;
        let rem_sum: u64 = remaining.iter().map(|(_, v)| v).sum();
        let surplus = new_cov_value as i64 - rem_sum as i64;
        let mut new_allocs = remaining.clone();
        let first = new_allocs[0].1 as i64 + surplus;
        if first < 0 { return err("withdraw exceeds covenant"); }
        new_allocs[0].1 = first as u64;
        let mut canon = new_allocs.clone();
        canon.sort_by(|a, b| a.0.cmp(&b.0));
        let alloc_pairs: Vec<(String, u64)> = canon.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
        (cosign::RefreshParams {
            old_allocations: old_allocs.clone(), old_expiry: cov.expiry,
            new_allocations: new_allocs, new_expiry: cov.expiry,
            prev_txid: old_txid_internal, prev_vout: cov.vout, prev_value: cov.value,
            fee, override_out_spk: None, payout: Some((account_key, payout_out, dest_spk.clone())),
        }, Some((new_cov_value, alloc_pairs)))
    };

    let res = match s.cosign_hub.run_refresh(params, "arcade-withdraw", std::time::Duration::from_secs(30)).await {
        Ok(r) => r, Err(e) => return err(&e),
    };
    let txid = match s.broadcast(&res.signed_tx_hex) { Ok(t) => t, Err(e) => return err(&format!("broadcast: {e}")) };
    s.mine(1);

    // record the resulting covenant (payout is output 0, new covenant is output 1),
    // or clear it if the last member exited.
    match &new_state {
        None => { let _ = s.covenant.update(|st| { st.covenant = None; st.unroll = None; }).await; }
        Some((value, allocs)) => {
            let value = *value;
            let allocs = allocs.clone();
            let new_allocs: Vec<([u8; 32], u64)> = allocs.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
            let expiry = cov.expiry;
            let st_txid = txid.clone();
            let st_allocs = allocs.clone();
            let _ = s.covenant.update(move |st| {
                st.covenant = Some(covenant_manager::CovenantState { txid: st_txid, vout: 1, value, allocations: st_allocs, expiry });
                st.unroll = None;
            }).await;
            // re-arm the escape hatch for the new (smaller) covenant.
            presign_unroll(&s, &txid, 1, value, &new_allocs, cov.expiry).await;
        }
    }

    // debit the player's L2 balance by what was paid out.
    let debited = payout.min(balance);
    { let mut cm = s.coin_manager.lock().await; let _ = cm.account_balance_down(account_key, debited); let _ = cm.apply_changes(); }
    s.notify();
    let new_balance = s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0);
    Json(json!({ "ok": true, "txid": txid, "withdrawn": debited, "balance": new_balance }))
}

// After a UNILATERAL exit (the player broadcast the unroll + swept their leaf with
// their own key), tidy the L2 ledger when the operator is up: clear the now-spent
// covenant and zero the exiter's balance. Best-effort + BLS-authed; if the operator
// is gone this is moot (the player already has their coins on-chain).
#[derive(Deserialize)]
struct ExitDoneReq { account_key: String, bls_key: String, bls_signature: String }
async fn post_exit_done(State(s): State<ArcadeState>, Json(b): Json<ExitDoneReq>) -> Json<Value> {
    let err = |m: &str| Json(json!({ "ok": false, "error": m }));
    let account = match parse_hex::<32>(&b.account_key) { Some(a) => a, None => return err("bad account") };
    let bls_key = match parse_hex::<48>(&b.bls_key) { Some(k) => k, None => return err("bad bls key") };
    let sig = match parse_hex::<96>(&b.bls_signature) { Some(x) => x, None => return err("bad signature") };
    let sighash = account.to_vec().hash(Some(HashTag::CustomString("Cube/sighash/arcade/exit-done".to_string())));
    if !bls_verify(&bls_key, sighash, sig) { return err("signature verification failed"); }
    let _guard = s.exec_lock.lock().await;
    // only clear the covenant if it's actually been spent on-chain (the unroll).
    if let Some(cov) = s.covenant.current().await {
        let spent = s.rpc()
            .and_then(|c| c.call::<Value>("gettxout", &[json!(cov.txid), json!(cov.vout)]).ok())
            .map(|v| v.is_null())
            .unwrap_or(false);
        if spent { let _ = s.covenant.update(|st| { st.covenant = None; st.unroll = None; }).await; }
    }
    let bal = s.coin_manager.lock().await.get_account_balance(account).unwrap_or(0);
    if bal > 0 { let mut cm = s.coin_manager.lock().await; let _ = cm.account_balance_down(account, bal); let _ = cm.apply_changes(); }
    s.notify();
    Json(json!({ "ok": true }))
}

// After a settle, reconcile the on-chain covenant to the players' CURRENT L2
// balances via a cosigned refresh, so a winner can cooperatively withdraw their
// winnings. The covenant otherwise tracks only each player's genesis stake, so a
// winner's balance (stake + winnings) exceeds their covenant claim and the
// withdraw is rejected ("no on-chain claim"). Re-attributing the covenant to the
// post-settle balances fixes that for everyone (winner up, losers down).
//
// SAFE + best-effort: it only runs when the balances it would back EXACTLY equal
// the covenant value — i.e. the clean case where every claimant's funds are in the
// covenant. If they differ (post-genesis deposits sitting at separate LiftV2
// addresses, a decoupled covenant, etc.) it SKIPS rather than mint/burn on-chain
// value. N-of-N cosigned by the current covenant members; if any are offline the
// cosign times out and it skips (the next settle retries).
async fn reconcile_covenant(s: &ArcadeState, winner: Option<[u8; 32]>) {
    let _guard = s.exec_lock.lock().await;
    let cov = match s.covenant.current().await { Some(c) => c, None => return };
    let operator = parse_hex::<32>(OPERATOR_ACCOUNT_HEX);
    // PLAYER accounts to (re)attribute: current covenant members + the winner, but
    // NOT the operator (the engine doesn't hold the operator's cosign key, so the
    // operator can't be a covenant member — its rake is paid OUT instead, below).
    let mut accounts: Vec<[u8; 32]> = cov.allocations.iter().filter_map(|(h, _)| parse_hex::<32>(h)).collect();
    accounts.sort(); accounts.dedup();
    if let Some(w) = winner { if !accounts.contains(&w) { accounts.push(w); } }
    accounts.retain(|a| Some(*a) != operator);
    // each player's current spendable L2 balance; keep the non-zero ones.
    let mut new_allocs: Vec<([u8; 32], u64)> = {
        let cm = s.coin_manager.lock().await;
        accounts.iter().map(|a| (*a, cm.get_account_balance(*a).unwrap_or(0))).filter(|(_, v)| *v > 0).collect()
    };
    if new_allocs.is_empty() { return; }
    new_allocs.sort_by(|a, b| a.0.cmp(&b.0));
    // skip if the covenant already reflects the players' balances (nothing to do).
    let bal_pairs: Vec<(String, u64)> = new_allocs.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let mut old_pairs = cov.allocations.clone(); old_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    if old_pairs == bal_pairs { return; }
    let player_sum: u64 = new_allocs.iter().map(|(_, v)| v).sum();

    // the operator's accrued rake (its native L2 balance) is paid OUT on-chain to the
    // operator's address, so it leaves the covenant; dust rakes are deferred (kept in
    // L2) so we don't emit an unspendable output.
    let op_rake = match operator { Some(op) => s.coin_manager.lock().await.get_account_balance(op).unwrap_or(0), None => 0 };
    let mine_spk = bitcoin::Address::from_str(&s.mine_address).ok().map(|a| a.assume_checked().script_pubkey().to_bytes());
    let payout_amt = if op_rake >= 546 && mine_spk.is_some() { op_rake } else { 0 };

    // CONSERVATION: payout + new covenant == covenant value − fee. The L2 ledger
    // doesn't track on-chain fees, so Σ (players + paid rake) drifts slightly from
    // the covenant (the genesis/refresh fees were paid on-chain); absorb that small
    // drift off the largest player claim. A large gap means the covenant is
    // decoupled from the ledger (post-genesis deposits elsewhere) — SKIP.
    let fee = s.estimate_fee(refresh_vsize() + VB_TAPROOT_OUT + if payout_amt > 0 { VB_TAPROOT_OUT } else { 0 });
    let target = cov.value.saturating_sub(fee);          // on-chain value to distribute
    let player_target = target.saturating_sub(payout_amt); // ... minus the rake payout
    const MAX_RECONCILE_DRIFT: u64 = 1_000_000;
    let adjust = player_sum as i64 - player_target as i64; // remove this from players (>0) or add (<0)
    if adjust.abs() as u64 > MAX_RECONCILE_DRIFT {
        eprintln!("arcade: reconcile skipped — players {} vs target {} off by {} (decoupled?)", player_sum, player_target, adjust);
        return;
    }
    // apply the drift to the largest player claim (keep it positive).
    {
        let max = match new_allocs.iter_mut().max_by_key(|(_, v)| *v) { Some(m) => m, None => return };
        let adjusted = max.1 as i64 - adjust;
        if adjusted <= 0 { eprintln!("arcade: reconcile skipped — drift exceeds largest claim"); return; }
        max.1 = adjusted as u64;
    }
    let old_allocs: Vec<([u8; 32], u64)> = cov.allocations.iter().filter_map(|(h, v)| parse_hex::<32>(h).map(|a| (a, *v))).collect();
    let old_txid = match bitcoin::Txid::from_str(&cov.txid) { Ok(t) => t.to_byte_array(), Err(_) => return };
    let payout = match (payout_amt > 0, operator, mine_spk) {
        (true, Some(op), Some(spk)) => Some((op, payout_amt, spk)),
        _ => None,
    };
    let params = cosign::RefreshParams {
        old_allocations: old_allocs, old_expiry: cov.expiry,
        new_allocations: new_allocs.clone(), new_expiry: cov.expiry,
        prev_txid: old_txid, prev_vout: cov.vout, prev_value: cov.value,
        fee, override_out_spk: None, payout,
    };
    let res = match s.cosign_hub.run_refresh(params, "arcade-reconcile", std::time::Duration::from_secs(30)).await {
        Ok(r) => r, Err(e) => { eprintln!("arcade: reconcile cosign failed: {}", e); return; }
    };
    let txid = match s.broadcast(&res.signed_tx_hex) { Ok(t) => t, Err(e) => { eprintln!("arcade: reconcile broadcast: {}", e); return; } };
    s.mine(1);
    // the rake left the contract on-chain (payout) — debit the operator's L2 balance.
    if payout_amt > 0 { if let Some(op) = operator { let mut cm = s.coin_manager.lock().await; let _ = cm.account_balance_down(op, payout_amt); let _ = cm.apply_changes(); } }
    // a payout sits at output 0, so the new covenant is output 1 (else output 0).
    let cov_vout: u32 = if payout_amt > 0 { 1 } else { 0 };
    let new_value: u64 = new_allocs.iter().map(|(_, v)| v).sum();
    let mut canon = new_allocs.clone(); canon.sort_by(|a, b| a.0.cmp(&b.0));
    let alloc_pairs: Vec<(String, u64)> = canon.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let expiry = cov.expiry;
    let st_txid = txid.clone();
    let _ = s.covenant.update(move |st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: st_txid, vout: cov_vout, value: new_value, allocations: alloc_pairs, expiry });
        st.unroll = None;
        st.last_settle = None;
    }).await;
    presign_unroll(s, &txid, cov_vout, new_value, &canon, expiry).await;
    eprintln!("arcade: reconciled covenant to {} player balances + {} rake payout ({} -> {})", canon.len(), payout_amt, &cov.txid[..cov.txid.len().min(12)], &txid[..txid.len().min(12)]);
    s.notify();
}

// The round-lifecycle loop: close + settle when a round is ripe.
async fn lifecycle(s: ArcadeState) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let (g, rs, t, k, d, w, total, b, count, _seed) = round_view(&s).await;
        let now = Utc::now().timestamp() as u64;
        let closed = k == d + 1;
        if closed || count < MIN_PARTICIPANTS || now < t + ROUND_DURATION {
            continue;
        }
        // 1) close (snapshots the seed from the current block hash)
        let target = { s.sync_manager.lock().await.cube_batch_sync_height_tip() } + 1;
        let contract = { s.registery.lock().await.get_contract_by_contract_id(s.contract_id).unwrap_or_else(|| Contract::new(s.contract_id, 0)) };
        let close_call = s.settler_call(contract.clone(), 1, vec![], target);
        if let Err(e) = run_call(&s, &close_call).await {
            eprintln!("arcade: close failed: {}", e);
            continue;
        }
        // 2) compute winner / rollover from the stored seed (mirror the contract)
        let (_g2, _rs2, _t2, _k2, _d2, _w2, total2, b2, _c2, seed) = round_view(&s).await;
        let round_total = total2.saturating_sub(b2);
        let house = round_total * ODDS_DENOM; // win region is 1/(ODDS_DENOM+1) of space
        let space = (round_total + house).max(1);
        let seed_su = StackItem::new(seed.clone()).to_stack_uint().unwrap_or_else(|| StackUint::from(0u64));
        let r = (seed_su % StackUint::from(space)).to_u64().unwrap_or(0);
        let rg = r + b2;
        let rollover = rg >= total2;
        let idx = if rollover {
            0u64
        } else {
            // find idx in [rs, g) with cum[idx-1] <= rg < cum[idx]
            let mut found = rs;
            for i in rs..g {
                let upper = s.read_cum(i).await;
                let lower = if i == 0 { 0 } else { s.read_cum(i - 1).await };
                if lower <= rg && rg < upper {
                    found = i;
                    break;
                }
            }
            found
        };
        let winner_key = if rollover { None } else { s.read_participant(idx).await.map(hex::encode) };
        let pot = { s.coin_manager.lock().await.get_contract_balance(s.contract_id).unwrap_or(0) };
        let round_no = d + 1;
        // Capture the full settlement breakdown (entry bands + the draw) for the
        // provably-fair details page, before settle advances the round markers.
        let mut segments: Vec<Value> = Vec::new();
        for i in rs..g {
            let upper = s.read_cum(i).await;
            let lower = if i == 0 { 0 } else { s.read_cum(i - 1).await };
            segments.push(json!({
                "key": s.read_participant(i).await.map(hex::encode).unwrap_or_default(),
                "contribution": upper - lower,
                "lower": lower.saturating_sub(b2), // round-local band start
                "upper": upper.saturating_sub(b2), // round-local band end
                "winner": !rollover && i == idx,
            }));
        }
        let detail = json!({
            "round": round_no,
            "ts": now,
            "kind": if rollover { "rollover" } else { "win" },
            "winner": winner_key.clone(),
            "amount": pot,
            "seed_hex": hex::encode(&seed), // little-endian, as the VM reads it
            "round_total": round_total,
            "house": house,
            "space": space,
            "r": r,    // draw position within [0, space)
            "rg": rg,  // global position (r + b)
            "b": b2,
            "total": total2,
            "rollover": rollover,
            "rake_percent": RAKE_PERCENT,
            "duration": ROUND_DURATION,
            "segments": segments,
        });
        // 3) settle
        let settle_call = s.settler_call(contract, 2, vec![CalldataElement::U32(idx as u32)], target);
        match run_call(&s, &settle_call).await {
            Ok(_) => {
                s.mine(1);
                let event = feed_event(&detail);
                if rollover {
                    println!("arcade: round {} rolled over (jackpot grows to {})", round_no, pot);
                } else {
                    let wk = winner_key.clone().unwrap_or_default();
                    println!("arcade: round {} winner {} wins {}", round_no, &wk[..wk.len().min(12)], pot);
                    *s.last_winner.lock().await = winner_key.clone();
                }
                {
                    let mut rd = s.round_details.lock().await;
                    rd.insert(round_no, detail);
                    // keep the whole jackpot history (bounded generously to cap disk).
                    while rd.len() > 5000 {
                        if let Some(&min) = rd.keys().min() { rd.remove(&min); } else { break; }
                    }
                }
                {
                    let mut feed = s.recent_draws.lock().await;
                    feed.insert(0, event);
                    feed.truncate(12);
                }
                s.persist_history().await; // survive restarts
                s.notify();
                // re-attribute the on-chain covenant to the new balances so the
                // winner can withdraw their winnings (best-effort; safe no-op when
                // it can't conserve value or members are offline).
                if !rollover {
                    let w = winner_key.as_deref().and_then(|h| parse_hex::<32>(h));
                    reconcile_covenant(&s, w).await;
                }
            }
            Err(e) => eprintln!("arcade: settle failed: {}", e),
        }
    }
}

/// Spawns the arcade web server + round-lifecycle task.
pub async fn run_arcade(
    handles: cube::operative::runner::hook::EngineHandles,
    engine_secret: [u8; 32],
    port: u16,
    contract_id: [u8; 32],
    mine_address: String,
) {
    let cube::operative::runner::hook::EngineHandles {
        chain: _chain,
        engine_key,
        registery,
        coin_manager,
        state_manager,
        flame_manager,
        sync_manager,
        utxo_set,
        params_manager,
        privileges_manager,
        graveyard,
        archival_manager,
        rpc_url,
        rpc_user,
        rpc_pass,
    } = handles;
    // Re-bind the owned handles as references so the body below (written against
    // &MANAGER params) compiles unchanged.
    let registery = &registery;
    let coin_manager = &coin_manager;
    let state_manager = &state_manager;
    let flame_manager = &flame_manager;
    let sync_manager = &sync_manager;
    let utxo_set = &utxo_set;
    let params_manager = &params_manager;
    let privileges_manager = &privileges_manager;
    let graveyard = &graveyard;
    let archival_manager = archival_manager.as_ref();
    // Derive + register the server "settler" account (drives close/settle).
    let settler_secret = sha256(b"cube-arcade-settler-v2");
    let kh = match KeyHolder::new(settler_secret) {
        Some(kh) => kh,
        None => {
            eprintln!("arcade: failed to build settler keyholder");
            return;
        }
    };
    let settler_account = kh.secp_public_key_bytes();
    let settler_bls = kh.bls_public_key_bytes();
    {
        let now = Utc::now().timestamp() as u64;
        let already = { registery.lock().await.get_account_info_by_account_key(settler_account).is_some() };
        if !already {
            let mut reg = registery.lock().await;
            let _ = reg.register_account(settler_account, now, Some(settler_bls), None, None, None);
            let _ = reg.apply_changes();
        }
        let mut cm = coin_manager.lock().await;
        if cm.get_account_balance(settler_account).is_none() {
            let _ = cm.register_account(settler_account, 10_000_000);
        }
        let _ = cm.apply_changes();
    }

    // Register the operator account (receives the 1% rake) if absent.
    if let (Some(op_acct), Some(op_bls)) = (parse_hex::<32>(OPERATOR_ACCOUNT_HEX), parse_hex::<48>(OPERATOR_BLS_HEX)) {
        let now = Utc::now().timestamp() as u64;
        let already = { registery.lock().await.get_account_info_by_account_key(op_acct).is_some() };
        if !already {
            let mut reg = registery.lock().await;
            let _ = reg.register_account(op_acct, now, Some(op_bls), None, None, None);
            let _ = reg.apply_changes();
        }
        let mut cm = coin_manager.lock().await;
        if cm.get_account_balance(op_acct).is_none() {
            let _ = cm.register_account(op_acct, 0);
        }
        let _ = cm.apply_changes();
    }

    // Deploy the lottery v3 program (decompiled from embedded bytecode) if it
    // isn't registered yet. The arcade executes calls directly against the
    // managers, so a direct registration is all the engine needs.
    if registery.lock().await.get_contract_by_contract_id(contract_id).is_none() {
        match hex::decode(V3_BYTES_HEX) {
            Ok(bytes) => {
                let mut it = bytes.into_iter();
                match cube::executive::executable::executable::Program::decompile(&mut it) {
                    Ok(program) if program.contract_id() == contract_id => {
                        let now = Utc::now().timestamp() as u64;
                        {
                            let mut reg = registery.lock().await;
                            let _ = reg.register_contract(contract_id, now, program);
                            let _ = reg.apply_changes();
                        }
                        {
                            let mut cm = coin_manager.lock().await;
                            let _ = cm.register_contract(contract_id, 0);
                            let _ = cm.apply_changes();
                        }
                        {
                            let mut sm = state_manager.lock().await;
                            let _ = sm.register_contract(contract_id);
                            let _ = sm.apply_changes();
                        }
                        println!("arcade: registered lottery v3 contract {}", hex::encode(contract_id));
                    }
                    Ok(program) => eprintln!(
                        "arcade: v3 bytecode contract_id {} != configured {}; not registering",
                        hex::encode(program.contract_id()), hex::encode(contract_id)
                    ),
                    Err(e) => eprintln!("arcade: failed to decompile v3 bytecode: {:?}", e),
                }
            }
            Err(e) => eprintln!("arcade: bad V3 bytecode hex: {}", e),
        }
    }

    let settler_reg_index = registery
        .lock()
        .await
        .get_account_info_by_account_key(settler_account)
        .map(|(_, _, idx, _)| idx)
        .unwrap_or(0);

    // Verify the plumbed engine secret derives the engine pubkey the managers
    // report — the covenant cosign is built on this identity, so a mismatch would
    // silently break every refresh/lift-in. Loud warning, not a hard abort (the
    // arcade still serves the L2 game; only on-chain cosign would be affected).
    {
        use cube::transmutative::secp::into::IntoScalar;
        use cube::transmutative::secp::schnorr::LiftScalar;
        match engine_secret.into_scalar() {
            Ok(s) if s.lift().base_point_mul().serialize_xonly() == engine_key => {
                println!("arcade: engine secret verified against engine key {}", hex::encode(engine_key));
            }
            _ => eprintln!(
                "arcade: WARNING engine secret does NOT derive engine key {} — covenant cosign will fail",
                hex::encode(engine_key)
            ),
        }
    }
    let cosign_hub = cosign::CosignHub::new(engine_secret, engine_key);
    let covenant_path = std::env::var("CUBE_COVENANT_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("arcade-covenant.json"));
    let covenant = covenant_manager::CovenantManager::load(covenant_path);

    let credited_path = std::env::var("CUBE_CREDITED_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("arcade-credited.json"));
    let credited_set: std::collections::HashSet<String> = std::fs::read(&credited_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default();

    // Load persisted jackpot history and rebuild the live feed (most-recent 12) from
    // it, so the draw history survives restarts and shows for every player.
    let history_path = std::env::var("CUBE_HISTORY_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("arcade-history.json"));
    let round_details_map: HashMap<u64, Value> = std::fs::read(&history_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<HashMap<u64, Value>>(&b).ok())
        .unwrap_or_default();
    let recent_feed: Vec<Value> = {
        let mut rounds: Vec<&Value> = round_details_map.values().collect();
        rounds.sort_by(|a, b| b["round"].as_u64().unwrap_or(0).cmp(&a["round"].as_u64().unwrap_or(0)));
        rounds.into_iter().take(12).map(|d| feed_event(d)).collect()
    };

    // The engine's bitcoind fee/spending wallet (funds CPFP children for the
    // feeless package-broadcast unroll). regtest harness uses "cube", mut "mutiny".
    let btc_wallet = std::env::var("CUBE_BTC_WALLET").unwrap_or_else(|_| match &_chain {
        Chain::Regtest => "cube".to_string(),
        _ => "mutiny".to_string(),
    });
    let (tx, _rx) = broadcast::channel::<()>(64);
    let state = ArcadeState {
        chain: _chain,
        engine_key,
        contract_id,
        registery: Arc::clone(registery),
        coin_manager: Arc::clone(coin_manager),
        state_manager: Arc::clone(state_manager),
        flame_manager: Arc::clone(flame_manager),
        sync_manager: Arc::clone(sync_manager),
        utxo_set: Arc::clone(utxo_set),
        params_manager: Arc::clone(params_manager),
        privileges_manager: Arc::clone(privileges_manager),
        graveyard: Arc::clone(graveyard),
        archival_manager: archival_manager.map(Arc::clone),
        rpc_url,
        rpc_user,
        rpc_pass,
        btc_wallet,
        mine_address,
        settler_account,
        settler_bls,
        settler_reg_index,
        last_winner: Arc::new(tokio::sync::Mutex::new(None)),
        recent_draws: Arc::new(tokio::sync::Mutex::new(recent_feed)),
        round_details: Arc::new(tokio::sync::Mutex::new(round_details_map)),
        exec_lock: Arc::new(tokio::sync::Mutex::new(())),
        tx: tx.clone(),
        cosign_hub,
        covenant,
        pending_deposits: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        deposit_watch: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        credited_deposits: Arc::new(tokio::sync::Mutex::new(credited_set)),
        credited_path,
        history_path,
        coinos_url: std::env::var("COINOS_URL").ok().filter(|v| !v.is_empty()),
        coinos_token: std::env::var("COINOS_TOKEN").ok().filter(|v| !v.is_empty()),
        coinos_webhook_url: std::env::var("COINOS_WEBHOOK_URL").ok().filter(|v| !v.is_empty()),
        ln_invoices: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        auto_genesis_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    tokio::spawn(lifecycle(state.clone()));
    tokio::spawn(deposit_watcher(state.clone()));
    // Heartbeat: nudge WS clients periodically (reaps dead sockets, resync safety).
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let _ = tx.send(());
        }
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/cosign", get(cosign::cosign_ws))
        .route("/", get(serve_index))
        .route("/bundle.js", get(serve_bundle))
        .route("/sw.js", get(serve_sw))
        .route("/manifest.webmanifest", get(serve_manifest))
        .route("/exit-tool.bundle.js", get(serve_exit_tool))
        .route("/api/state", get(get_state))
        .route("/api/round/:n", get(get_round))
        .route("/api/history", get(get_history))
        .route("/api/exit", get(get_exit))
        .route("/api/winnings", get(get_winnings))
        .route("/api/covenant", get(get_covenant))
        .route("/api/feerate", get(get_feerate))
        .route("/api/txstatus", get(get_txstatus))
        .route("/api/exit_kit", get(get_exit_kit))
        .route("/api/exit_done", post(post_exit_done))
        .route("/api/deposit_address", get(get_deposit_address))
        .route("/api/ln/deposit", post(post_ln_deposit))
        .route("/api/ln/webhook", post(post_ln_webhook))
        .route("/api/deposit", post(post_deposit))
        .route("/api/deposit/claim", post(post_deposit_claim))
        .route("/api/covenant/genesis", post(post_genesis))
        .route("/api/covenant/refresh", post(post_refresh))
        .route("/api/covenant/unroll", post(post_unroll))
        .route("/api/settle_assertion", post(post_settle_assertion))
        .route("/api/settle", post(post_settle))
        .route("/api/broadcast", post(post_broadcast))
        .route("/api/faucet", post(post_faucet))
        .route("/api/call", post(post_call))
        .route("/api/withdraw", post(post_withdraw))
        .layer(axum::middleware::from_fn(access_log))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("arcade: failed to bind {}: {}", addr, e);
            return;
        }
    };
    println!("🎲 Cube Lottery arcade on http://127.0.0.1:{}/", port);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
}
