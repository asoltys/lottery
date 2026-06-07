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
use cube::transmutative::key::KeyHolder;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRef, Path, Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse};
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
const ODDS_DENOM: u64 = 475; // house = round_total * 475 -> ~0.21% per-round win odds (match contract)
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
// draw/odds/rake rules as v3. contract_id
// 82b2b9530ee1e22739dff2653bb95c6495f151bb3ea9b0930c852aa574a62fdd
const V3_BYTES_HEX: &str = "2470657270657475616c206a61636b706f7420763420286e6f6e2d637573746f6469616c29000305656e7465720001092a0076b975c40167ce0172ce8763bd0174cd680154ce9369760154cd01630167ce7ecd01700167ce7eb9757ccd0167ce5193690167cd6505636c6f736500001c000172ce0167ce946951a269bd0174ce01789369a269d30173cd0164ce519369016bcd6506736574746c650001028a006b016bce0164ce51936987690142ce0154ce94697602db01956993690173ce9669750142ce9369760154cea263750164ce5193690164cd0154ce0142cd0167ce0172cdbd0174cd676c009369766b7601637c7ece7c76008763750067517c946901637c7ece687ca569c9c70164cb96697c7576008763756720a55068222783355b755993fe7e1ac0b190d29fa2689a9ebc041ff7252617dd0400cc686c01707c7ececb7c00cc0164ce5193690164cd0154ce0142cd0167ce0172cdbd0174cd0164ce0177cd6865";
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
}

// A confirmed LiftV2 deposit UTXO awaiting inclusion in the pot covenant.
#[derive(Clone)]
struct PendingDeposit {
    account: [u8; 32],
    txid_internal: [u8; 32], // bitcoin internal byte order (for the outpoint)
    vout: u32,
    value: u64,
}

// Covenant lifecycle tuning (regtest-friendly small values).
const COVENANT_FEE: u64 = 1_000; // per genesis/refresh/unroll tx
const COVENANT_EXIT_DELAY: u16 = 6; // CSV blocks for the demo (vs 144 in prod)
const COVENANT_EXPIRY_WINDOW: u64 = 12_960; // CLTV engine-reclaim window above tip

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
    // Broadcast a fully-signed tx (hex) via bitcoind; returns the display txid.
    fn broadcast(&self, tx_hex: &str) -> Result<String, String> {
        let rpc = self.rpc().ok_or("bitcoin rpc unavailable")?;
        rpc.send_raw_transaction(tx_hex).map(|t| t.to_string()).map_err(|e| format!("{e}"))
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
            out["account"] = json!({
                "registered": registered, "registery_index": reg_index, "balance": balance,
                "your_contribution": your,
                "odds_pct": if round_total > 0 { (your as f64) * 100.0 / (round_total as f64) } else { 0.0 },
            });
        }
    }
    out
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

// The LiftV2 deposit address for a player: a taproot {key-path MuSig2(account,
// engine); script-path CSV-3mo account sweep}. Funding it and lifting it in is how
// a player trustlessly puts real BTC into the pot covenant.
async fn get_deposit_address(State(s): State<ArcadeState>, Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    let account = match params.get("account").and_then(|a| parse_hex::<32>(a)) {
        Some(a) => a,
        None => return Json(json!({ "error": "bad account" })),
    };
    let spk = match return_liftv2_taproot(account, s.engine_key).and_then(|t| t.spk()) {
        Some(s) => s,
        None => return Json(json!({ "error": "could not derive deposit taproot" })),
    };
    let network = match s.chain {
        Chain::Mainnet => bitcoin::Network::Bitcoin,
        Chain::Signet => bitcoin::Network::Signet,
        _ => bitcoin::Network::Regtest,
    };
    let script = bitcoin::ScriptBuf::from_bytes(spk.clone());
    let address = match bitcoin::Address::from_script(script.as_script(), network) {
        Ok(a) => a.to_string(),
        Err(_) => return Json(json!({ "error": "address encode failed" })),
    };
    Json(json!({
        "account": hex::encode(account),
        "engine": hex::encode(s.engine_key),
        "address": address,
        "scriptpubkey": hex::encode(spk),
    }))
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
    Json(json!({ "ok": true, "value": value, "pending": s.pending_deposits.lock().await.len() }))
}

// GENESIS: combine all queued deposits into the pot covenant via N-of-N cosign
// (depositors must be connected to /cosign), broadcast it, and record the covenant.
async fn post_genesis(State(s): State<ArcadeState>) -> Json<Value> {
    let deposits = { s.pending_deposits.lock().await.clone() };
    if deposits.is_empty() { return Json(json!({"ok":false,"error":"no pending deposits"})); }
    if s.covenant.current().await.is_some() { return Json(json!({"ok":false,"error":"covenant exists; use refresh to add"})); }
    let gdeposits: Vec<cosign::GenesisDeposit> = deposits.iter().map(|d| cosign::GenesisDeposit {
        account_key: d.account, prev_txid: d.txid_internal, prev_vout: d.vout, prev_value: d.value,
    }).collect();
    let mut allocs: Vec<([u8; 32], u64)> = deposits.iter().map(|d| (d.account, d.value)).collect();
    if let Some(max) = allocs.iter_mut().max_by_key(|(_, v)| *v) { max.1 = max.1.saturating_sub(COVENANT_FEE); }
    let tip = { s.sync_manager.lock().await.bitcoin_sync_height_tip() };
    let expiry = (tip + COVENANT_EXPIRY_WINDOW) as u32;
    let res = match s.cosign_hub.run_genesis(gdeposits, allocs.clone(), expiry, COVENANT_FEE, std::time::Duration::from_secs(30)).await {
        Ok(r) => r, Err(e) => return Json(json!({"ok":false,"error":e})),
    };
    let txid = match s.broadcast(&res.signed_tx_hex) { Ok(t) => t, Err(e) => return Json(json!({"ok":false,"error":format!("broadcast: {e}")})) };
    s.mine(1);
    let mut canonical = allocs.clone();
    canonical.sort_by(|a, b| a.0.cmp(&b.0));
    let cov_value: u64 = canonical.iter().map(|(_, v)| v).sum();
    let alloc_pairs: Vec<(String, u64)> = canonical.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
    let _ = s.covenant.update(|st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: txid.clone(), vout: 0, value: cov_value, allocations: alloc_pairs, expiry });
        st.unroll = None;
    }).await;
    { s.pending_deposits.lock().await.clear(); }
    s.notify();
    Json(json!({ "ok": true, "txid": txid, "covenant_value": cov_value, "participants": canonical.len() }))
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
    if let Some(max) = new_allocs.iter_mut().max_by_key(|(_, v)| *v) { max.1 = max.1.saturating_sub(COVENANT_FEE); }
    let new_expiry = cov.expiry;
    let params = cosign::RefreshParams {
        old_allocations: old_allocs, old_expiry: cov.expiry, new_allocations: new_allocs.clone(),
        new_expiry, prev_txid: old_txid_internal, prev_vout: cov.vout, prev_value: cov.value,
        fee: COVENANT_FEE, override_out_spk: None,
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
    let unroll = match s.cosign_hub.run_unroll(canonical.clone(), new_expiry, new_txid_internal, 0, new_value, COVENANT_EXIT_DELAY, COVENANT_FEE, None, std::time::Duration::from_secs(30)).await {
        Ok(u) => u, Err(e) => return Json(json!({"ok":false,"error":format!("unroll presign: {e}")})),
    };
    let _ = s.covenant.update(|st| {
        st.covenant = Some(covenant_manager::CovenantState { txid: refresh_txid.clone(), vout: 0, value: new_value, allocations: alloc_pairs, expiry: new_expiry });
        st.unroll = Some(covenant_manager::PreSignedUnroll { covenant_txid: refresh_txid.clone(), unroll_txid: unroll.txid.clone(), unroll_tx_hex: unroll.signed_tx_hex.clone() });
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
    let txid = match s.broadcast(&unroll.unroll_tx_hex) { Ok(t) => t, Err(e) => return Json(json!({"ok":false,"error":format!("broadcast: {e}")})) };
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
    match s.broadcast(&b.tx_hex) {
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
        commits.push(InstanceCommit { tables_commit: v.tables_commit(&tables), disprove_hash: v.disprove_hash(&wires) });
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
    let instances: Vec<Value> = (0..K)
        .map(|i| json!({
            "tables_commit": hex::encode(commits[i].tables_commit),
            "disprove_hash": hex::encode(commits[i].disprove_hash),
            "opened": opened[i],
            "wires": if opened[i] { serde_json::to_value(&all_wires[i]).ok() } else { None },
        }))
        .collect();

    // Pre-sign the covenant's unroll with every leaf locked to this round.
    let prev_txid_internal = match bitcoin::Txid::from_str(&cov.txid) {
        Ok(t) => t.to_byte_array(),
        Err(_) => return Json(json!({"ok":false,"error":"bad covenant txid"})),
    };
    let unroll = match s
        .cosign_hub
        .run_unroll(allocs.clone(), cov.expiry, prev_txid_internal, cov.vout, cov.value, COVENANT_EXIT_DELAY, COVENANT_FEE, Some(disprove_hash), std::time::Duration::from_secs(30))
        .await
    {
        Ok(u) => u,
        Err(e) => return Json(json!({"ok":false,"error":format!("unroll pre-sign: {e}")})),
    };
    let _ = s.covenant.update(|st| {
        st.unroll = Some(covenant_manager::PreSignedUnroll {
            covenant_txid: cov.txid.clone(),
            unroll_txid: unroll.txid.clone(),
            unroll_tx_hex: unroll.signed_tx_hex.clone(),
        });
    }).await;
    s.notify();
    Json(json!({
        "ok": true,
        "rg": rg, "total": total, "honest_winner": honest_winner, "claimed_winner": claimed,
        "is_honest": Some(claimed) == honest_winner,
        "engine_key": hex::encode(s.engine_key),
        "expiry": cov.expiry, "exit_delay": COVENANT_EXIT_DELAY,
        "disprove_hash": hex::encode(disprove_hash),
        "k": K, "settle_instance": settle_idx, "instances": instances,
        "unroll_txid": unroll.txid,
        "unroll_tx_hex": unroll.signed_tx_hex,
        "leaves": serde_json::to_value(&unroll.leaves).unwrap_or(Value::Null),
        "assertion": assertion,
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
async fn post_withdraw(State(s): State<ArcadeState>, Json(body): Json<WithdrawReq>) -> Json<Value> {
    let err = |m: &str| Json(json!({ "ok": false, "error": m }));
    // Custodial on-chain payout is only allowed on regtest. On signet/mainnet it's
    // disabled — otherwise faucet-derived (free) L2 balance could be cashed out as
    // real BTC. Non-custodial exit is via the unilateral VTXO exit (see /api/exit).
    if s.chain != Chain::Regtest {
        return err("on-chain withdraw disabled on this network — exit via your VTXO (see how-it-works)");
    }
    let account_key = match parse_hex::<32>(&body.account_key) { Some(a) => a, None => return err("bad account key") };
    let bls_key = match parse_hex::<48>(&body.bls_key) { Some(b) => b, None => return err("bad bls key") };
    let signature = match parse_hex::<96>(&body.bls_signature) { Some(x) => x, None => return err("bad signature") };
    if body.amount == 0 {
        return err("amount must be positive");
    }
    let address = match bitcoin::Address::from_str(&body.address) {
        Ok(a) => a.assume_checked(),
        Err(_) => return err("invalid address"),
    };

    // Authorize: BLS-verify a sighash over (account_key ‖ amount ‖ address) so
    // only the key owner can move their balance.
    let mut preimage = Vec::with_capacity(32 + 8 + body.address.len());
    preimage.extend_from_slice(&account_key);
    preimage.extend_from_slice(&body.amount.to_le_bytes());
    preimage.extend_from_slice(body.address.as_bytes());
    let sighash = preimage.hash(Some(HashTag::CustomString("Cube/sighash/arcade/withdraw".to_string())));
    if !bls_verify(&bls_key, sighash, signature) {
        return err("signature verification failed");
    }

    let _guard = s.exec_lock.lock().await;
    let balance = match s.coin_manager.lock().await.get_account_balance(account_key) {
        Some(b) => b,
        None => return err("account has no balance"),
    };
    if body.amount > balance {
        return err("insufficient balance");
    }
    let rpc = match s.rpc() { Some(r) => r, None => return err("bitcoin rpc unavailable") };
    let txid = match rpc.send_to_address(&address, bitcoin::Amount::from_sat(body.amount), None, None, Some(false), None, None, None) {
        Ok(t) => t,
        Err(e) => return Json(json!({ "ok": false, "error": format!("payout failed: {}", e) })),
    };
    {
        let mut cm = s.coin_manager.lock().await;
        if cm.account_balance_down(account_key, body.amount).is_err() {
            return err("debit failed");
        }
        let _ = cm.apply_changes();
    }
    s.mine(1); // confirm the payout
    s.notify();
    let new_balance = { s.coin_manager.lock().await.get_account_balance(account_key).unwrap_or(0) };
    Json(json!({ "ok": true, "txid": txid.to_string(), "balance": new_balance }))
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
                {
                    let mut rd = s.round_details.lock().await;
                    rd.insert(round_no, detail);
                    while rd.len() > 500 {
                        if let Some(&min) = rd.keys().min() { rd.remove(&min); } else { break; }
                    }
                }
                let event = if rollover {
                    println!("arcade: round {} rolled over (jackpot grows to {})", round_no, pot);
                    json!({ "round": round_no, "kind": "rollover", "amount": pot, "ts": now })
                } else {
                    let wk = winner_key.clone().unwrap_or_default();
                    println!("arcade: round {} winner {} wins {}", round_no, &wk[..wk.len().min(12)], pot);
                    *s.last_winner.lock().await = winner_key.clone();
                    json!({ "round": round_no, "kind": "win", "winner": wk, "amount": pot, "ts": now })
                };
                let mut feed = s.recent_draws.lock().await;
                feed.insert(0, event);
                feed.truncate(12);
                drop(feed);
                s.notify();
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
        mine_address,
        settler_account,
        settler_bls,
        settler_reg_index,
        last_winner: Arc::new(tokio::sync::Mutex::new(None)),
        recent_draws: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        round_details: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        exec_lock: Arc::new(tokio::sync::Mutex::new(())),
        tx: tx.clone(),
        cosign_hub,
        covenant,
        pending_deposits: Arc::new(tokio::sync::Mutex::new(Vec::new())),
    };

    tokio::spawn(lifecycle(state.clone()));
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
        .route("/api/state", get(get_state))
        .route("/api/round/:n", get(get_round))
        .route("/api/exit", get(get_exit))
        .route("/api/covenant", get(get_covenant))
        .route("/api/deposit_address", get(get_deposit_address))
        .route("/api/deposit", post(post_deposit))
        .route("/api/covenant/genesis", post(post_genesis))
        .route("/api/covenant/refresh", post(post_refresh))
        .route("/api/covenant/unroll", post(post_unroll))
        .route("/api/settle_assertion", post(post_settle_assertion))
        .route("/api/settle", post(post_settle))
        .route("/api/broadcast", post(post_broadcast))
        .route("/api/faucet", post(post_faucet))
        .route("/api/call", post(post_call))
        .route("/api/withdraw", post(post_withdraw))
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
