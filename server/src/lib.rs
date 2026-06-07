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
use axum::extract::{Path, Query, State};
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
}

impl ArcadeState {
    fn notify(&self) {
        let _ = self.tx.send(());
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
        .route("/", get(serve_index))
        .route("/bundle.js", get(serve_bundle))
        .route("/api/state", get(get_state))
        .route("/api/round/:n", get(get_round))
        .route("/api/exit", get(get_exit))
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
