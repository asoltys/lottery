//! Standalone harness to prove the live WS refresh-cosign end-to-end WITHOUT the
//! full engine: it runs only the cosign hub + a `/trigger` endpoint. Point the
//! node client harness (cosign_client_test.mjs) at it: clients connect, the
//! trigger drives a real Projector key-path refresh, and the server reports
//! whether the N-of-N aggregate signature verifies against the old covenant key.
//!
//! Run:  cargo run --bin cosign_test_server   (listens on 127.0.0.1:8099)

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use cube::transmutative::secp::into::IntoScalar;
use cube::transmutative::secp::schnorr::LiftScalar;
use lottery_arcade::cosign::{cosign_ws, CosignHub, DepositParams, GenesisDeposit, RefreshParams};

#[derive(Deserialize)]
struct Alloc {
    account: String,
    value: u64,
}
#[derive(Deserialize)]
struct TriggerReq {
    allocations: Vec<Alloc>,
    #[serde(default = "default_expiry")]
    expiry: u32,
    #[serde(default)]
    prev_txid: Option<String>,
    #[serde(default)]
    prev_vout: u32,
    #[serde(default = "default_prev_value")]
    prev_value: u64,
    #[serde(default = "default_fee")]
    fee: u64,
}
fn default_expiry() -> u32 {
    800_000
}
fn default_prev_value() -> u64 {
    0
}
fn default_fee() -> u64 {
    200
}

async fn connected(State(hub): State<CosignHub>) -> Json<Value> {
    let c: Vec<String> = hub.connected().await.iter().map(hex::encode).collect();
    Json(json!({ "connected": c }))
}

async fn trigger(State(hub): State<CosignHub>, Json(req): Json<TriggerReq>) -> Json<Value> {
    run_trigger(hub, req, false).await
}

// Malicious-engine variant: divert the pot to an engine-only P2TR while the
// context still advertises the honest covenant. A verifying client must refuse.
async fn trigger_evil(State(hub): State<CosignHub>, Json(req): Json<TriggerReq>) -> Json<Value> {
    run_trigger(hub, req, true).await
}

async fn run_trigger(hub: CosignHub, req: TriggerReq, evil: bool) -> Json<Value> {
    let allocations: Vec<([u8; 32], u64)> = req
        .allocations
        .iter()
        .filter_map(|a| {
            hex::decode(a.account.trim_start_matches("0x"))
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(|k| (k, a.value))
        })
        .collect();
    if allocations.len() != req.allocations.len() {
        return Json(json!({ "ok": false, "error": "bad account key" }));
    }
    let total: u64 = allocations.iter().map(|(_, v)| v).sum();
    let prev_value = if req.prev_value == 0 { total } else { req.prev_value };
    let prev_txid = req
        .prev_txid
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .unwrap_or([0xc0; 32]);

    // theft destination: a P2TR to the engine key (steals the pot).
    let override_out_spk = if evil {
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&hub.engine_key());
        Some(spk)
    } else {
        None
    };

    // new state == old state for the harness (a no-op refresh); the point is to
    // prove the N-of-N key-path signature, not a value transition.
    let params = RefreshParams {
        old_allocations: allocations.clone(),
        old_expiry: req.expiry,
        new_allocations: allocations,
        new_expiry: req.expiry + 1_000,
        prev_txid,
        prev_vout: req.prev_vout,
        prev_value,
        fee: req.fee,
        override_out_spk,
    };

    let label = if evil { "harness-refresh-EVIL" } else { "harness-refresh" };
    match hub.run_refresh(params, label, Duration::from_secs(8)).await {
        Ok(r) => Json(json!({
            "ok": true,
            "valid": r.valid,
            "agg_sig": hex::encode(r.agg_sig),
            "message": hex::encode(r.message),
            "agg_key": hex::encode(r.agg_key_xonly),
            "txid": r.txid,
            "signed_tx": r.signed_tx_hex,
        })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize)]
struct DepositReq {
    account: String,
    #[serde(default)]
    prev_txid: Option<String>,
    #[serde(default)]
    prev_vout: u32,
    #[serde(default = "default_deposit_value")]
    prev_value: u64,
    #[serde(default = "default_fee")]
    fee: u64,
    #[serde(default)]
    dest_spk: Option<String>,
}
fn default_deposit_value() -> u64 {
    100_000
}

async fn deposit(State(hub): State<CosignHub>, Json(req): Json<DepositReq>) -> Json<Value> {
    let account_key = match hex::decode(req.account.trim_start_matches("0x"))
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return Json(json!({ "ok": false, "error": "bad account key" })),
    };
    let prev_txid = req
        .prev_txid
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .unwrap_or([0xd0; 32]);
    // default destination: a P2TR to the engine key (a valid spk; the harness
    // only needs to prove the 2-of-2 key-path signature, not a real covenant).
    let dest_spk = req
        .dest_spk
        .as_deref()
        .and_then(|h| hex::decode(h).ok())
        .unwrap_or_else(|| {
            let mut spk = vec![0x51, 0x20];
            spk.extend_from_slice(&hub.engine_key());
            spk
        });

    let params = DepositParams {
        account_key,
        prev_txid,
        prev_vout: req.prev_vout,
        prev_value: req.prev_value,
        dest_spk,
        fee: req.fee,
    };
    match hub.run_deposit(params, "harness-deposit", Duration::from_secs(20)).await {
        Ok(r) => Json(json!({
            "ok": true,
            "valid": r.valid,
            "agg_sig": hex::encode(r.agg_sig),
            "message": hex::encode(r.message),
            "agg_key": hex::encode(r.agg_key_xonly),
            "txid": r.txid,
            "signed_tx": r.signed_tx_hex,
        })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[derive(Deserialize)]
struct GenesisDepositReq {
    account: String,
    prev_txid: String,
    #[serde(default)]
    prev_vout: u32,
    prev_value: u64,
}
#[derive(Deserialize)]
struct GenesisReq {
    deposits: Vec<GenesisDepositReq>,
    #[serde(default = "default_expiry")]
    expiry: u32,
    #[serde(default = "default_fee")]
    fee: u64,
}

async fn genesis(State(hub): State<CosignHub>, Json(req): Json<GenesisReq>) -> Json<Value> {
    let mut deposits = Vec::new();
    let mut allocations = Vec::new();
    for d in &req.deposits {
        let account = match hex::decode(d.account.trim_start_matches("0x"))
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            Some(k) => k,
            None => return Json(json!({ "ok": false, "error": "bad account key" })),
        };
        let prev_txid = match hex::decode(&d.prev_txid).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            Some(t) => t,
            None => return Json(json!({ "ok": false, "error": "bad prev_txid" })),
        };
        deposits.push(GenesisDeposit { account_key: account, prev_txid, prev_vout: d.prev_vout, prev_value: d.prev_value });
        allocations.push((account, d.prev_value)); // genesis: each depositor's claim = their deposit
    }
    // the covenant value is total deposits minus the genesis fee; reduce the
    // largest allocation by the fee so Σ allocations == covenant value.
    if let Some(max) = allocations.iter_mut().max_by_key(|(_, v)| *v) {
        max.1 = max.1.saturating_sub(req.fee);
    }
    match hub.run_genesis(deposits, allocations, req.expiry, req.fee, Duration::from_secs(20)).await {
        Ok(r) => Json(json!({
            "ok": true, "valid": r.valid, "txid": r.txid, "signed_tx": r.signed_tx_hex,
        })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[tokio::main]
async fn main() {
    // fixed engine secret for the harness; engine x-only key is its even-Y pubkey.
    let engine_secret: [u8; 32] = {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        s
    };
    let engine_key = engine_secret
        .into_scalar()
        .unwrap()
        .lift()
        .base_point_mul()
        .serialize_xonly();
    println!("engine x-only key: {}", hex::encode(engine_key));

    let hub = CosignHub::new(engine_secret, engine_key);
    let app = Router::new()
        .route("/cosign", get(cosign_ws))
        .route("/connected", get(connected))
        .route("/trigger", post(trigger))
        .route("/trigger_evil", post(trigger_evil))
        .route("/deposit", post(deposit))
        .route("/genesis", post(genesis))
        .with_state(hub);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8099").await.unwrap();
    println!("cosign test server on http://127.0.0.1:8099  (/cosign ws, /trigger, /connected)");
    let _ = Arc::new(()); // silence unused import if any
    axum::serve(listener, app).await.unwrap();
}
