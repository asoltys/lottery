//! Live N-of-N MuSig2 REFRESH cosign over WebSocket — the non-custodial keystone.
//!
//! A contract pot lives in a funding (covenant) output locked to a Projector
//! value-bound MuSig2 key path (all participants + engine). To move the pot to a
//! new state (a round settle, a deposit, a payout) the engine must spend the old
//! covenant into the new one — a taproot KEY-PATH spend of the N-of-N aggregate.
//! That spend can only happen if EVERY participant co-signs, so no operator can
//! move the pot unilaterally. This module drives that cosign live: each player's
//! browser holds a WebSocket here and contributes a nonce then a partial
//! signature (computed by the verified `musig.mjs`, byte-identical to cube's
//! `partial_sign`). The engine aggregates them into the 64-byte key-path witness.
//!
//! Protocol (2-round MuSig2, one WS per participant):
//!   round 1: server → client  `start`     (message, pubkeys, tweak, your value/index)
//!            client → server  `nonce`     (proj_pubkey, hiding, binding)
//!   round 2: server → client  `aggnonces` (every signer's public nonces)
//!            client → server  `partial`   (proj_pubkey, partial scalar)
//!   done:    server → client  `complete`  (agg_sig, txid) | `abort` (reason)
//!
//! TRUST NOTE (increment 2): the client currently signs the server-provided
//! sighash. The Projector value-binding guarantees the engine cannot reattribute
//! VALUE behind a participant's back, but a fully paranoid client should also
//! rebuild the next covenant and confirm its own exitable leaf before signing
//! (client-side tx verification — increment 3). This is documented, not silent.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};

use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use cube::constructive::txout_types::lift::lift_versions::liftv2::cosign::EngineCosigner;
use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
use cube::constructive::txout_types::timeout_tree::funding_taproot;
use cube::constructive::txout_types::timeout_tree::refresh::{
    covenant_scriptpubkey, engine_projected_pubkey, engine_projected_secret,
    participant_projected_pubkey, refresh_keyagg,
};
use cube::transmutative::hash::{Hash, HashTag};
use cube::transmutative::musig::session::MusigSessionCtx;
use cube::transmutative::secp::into::{IntoPoint, IntoScalar};
use cube::transmutative::secp::schnorr::{verify_xonly, LiftScalar, SchnorrSigningMode};
use secp::{Point, Scalar};

// ---------- wire protocol ----------

#[derive(Serialize, Deserialize, Clone)]
pub struct NonceMsg {
    pub pubkey: String, // 33-byte projected pubkey hex
    pub hiding: String, // 33-byte hiding nonce pubkey hex
    pub binding: String, // 33-byte binding nonce pubkey hex
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMsg {
    #[serde(rename = "start")]
    Start {
        session: String,
        label: String,
        kind: String,         // "refresh" (Projector-projected) | "deposit" (plain 2-of-2)
        project: bool,        // true: sign with projected secret; false: even-Y account secret
        message: String,      // 32-byte sighash hex (what the client signs)
        pubkeys: Vec<String>, // all signers' pubkeys (33-byte hex)
        tweak: String,        // taproot tweak (32-byte hex)
        your_pubkey: String,  // this client's signing pubkey (so it can self-check)
        your_value: u64,      // value this client's key is projected by (refresh only)
        your_index: u32,      // this client's signer index (refresh only)
        ctx: Value,           // full tx context so the client rebuilds + verifies what it signs
    },
    #[serde(rename = "aggnonces")]
    AggNonces { session: String, nonces: Vec<NonceMsg> },
    #[serde(rename = "complete")]
    Complete { session: String, agg_sig: String, txid: Option<String> },
    #[serde(rename = "abort")]
    Abort { session: String, reason: String },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMsg {
    #[serde(rename = "hello")]
    Hello { account: String }, // 32-byte x-only account key hex (even-Y)
    #[serde(rename = "nonce")]
    Nonce { session: String, pubkey: String, hiding: String, binding: String },
    #[serde(rename = "partial")]
    Partial { session: String, pubkey: String, partial: String },
}

// A message routed from a connection's read loop into an active session.
enum SessionInput {
    Nonce(NonceMsg),
    Partial { pubkey: String, partial: String },
}

// ---------- hub ----------

#[derive(Clone)]
pub struct CosignHub {
    engine_secret: Arc<[u8; 32]>, // raw engine secret (lifted to even-Y when signing)
    engine_key: [u8; 32],         // engine x-only pubkey
    // account_key -> sender to that connection's socket-writer
    participants: Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<ServerMsg>>>>,
    // session_id -> inbox for that session's incoming nonces/partials
    sessions: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<SessionInput>>>>,
    // monotonic session counter (Math.random/Date are fine here; this is the server)
    counter: Arc<Mutex<u64>>,
}

/// Parameters for one covenant refresh (old state → new state).
pub struct RefreshParams {
    pub old_allocations: Vec<([u8; 32], u64)>,
    pub old_expiry: u32,
    pub new_allocations: Vec<([u8; 32], u64)>,
    pub new_expiry: u32,
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub prev_value: u64,
    pub fee: u64,
    /// TEST-ONLY: if set, the actual tx output uses this spk instead of the honest
    /// next-covenant spk, while the context still advertises the honest
    /// allocations — models a malicious engine trying to divert the pot. A
    /// verifying client recomputes the covenant + sighash and must refuse.
    pub override_out_spk: Option<Vec<u8>>,
}

/// The signed refresh, ready to broadcast.
pub struct RefreshResult {
    pub agg_sig: [u8; 64],
    pub message: [u8; 32],
    pub agg_key_xonly: [u8; 32],
    pub valid: bool,
    pub signed_tx_hex: String,
    pub txid: String,
}

/// Parameters for one LiftV2 deposit lift-in (spend a 2-of-2 account+engine
/// deposit output into the pot covenant via a cooperative key-path cosign).
pub struct DepositParams {
    pub account_key: [u8; 32],
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub prev_value: u64,
    pub dest_spk: Vec<u8>, // where the lifted funds go (e.g. the pot covenant spk)
    pub fee: u64,
}

/// One deposit feeding the genesis tx (a LiftV2 UTXO to be lifted into the pot).
pub struct GenesisDeposit {
    pub account_key: [u8; 32],
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub prev_value: u64,
}

fn pt(hexstr: &str) -> Option<Point> {
    Point::from_hex(hexstr).ok()
}
fn ser_pt(p: &Point) -> String {
    hex::encode(p.serialize())
}

impl CosignHub {
    pub fn new(engine_secret: [u8; 32], engine_key: [u8; 32]) -> Self {
        CosignHub {
            engine_secret: Arc::new(engine_secret),
            engine_key,
            participants: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(Mutex::new(0)),
        }
    }

    /// How many participant sockets are currently connected.
    pub async fn connected(&self) -> Vec<[u8; 32]> {
        self.participants.lock().await.keys().cloned().collect()
    }

    /// The engine's x-only key (for callers that need the keyagg counterpart).
    pub fn engine_key(&self) -> [u8; 32] {
        self.engine_key
    }

    // Deterministic, message-bound engine nonce secrets (never reused across
    // sighashes; each refresh has a unique sighash → unique nonces). Safe for a
    // single-engine signer; not safe to copy for a multi-engine setup.
    fn engine_nonces(&self, sighash: &[u8; 32]) -> (Scalar, Scalar) {
        let derive = |tag: &str| -> Scalar {
            let mut pre = Vec::with_capacity(64);
            pre.extend_from_slice(sighash);
            pre.extend_from_slice(self.engine_secret.as_ref());
            pre.hash(Some(HashTag::CustomString(tag.to_string())))
                .into_reduced_scalar()
                .expect("nonce scalar")
        };
        (derive("CubeArcadeNonce/h"), derive("CubeArcadeNonce/b"))
    }

    /// Drive one live refresh cosign to completion (or abort on timeout). Returns
    /// the aggregated 64-byte key-path signature + the assembled, broadcastable tx.
    pub async fn run_refresh(
        &self,
        mut p: RefreshParams,
        label: &str,
        round_timeout: Duration,
    ) -> Result<RefreshResult, String> {
        // Canonicalize allocation order (defines projection indices) — both the
        // on-chain funding and this refresh MUST agree, so sort by account key.
        p.old_allocations.sort_by(|a, b| a.0.cmp(&b.0));
        p.new_allocations.sort_by(|a, b| a.0.cmp(&b.0));

        // --- build the refresh tx + key-path sighash (BIP341) ---
        let old_taproot = funding_taproot(self.engine_key, &p.old_allocations, p.old_expiry)
            .ok_or("funding_taproot(old) failed")?;
        let old_spk = ScriptBuf::from_bytes(old_taproot.spk().ok_or("old spk")?);
        let prev_txout = TxOut {
            value: Amount::from_sat(p.prev_value),
            script_pubkey: old_spk,
        };
        let new_spk = ScriptBuf::from_bytes(
            covenant_scriptpubkey(self.engine_key, &p.new_allocations, p.new_expiry)
                .ok_or("covenant_scriptpubkey(new) failed")?,
        );
        // The new covenant holds exactly the sum of its leaves; the tx fee is
        // whatever's left over (prev_value - out_value). Conservation: the client
        // checks out_value == Σ new_allocations and prev_value >= out_value.
        let new_total: u64 = p.new_allocations.iter().map(|(_, v)| v).sum();
        let out_value = new_total;
        if p.prev_value < out_value {
            return Err("prev_value < new covenant total".into());
        }
        let outpoint = OutPoint::new(
            Txid::from_byte_array(p.prev_txid),
            p.prev_vout,
        );
        let mut refresh_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: match &p.override_out_spk {
                    Some(spk) => ScriptBuf::from_bytes(spk.clone()),
                    None => new_spk,
                },
            }],
        };
        let sighash = SighashCache::new(&refresh_tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[prev_txout]),
                TapSighashType::Default,
            )
            .map_err(|e| format!("sighash: {e}"))?
            .to_byte_array();

        // --- MuSig2 keyagg over (participants + engine), with funding tweak ---
        let keyagg = refresh_keyagg(self.engine_key, &p.old_allocations, p.old_expiry)
            .ok_or("refresh_keyagg failed")?;
        let tweak_hex = hex::encode(old_taproot.tap_tweak());

        // engine projected pubkey + secret (engine signs by the pot total).
        let engine_pub = engine_projected_pubkey(self.engine_key.into_point().map_err(|_| "engine point")?, &p.old_allocations)
            .ok_or("engine_projected_pubkey")?;
        let engine_sec = engine_projected_secret(
            (*self.engine_secret).into_scalar().map_err(|_| "engine scalar")?.lift(),
            &p.old_allocations,
        )
        .ok_or("engine_projected_secret")?;

        // each participant's projected pubkey (index = position in sorted allocs).
        let mut participant_pubs: Vec<([u8; 32], Point, u64, u32)> = Vec::new(); // (account, proj_pub, value, index)
        for (i, (account, value)) in p.old_allocations.iter().enumerate() {
            let base = account.into_point().map_err(|_| "account point")?;
            let proj = participant_projected_pubkey(base, *value, i as u32)
                .ok_or("participant_projected_pubkey")?;
            participant_pubs.push((*account, proj, *value, i as u32));
        }

        // full pubkey list (all signers) for the clients' keyagg.
        let mut pubkeys: Vec<String> = participant_pubs.iter().map(|(_, p, _, _)| ser_pt(p)).collect();
        pubkeys.push(ser_pt(&engine_pub));

        // --- session bookkeeping ---
        let session_id = {
            let mut c = self.counter.lock().await;
            *c += 1;
            format!("refresh-{}", *c)
        };
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<SessionInput>();
        self.sessions.lock().await.insert(session_id.clone(), inbox_tx);

        // snapshot the connected sockets we need; abort early if anyone is missing.
        let sockets = {
            let parts = self.participants.lock().await;
            let mut map: HashMap<[u8; 32], mpsc::UnboundedSender<ServerMsg>> = HashMap::new();
            for (account, _, _, _) in &participant_pubs {
                match parts.get(account) {
                    Some(tx) => {
                        map.insert(*account, tx.clone());
                    }
                    None => {
                        self.sessions.lock().await.remove(&session_id);
                        return Err(format!("participant {} not connected", hex::encode(account)));
                    }
                }
            }
            map
        };

        // start the MuSig2 session; pre-insert the engine's nonce.
        let mut session = MusigSessionCtx::new(&keyagg, sighash).ok_or("session new")?;
        let (eng_hn, eng_bn) = self.engine_nonces(&sighash);
        if !session.insert_nonce(engine_pub, eng_hn.base_point_mul(), eng_bn.base_point_mul()) {
            self.sessions.lock().await.remove(&session_id);
            return Err("engine nonce rejected by keyagg".into());
        }

        // tx context so each client can rebuild the covenant + sighash and verify
        // exactly what it signs (no trust in the server's asserted message).
        let alloc_json = |allocs: &[([u8; 32], u64)]| -> Value {
            Value::Array(
                allocs
                    .iter()
                    .map(|(k, v)| json!({ "account": hex::encode(k), "value": v }))
                    .collect(),
            )
        };
        let ctx = json!({
            "kind": "refresh",
            "engine": hex::encode(self.engine_key),
            "old_allocations": alloc_json(&p.old_allocations),
            "old_expiry": p.old_expiry,
            "new_allocations": alloc_json(&p.new_allocations),
            "new_expiry": p.new_expiry,
            "prev_txid": hex::encode(p.prev_txid),
            "prev_vout": p.prev_vout,
            "prev_value": p.prev_value,
            "out_value": out_value,
        });

        // round 1: ask each participant for a nonce.
        for (account, proj, value, index) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::Start {
                session: session_id.clone(),
                label: label.to_string(),
                kind: "refresh".to_string(),
                project: true,
                message: hex::encode(sighash),
                pubkeys: pubkeys.clone(),
                tweak: tweak_hex.clone(),
                your_pubkey: ser_pt(proj),
                your_value: *value,
                your_index: *index,
                ctx: ctx.clone(),
            });
        }

        // collect participant nonces (keyed by their projected pubkey). The engine
        // nonce is NOT counted here (it's already in the session) — only the client
        // nonces are awaited, then merged into the broadcast set below.
        let mut nonces: HashMap<String, NonceMsg> = HashMap::new();
        let want_nonces = participant_pubs.len();
        let r1 = self
            .collect(&mut inbox_rx, round_timeout, |input, st| match input {
                SessionInput::Nonce(n) => {
                    // validate + register the nonce in the session.
                    if let (Some(k), Some(h), Some(b)) =
                        (pt(&n.pubkey), pt(&n.hiding), pt(&n.binding))
                    {
                        if session.insert_nonce(k, h, b) {
                            st.insert(n.pubkey.clone(), n);
                        }
                    }
                    st.len() == want_nonces
                }
                _ => false,
            }, &mut nonces, want_nonces)
            .await;
        if r1.is_err() {
            self.abort(&session_id, &sockets, "timed out collecting nonces").await;
            return Err("timed out collecting nonces".into());
        }

        // round 2: broadcast the full nonce set (clients + engine), request partials.
        nonces.insert(
            ser_pt(&engine_pub),
            NonceMsg {
                pubkey: ser_pt(&engine_pub),
                hiding: ser_pt(&eng_hn.base_point_mul()),
                binding: ser_pt(&eng_bn.base_point_mul()),
            },
        );
        let nonce_vec: Vec<NonceMsg> = pubkeys
            .iter()
            .filter_map(|k| nonces.get(k).cloned())
            .collect();
        for (account, _, _, _) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::AggNonces {
                session: session_id.clone(),
                nonces: nonce_vec.clone(),
            });
        }

        // engine partial.
        let engine_partial = session
            .partial_sign(engine_sec, eng_hn, eng_bn)
            .ok_or("engine partial_sign failed")?;
        session.insert_partial_sig(engine_pub, engine_partial);

        // collect participant partials.
        let mut partials: HashMap<String, ()> = HashMap::new();
        let want_partials = participant_pubs.len();
        let r2 = self
            .collect(&mut inbox_rx, round_timeout, |input, st| match input {
                SessionInput::Partial { pubkey, partial } => {
                    if let (Some(k), Ok(sc)) = (pt(&pubkey), Scalar::from_hex(&partial)) {
                        if session.insert_partial_sig(k, sc) {
                            st.insert(pubkey.clone(), ());
                        }
                    }
                    st.len() == want_partials
                }
                _ => false,
            }, &mut partials, want_partials)
            .await;
        if r2.is_err() {
            self.abort(&session_id, &sockets, "timed out collecting partials").await;
            return Err("timed out collecting partials".into());
        }

        // aggregate + verify.
        let agg_sig = session.full_agg_sig().ok_or("full_agg_sig failed")?;
        let agg_key_xonly = old_taproot
            .tweaked_key()
            .ok_or("tweaked_key")?
            .serialize_xonly();
        let valid = verify_xonly(agg_key_xonly, sighash, agg_sig, SchnorrSigningMode::BIP340);

        // assemble the key-path witness (single 64-byte schnorr sig, SIGHASH_DEFAULT).
        let mut witness = Witness::new();
        witness.push(agg_sig.to_vec());
        refresh_tx.input[0].witness = witness;
        let signed_tx_hex = hex::encode(bitcoin::consensus::encode::serialize(&refresh_tx));
        let txid = refresh_tx.compute_txid().to_string();

        // notify clients.
        for (account, _, _, _) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::Complete {
                session: session_id.clone(),
                agg_sig: hex::encode(agg_sig),
                txid: Some(txid.clone()),
            });
        }
        self.sessions.lock().await.remove(&session_id);

        Ok(RefreshResult {
            agg_sig,
            message: sighash,
            agg_key_xonly,
            valid,
            signed_tx_hex,
            txid,
        })
    }

    /// Cosign ONE LiftV2 deposit input of a (pre-built) tx: the depositor's 2-of-2
    /// (account+engine) key-path partial over the given input sighash, aggregated
    /// with the engine's into the 64-byte witness. `ctx` describes the whole tx so
    /// the depositor's browser verifies what it signs. Returns the input's sig.
    async fn cosign_deposit_input(
        &self,
        account_key: [u8; 32],
        sighash: [u8; 32],
        ctx: Value,
        label: &str,
        round_timeout: Duration,
    ) -> Result<[u8; 64], String> {
        let deposit_taproot = return_liftv2_taproot(account_key, self.engine_key)
            .ok_or("return_liftv2_taproot failed")?;
        let account_pt = account_key.into_point().map_err(|_| "account point")?;
        let engine_pt = self.engine_key.into_point().map_err(|_| "engine point")?;
        let pubkeys = vec![ser_pt(&account_pt), ser_pt(&engine_pt)];
        let tweak_hex = hex::encode(deposit_taproot.tap_tweak());

        let session_id = {
            let mut c = self.counter.lock().await;
            *c += 1;
            format!("deposit-{}", *c)
        };
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<SessionInput>();
        self.sessions.lock().await.insert(session_id.clone(), inbox_tx);
        let socket = match self.participants.lock().await.get(&account_key) {
            Some(tx) => tx.clone(),
            None => {
                self.sessions.lock().await.remove(&session_id);
                return Err(format!("depositor {} not connected", hex::encode(account_key)));
            }
        };

        let _ = socket.send(ServerMsg::Start {
            session: session_id.clone(),
            label: label.to_string(),
            kind: "deposit".to_string(),
            project: false,
            message: hex::encode(sighash),
            pubkeys: pubkeys.clone(),
            tweak: tweak_hex.clone(),
            your_pubkey: ser_pt(&account_pt),
            your_value: 0,
            your_index: 0,
            ctx,
        });

        let mut client_nonce: Option<NonceMsg> = None;
        let r1 = self
            .collect(&mut inbox_rx, round_timeout, |input, st: &mut Option<NonceMsg>| match input {
                SessionInput::Nonce(n) => {
                    if pt(&n.hiding).is_some() && pt(&n.binding).is_some() {
                        *st = Some(n);
                        return true;
                    }
                    false
                }
                _ => false,
            }, &mut client_nonce, 1)
            .await;
        if r1.is_err() || client_nonce.is_none() {
            self.abort_one(&session_id, &socket, "timed out collecting nonce").await;
            return Err("timed out collecting deposit nonce".into());
        }
        let client_nonce = client_nonce.unwrap();
        let client_h = pt(&client_nonce.hiding).ok_or("bad client hiding nonce")?;
        let client_b = pt(&client_nonce.binding).ok_or("bad client binding nonce")?;

        let (eng_hn, eng_bn) = self.engine_nonces(&sighash);
        let engine = EngineCosigner::begin(
            account_key,
            self.engine_key,
            (*self.engine_secret).into_scalar().map_err(|_| "engine scalar")?.lift(),
            eng_hn,
            eng_bn,
            client_h,
            client_b,
            sighash,
        )
        .ok_or("engine begin failed")?;
        let (engine_h, engine_b) = engine.engine_public_nonces();

        let nonce_vec = vec![
            client_nonce.clone(),
            NonceMsg {
                pubkey: ser_pt(&engine_pt),
                hiding: ser_pt(&engine_h),
                binding: ser_pt(&engine_b),
            },
        ];
        let _ = socket.send(ServerMsg::AggNonces { session: session_id.clone(), nonces: nonce_vec });

        let mut client_partial: Option<Scalar> = None;
        let r2 = self
            .collect(&mut inbox_rx, round_timeout, |input, st: &mut Option<Scalar>| match input {
                SessionInput::Partial { partial, .. } => match Scalar::from_hex(&partial) {
                    Ok(sc) => { *st = Some(sc); true }
                    Err(_) => false,
                },
                _ => false,
            }, &mut client_partial, 1)
            .await;
        if r2.is_err() || client_partial.is_none() {
            self.abort_one(&session_id, &socket, "timed out collecting partial").await;
            return Err("timed out collecting deposit partial".into());
        }

        let agg_sig = engine
            .complete(client_partial.unwrap())
            .ok_or("aggregate failed (bad client partial)")?;
        let agg_key_xonly = deposit_taproot.tweaked_key().ok_or("tweaked_key")?.serialize_xonly();
        if !verify_xonly(agg_key_xonly, sighash, agg_sig, SchnorrSigningMode::BIP340) {
            self.abort_one(&session_id, &socket, "deposit signature invalid").await;
            return Err("deposit input signature did not verify".into());
        }
        let _ = socket.send(ServerMsg::Complete {
            session: session_id.clone(),
            agg_sig: hex::encode(agg_sig),
            txid: None,
        });
        self.sessions.lock().await.remove(&session_id);
        Ok(agg_sig)
    }

    // Full-tx context for a deposit input, so the browser rebuilds + verifies the
    // exact (multi-input) tx it signs. `inputs` lists every deposit input as
    // (account, txid, vout, value); `covenant` (optional) lets the depositor
    // confirm the output really is a covenant in which it keeps an exitable claim.
    fn deposit_ctx(
        &self,
        my_account: [u8; 32],
        input_index: usize,
        inputs: &[([u8; 32], [u8; 32], u32, u64)],
        out_value: u64,
        out_spk: &[u8],
        covenant: Option<Value>,
    ) -> Value {
        let inputs_json: Vec<Value> = inputs
            .iter()
            .map(|(acct, txid, vout, value)| json!({
                "account": hex::encode(acct),
                "txid": hex::encode(txid),
                "vout": vout,
                "value": value,
            }))
            .collect();
        json!({
            "kind": "deposit",
            "engine": hex::encode(self.engine_key),
            "account": hex::encode(my_account),
            "input_index": input_index,
            "inputs": inputs_json,
            "outputs": [{ "value": out_value, "spk": hex::encode(out_spk) }],
            "covenant": covenant,
        })
    }

    /// Drive a single LiftV2 deposit lift-in into `dest_spk` (a 1-input tx).
    pub async fn run_deposit(
        &self,
        p: DepositParams,
        label: &str,
        round_timeout: Duration,
    ) -> Result<RefreshResult, String> {
        let deposit_taproot = return_liftv2_taproot(p.account_key, self.engine_key)
            .ok_or("return_liftv2_taproot failed")?;
        let deposit_spk = ScriptBuf::from_bytes(deposit_taproot.spk().ok_or("deposit spk")?);
        let prev_txout = TxOut { value: Amount::from_sat(p.prev_value), script_pubkey: deposit_spk };
        let outpoint = OutPoint::new(Txid::from_byte_array(p.prev_txid), p.prev_vout);
        let out_value = p.prev_value.saturating_sub(p.fee);
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from_bytes(p.dest_spk.clone()),
            }],
        };
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prev_txout]), TapSighashType::Default)
            .map_err(|e| format!("sighash: {e}"))?
            .to_byte_array();

        let ctx = self.deposit_ctx(
            p.account_key, 0,
            &[(p.account_key, p.prev_txid, p.prev_vout, p.prev_value)],
            out_value, &p.dest_spk, None,
        );
        let agg_sig = self.cosign_deposit_input(p.account_key, sighash, ctx, label, round_timeout).await?;

        let agg_key_xonly = deposit_taproot.tweaked_key().ok_or("tweaked_key")?.serialize_xonly();
        let valid = verify_xonly(agg_key_xonly, sighash, agg_sig, SchnorrSigningMode::BIP340);
        let mut witness = Witness::new();
        witness.push(agg_sig.to_vec());
        tx.input[0].witness = witness;
        Ok(RefreshResult {
            agg_sig,
            message: sighash,
            agg_key_xonly,
            valid,
            signed_tx_hex: hex::encode(bitcoin::consensus::encode::serialize(&tx)),
            txid: tx.compute_txid().to_string(),
        })
    }

    /// GENESIS: combine many LiftV2 deposits into the pot covenant in one tx —
    /// inputs are the deposit UTXOs (each 2-of-2 cosigned by its depositor), the
    /// single output is the covenant over `allocations`. Each depositor cosigns
    /// only its own input, verifying the whole tx (incl. its covenant claim).
    pub async fn run_genesis(
        &self,
        deposits: Vec<GenesisDeposit>,
        mut allocations: Vec<([u8; 32], u64)>,
        expiry: u32,
        fee: u64,
        round_timeout: Duration,
    ) -> Result<RefreshResult, String> {
        if deposits.is_empty() {
            return Err("genesis needs at least one deposit".into());
        }
        allocations.sort_by(|a, b| a.0.cmp(&b.0));
        let covenant_spk = covenant_scriptpubkey(self.engine_key, &allocations, expiry)
            .ok_or("covenant_scriptpubkey failed")?;
        let total_in: u64 = deposits.iter().map(|d| d.prev_value).sum();
        let out_value = total_in.saturating_sub(fee);

        // prevouts (each deposit's LiftV2 output) + inputs.
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(deposits.len());
        let mut txins: Vec<TxIn> = Vec::with_capacity(deposits.len());
        for d in &deposits {
            let dt = return_liftv2_taproot(d.account_key, self.engine_key).ok_or("liftv2 taproot")?;
            prevouts.push(TxOut {
                value: Amount::from_sat(d.prev_value),
                script_pubkey: ScriptBuf::from_bytes(dt.spk().ok_or("deposit spk")?),
            });
            txins.push(TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(d.prev_txid), d.prev_vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: txins,
            output: vec![TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: ScriptBuf::from_bytes(covenant_spk.clone()),
            }],
        };

        let alloc_json = Value::Array(
            allocations
                .iter()
                .map(|(k, v)| json!({ "account": hex::encode(k), "value": v }))
                .collect(),
        );
        let covenant_ctx = json!({ "allocations": alloc_json, "expiry": expiry });
        let input_tuples: Vec<([u8; 32], [u8; 32], u32, u64)> = deposits
            .iter()
            .map(|d| (d.account_key, d.prev_txid, d.prev_vout, d.prev_value))
            .collect();

        // compute every input's key-path sighash up front (cache borrows tx), then
        // drop the cache so we can fill witnesses afterward.
        let sighashes: Vec<[u8; 32]> = {
            let mut cache = SighashCache::new(&tx);
            let mut v = Vec::with_capacity(deposits.len());
            for j in 0..deposits.len() {
                v.push(
                    cache
                        .taproot_key_spend_signature_hash(j, &Prevouts::All(&prevouts), TapSighashType::Default)
                        .map_err(|e| format!("sighash[{j}]: {e}"))?
                        .to_byte_array(),
                );
            }
            v
        };

        // cosign each deposit input (sequentially) over the full multi-input tx.
        let mut sigs: Vec<[u8; 64]> = Vec::with_capacity(deposits.len());
        for (j, d) in deposits.iter().enumerate() {
            let ctx = self.deposit_ctx(
                d.account_key, j, &input_tuples, out_value, &covenant_spk, Some(covenant_ctx.clone()),
            );
            let sig = self
                .cosign_deposit_input(d.account_key, sighashes[j], ctx, "genesis", round_timeout)
                .await?;
            sigs.push(sig);
        }
        for (j, sig) in sigs.into_iter().enumerate() {
            let mut w = Witness::new();
            w.push(sig.to_vec());
            tx.input[j].witness = w;
        }

        Ok(RefreshResult {
            agg_sig: [0u8; 64], // per-input sigs are in the witnesses; no single agg here
            message: [0u8; 32],
            agg_key_xonly: [0u8; 32],
            valid: true,
            signed_tx_hex: hex::encode(bitcoin::consensus::encode::serialize(&tx)),
            txid: tx.compute_txid().to_string(),
        })
    }

    async fn abort_one(
        &self,
        session_id: &str,
        socket: &mpsc::UnboundedSender<ServerMsg>,
        reason: &str,
    ) {
        let _ = socket.send(ServerMsg::Abort {
            session: session_id.to_string(),
            reason: reason.to_string(),
        });
        self.sessions.lock().await.remove(session_id);
    }

    // Drain the session inbox until `done(input, state)` returns true or timeout.
    async fn collect<S>(
        &self,
        rx: &mut mpsc::UnboundedReceiver<SessionInput>,
        timeout: Duration,
        mut handle: impl FnMut(SessionInput, &mut S) -> bool,
        state: &mut S,
        _want: usize,
    ) -> Result<(), ()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(input)) => {
                    if handle(input, state) {
                        return Ok(());
                    }
                }
                Ok(None) => return Err(()), // channel closed
                Err(_) => return Err(()),   // timed out
            }
        }
    }

    async fn abort(
        &self,
        session_id: &str,
        sockets: &HashMap<[u8; 32], mpsc::UnboundedSender<ServerMsg>>,
        reason: &str,
    ) {
        for tx in sockets.values() {
            let _ = tx.send(ServerMsg::Abort {
                session: session_id.to_string(),
                reason: reason.to_string(),
            });
        }
        self.sessions.lock().await.remove(session_id);
    }
}

// ---------- websocket connection ----------

pub async fn cosign_ws(ws: WebSocketUpgrade, State(hub): State<CosignHub>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| cosign_conn(socket, hub))
}

async fn cosign_conn(mut socket: WebSocket, hub: CosignHub) {
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();
    let mut my_account: Option<[u8; 32]> = None;

    loop {
        tokio::select! {
            // server → this socket
            Some(outgoing) = rx.recv() => {
                let txt = match serde_json::to_string(&outgoing) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(txt)).await.is_err() {
                    break;
                }
            }
            // this socket → server
            incoming = socket.recv() => {
                let msg = match incoming {
                    Some(Ok(m)) => m,
                    _ => break,
                };
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    _ => continue,
                };
                let cm: ClientMsg = match serde_json::from_str(&text) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                match cm {
                    ClientMsg::Hello { account } => {
                        if let Ok(bytes) = hex::decode(account.trim_start_matches("0x")) {
                            if let Ok(a) = <[u8; 32]>::try_from(bytes) {
                                my_account = Some(a);
                                hub.participants.lock().await.insert(a, tx.clone());
                            }
                        }
                    }
                    ClientMsg::Nonce { session, pubkey, hiding, binding } => {
                        if let Some(inbox) = hub.sessions.lock().await.get(&session) {
                            let _ = inbox.send(SessionInput::Nonce(NonceMsg { pubkey, hiding, binding }));
                        }
                    }
                    ClientMsg::Partial { session, pubkey, partial } => {
                        if let Some(inbox) = hub.sessions.lock().await.get(&session) {
                            let _ = inbox.send(SessionInput::Partial { pubkey, partial });
                        }
                    }
                }
            }
        }
    }

    if let Some(a) = my_account {
        hub.participants.lock().await.remove(&a);
    }
}
