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
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use cube::constructive::txout_types::lift::lift_versions::liftv2::cosign::EngineCosigner;
use cube::constructive::txout_types::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
use cube::constructive::txout_types::timeout_tree::{funding_taproot, TimeoutTree};
use cube::constructive::txout_types::timeout_tree::refresh::{
    covenant_scriptpubkey, engine_projected_pubkey, engine_projected_secret,
    participant_projected_pubkey, refresh_keyagg,
};
use cube::transmutative::hash::{Hash, HashTag};
use cube::transmutative::musig::session::MusigSessionCtx;
use cube::transmutative::secp::into::{IntoPoint, IntoScalar};
use cube::transmutative::secp::schnorr::{sign, verify_xonly, LiftScalar, SchnorrSigningMode};
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
    /// Cooperative WITHDRAW: if set, the refresh tx gets an extra FIRST output that
    /// pays `(value, dest_spk)` to a leaving player's own address, and the new
    /// covenant holds the rest. (leaver_account, value, dest_spk). All current
    /// members co-sign; the leaver verifies the payout is to their address, the
    /// others verify their claim is preserved. Nothing leaves the operator wallet.
    pub payout: Option<([u8; 32], u64, Vec<u8>)>,
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

/// Result of a covenant DISSOLVE: the engine spends the covenant (via its expiry
/// script path, no member cosign) into one LiftV2 output per member, each of which
/// its owner can unilaterally sweep with their own key. `outputs` lists each
/// member's resulting (account, vout, value) so the caller can re-queue them.
pub struct DissolveResult {
    pub signed_tx_hex: String,
    pub txid: String,
    pub outputs: Vec<([u8; 32], u32, u64)>,
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

/// A materialized VTXO leaf after the unroll: what a holder needs to unilaterally
/// sweep it (CSV exit path) with only its own key.
#[derive(Serialize)]
pub struct LeafInfo {
    pub account: String,
    pub value: u64,
    pub vout: u32,
    pub scriptpubkey: String,
    pub exit_script: String,
    pub control_block: String,
    pub exit_delay: u16,
    /// The disprove (fraud-proof) spend path, present when the leaf is locked to a
    /// round's garbled "invalid" label — empty otherwise.
    pub disprove_script: String,
    pub disprove_control_block: String,
    /// The winner-sweep spend path on a LOSER leaf, present when this settle is
    /// enforced — empty on the winner's own leaf and on unsettled unrolls. The
    /// proven winner spends it with the garbled VALID label to take the pot with
    /// no loser cooperation.
    pub winner_sweep_script: String,
    pub winner_sweep_control_block: String,
}

/// Result of pre-signing + assembling the unroll (covenant -> per-participant
/// VTXO leaves), broadcastable by anyone with nobody online.
#[derive(Serialize)]
pub struct UnrollResult {
    pub txid: String,
    pub signed_tx_hex: String,
    pub valid: bool,
    pub leaves: Vec<LeafInfo>,
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
        // The new covenant holds exactly the sum of its leaves; the tx fee is
        // whatever's left over (prev_value - out_value). Conservation: the client
        // checks out_value == Σ new_allocations and prev_value >= outputs.
        let new_total: u64 = p.new_allocations.iter().map(|(_, v)| v).sum();
        let out_value = new_total;
        let outpoint = OutPoint::new(Txid::from_byte_array(p.prev_txid), p.prev_vout);
        let payout_value = p.payout.as_ref().map(|(_, v, _)| *v).unwrap_or(0);
        if p.prev_value < out_value + payout_value {
            return Err("prev_value < outputs (payout + new covenant)".into());
        }
        // Build the outputs: a WITHDRAW payout (to a leaver's address) comes FIRST,
        // then the new covenant (omitted when the last member exits → empty allocs).
        let mut outputs: Vec<TxOut> = Vec::new();
        if let Some((_, pv, dest_spk)) = &p.payout {
            outputs.push(TxOut { value: Amount::from_sat(*pv), script_pubkey: ScriptBuf::from_bytes(dest_spk.clone()) });
        }
        if !p.new_allocations.is_empty() {
            let new_spk = ScriptBuf::from_bytes(
                covenant_scriptpubkey(self.engine_key, &p.new_allocations, p.new_expiry)
                    .ok_or("covenant_scriptpubkey(new) failed")?,
            );
            outputs.push(TxOut {
                value: Amount::from_sat(out_value),
                script_pubkey: match &p.override_out_spk { Some(spk) => ScriptBuf::from_bytes(spk.clone()), None => new_spk },
            });
        }
        if outputs.is_empty() { return Err("refresh has no outputs".into()); }
        let mut refresh_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
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
            // present iff this refresh is a cooperative withdraw (extra payout output).
            "payout_account": p.payout.as_ref().map(|(a, _, _)| hex::encode(a)),
            "payout_value": p.payout.as_ref().map(|(_, v, _)| *v),
            "payout_spk": p.payout.as_ref().map(|(_, _, spk)| hex::encode(spk)),
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

    /// UNROLL (unilateral-exit enabler): pre-sign the spend of the pot covenant
    /// into per-participant VTXO leaves via N-of-N cosign. Anyone can broadcast the
    /// result later with nobody online; each holder then CSV-sweeps its leaf.
    pub async fn run_unroll(
        &self,
        mut allocations: Vec<([u8; 32], u64)>,
        expiry: u32,
        prev_txid: [u8; 32],
        prev_vout: u32,
        prev_value: u64,
        exit_delay: u16,
        fee: u64,
        disprove_hash: Option<[u8; 32]>,
        // `(winner_key, valid_hash)` for a settle unroll: attaches a winner-sweep
        // path to every LOSER leaf so the proven winner can take the pot with no
        // loser cooperation. `None` on genesis/refresh unrolls (no winner yet).
        winner_sweep: Option<([u8; 32], [u8; 32])>,
        round_timeout: Duration,
    ) -> Result<UnrollResult, String> {
        allocations.sort_by(|a, b| a.0.cmp(&b.0));
        // When a round's settle is being enforced, every leaf carries that round's
        // garbled "invalid" label as its disprove lock — so any participant who can
        // disprove the settle reclaims their own VTXO leaf.
        let disprove_hashes: Option<Vec<[u8; 32]>> = disprove_hash.map(|h| vec![h; allocations.len()]);
        // build_with_sweep takes (valid_hash, winner_key); our param is
        // (winner_key, valid_hash) to match the settle call site (winner + label).
        let tree_sweep = winner_sweep.map(|(wk, vh)| (vh, wk));
        let tree = TimeoutTree::build_with_sweep(self.engine_key, &allocations, expiry, exit_delay, disprove_hashes.as_deref(), tree_sweep)
            .ok_or("timeout tree build failed")?;
        let mut outs = tree.unroll_outputs().ok_or("unroll outputs")?;
        if outs.is_empty() {
            return Err("no leaves to unroll".into());
        }
        // SELF-FUNDED unroll: bake the miner fee into the leaves so this pre-signed
        // tx is broadcastable STANDALONE by anyone — the watchtower, or a stranded
        // player force-exiting with no operator and no CPFP funder (which is what a
        // browser-only user is). That trustless property is why we don't use a feeless
        // TRUC+P2A unroll here (CPFP needs an external funder = the operator).
        //
        // Spread the fee EVENLY across every leaf (fee/N each) — the unroll is a shared
        // action anyone can trigger that forces EVERYONE on-chain, so no single holder
        // should bear its whole cost. The few-sat remainder lands on the largest leaf,
        // which can always absorb it without dusting.
        let n = outs.len() as u64;
        let per = fee / n;
        let rem = fee % n;
        for o in outs.iter_mut() {
            o.value = Amount::from_sat(o.value.to_sat().saturating_sub(per));
        }
        if rem > 0 {
            let big = outs.iter().enumerate().max_by_key(|(_, o)| o.value.to_sat()).map(|(i, _)| i).unwrap_or(0);
            outs[big].value = Amount::from_sat(outs[big].value.to_sat().saturating_sub(rem));
        }

        let covenant_taproot = funding_taproot(self.engine_key, &allocations, expiry)
            .ok_or("funding_taproot failed")?;
        let covenant_spk = ScriptBuf::from_bytes(covenant_taproot.spk().ok_or("covenant spk")?);
        let prev_txout = TxOut { value: Amount::from_sat(prev_value), script_pubkey: covenant_spk };
        let outpoint = OutPoint::new(Txid::from_byte_array(prev_txid), prev_vout);
        let mut unroll_tx = Transaction {
            version: Version::TWO, // self-funded (baked fee) → broadcastable standalone, no CPFP
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outs.clone(),
        };
        let sighash = SighashCache::new(&unroll_tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prev_txout]), TapSighashType::Default)
            .map_err(|e| format!("sighash: {e}"))?
            .to_byte_array();

        // map each output to its leaf (same order) for the client ctx + sweep data.
        let mut leaf_info: Vec<LeafInfo> = Vec::with_capacity(outs.len());
        let mut out_json: Vec<Value> = Vec::with_capacity(outs.len());
        for (k, leaf) in tree.leaves.iter().enumerate() {
            let spk = leaf.scriptpubkey().ok_or("leaf spk")?;
            let (_lh, script, cb) = leaf.exit_spend_elements().ok_or("leaf exit elements")?;
            // the disprove (fraud-proof) spend path, present iff a round lock is set.
            let (disprove_script, disprove_cb) = match leaf.disprove_spend_elements() {
                Some((_dlh, ds, dcb)) => (hex::encode(ds), hex::encode(dcb)),
                None => (String::new(), String::new()),
            };
            // the winner-sweep path, present iff this is a LOSER leaf in a settle.
            let (winner_sweep_script, winner_sweep_cb) = match leaf.winner_sweep_spend_elements() {
                Some((_wlh, ws, wcb)) => (hex::encode(ws), hex::encode(wcb)),
                None => (String::new(), String::new()),
            };
            out_json.push(json!({
                "value": outs[k].value.to_sat(),
                "spk": hex::encode(outs[k].script_pubkey.as_bytes()),
                "account": hex::encode(leaf.account_key),
            }));
            leaf_info.push(LeafInfo {
                account: hex::encode(leaf.account_key),
                value: outs[k].value.to_sat(),
                vout: k as u32,
                scriptpubkey: hex::encode(spk),
                exit_script: hex::encode(script),
                control_block: hex::encode(cb),
                exit_delay,
                disprove_script,
                disprove_control_block: disprove_cb,
                winner_sweep_script,
                winner_sweep_control_block: winner_sweep_cb,
            });
        }
        let alloc_json = Value::Array(
            allocations.iter().map(|(k, v)| json!({ "account": hex::encode(k), "value": v })).collect(),
        );
        let ctx = json!({
            "kind": "unroll",
            "engine": hex::encode(self.engine_key),
            "allocations": alloc_json,
            "expiry": expiry,
            "prev_txid": hex::encode(prev_txid),
            "prev_vout": prev_vout,
            "prev_value": prev_value,
            "outputs": out_json,
            // settle unrolls only: lets a cosigner recompute the same tree (incl.
            // each loser leaf's winner-sweep path) and verify what it signs.
            "winner": winner_sweep.map(|(wk, _)| hex::encode(wk)),
            "valid_hash": winner_sweep.map(|(_, vh)| hex::encode(vh)),
        });

        let agg_sig = self
            .cosign_covenant_keypath(&allocations, expiry, sighash, "unroll", ctx, "unroll", round_timeout)
            .await?;
        let agg_key_xonly = covenant_taproot.tweaked_key().ok_or("tweaked_key")?.serialize_xonly();
        let valid = verify_xonly(agg_key_xonly, sighash, agg_sig, SchnorrSigningMode::BIP340);
        let mut witness = Witness::new();
        witness.push(agg_sig.to_vec());
        unroll_tx.input[0].witness = witness;

        Ok(UnrollResult {
            txid: unroll_tx.compute_txid().to_string(),
            signed_tx_hex: hex::encode(bitcoin::consensus::encode::serialize(&unroll_tx)),
            valid,
            leaves: leaf_info,
        })
    }

    /// Shared N-of-N covenant key-path cosign (engine + all participants) over a
    /// given sighash. Used by the unroll; the refresh has its own inline copy. The
    /// `ctx` (kind "refresh"|"unroll") lets each client rebuild + verify the tx.
    async fn cosign_covenant_keypath(
        &self,
        allocations: &[([u8; 32], u64)],
        expiry: u32,
        sighash: [u8; 32],
        kind: &str,
        ctx: Value,
        label: &str,
        round_timeout: Duration,
    ) -> Result<[u8; 64], String> {
        let old_taproot = funding_taproot(self.engine_key, allocations, expiry).ok_or("funding_taproot")?;
        let keyagg = refresh_keyagg(self.engine_key, allocations, expiry).ok_or("refresh_keyagg")?;
        let tweak_hex = hex::encode(old_taproot.tap_tweak());
        let engine_pub = engine_projected_pubkey(self.engine_key.into_point().map_err(|_| "engine point")?, allocations)
            .ok_or("engine_projected_pubkey")?;
        let engine_sec = engine_projected_secret(
            (*self.engine_secret).into_scalar().map_err(|_| "engine scalar")?.lift(),
            allocations,
        )
        .ok_or("engine_projected_secret")?;
        let mut participant_pubs: Vec<([u8; 32], Point, u64, u32)> = Vec::new();
        for (i, (account, value)) in allocations.iter().enumerate() {
            let base = account.into_point().map_err(|_| "account point")?;
            let proj = participant_projected_pubkey(base, *value, i as u32).ok_or("participant projected")?;
            participant_pubs.push((*account, proj, *value, i as u32));
        }
        let mut pubkeys: Vec<String> = participant_pubs.iter().map(|(_, p, _, _)| ser_pt(p)).collect();
        pubkeys.push(ser_pt(&engine_pub));

        let session_id = {
            let mut c = self.counter.lock().await;
            *c += 1;
            format!("{}-{}", kind, *c)
        };
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<SessionInput>();
        self.sessions.lock().await.insert(session_id.clone(), inbox_tx);
        let sockets = {
            let parts = self.participants.lock().await;
            let mut map: HashMap<[u8; 32], mpsc::UnboundedSender<ServerMsg>> = HashMap::new();
            for (account, _, _, _) in &participant_pubs {
                match parts.get(account) {
                    Some(tx) => { map.insert(*account, tx.clone()); }
                    None => {
                        self.sessions.lock().await.remove(&session_id);
                        return Err(format!("participant {} not connected", hex::encode(account)));
                    }
                }
            }
            map
        };

        let mut session = MusigSessionCtx::new(&keyagg, sighash).ok_or("session new")?;
        let (eng_hn, eng_bn) = self.engine_nonces(&sighash);
        if !session.insert_nonce(engine_pub, eng_hn.base_point_mul(), eng_bn.base_point_mul()) {
            self.sessions.lock().await.remove(&session_id);
            return Err("engine nonce rejected".into());
        }
        for (account, proj, value, index) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::Start {
                session: session_id.clone(),
                label: label.to_string(),
                kind: kind.to_string(),
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

        let mut nonces: HashMap<String, NonceMsg> = HashMap::new();
        let want = participant_pubs.len();
        if self
            .collect(&mut inbox_rx, round_timeout, |input, st| match input {
                SessionInput::Nonce(n) => {
                    if let (Some(k), Some(h), Some(b)) = (pt(&n.pubkey), pt(&n.hiding), pt(&n.binding)) {
                        if session.insert_nonce(k, h, b) { st.insert(n.pubkey.clone(), n); }
                    }
                    st.len() == want
                }
                _ => false,
            }, &mut nonces, want)
            .await
            .is_err()
        {
            self.abort(&session_id, &sockets, "timed out collecting nonces").await;
            return Err("timed out collecting nonces".into());
        }

        nonces.insert(ser_pt(&engine_pub), NonceMsg {
            pubkey: ser_pt(&engine_pub),
            hiding: ser_pt(&eng_hn.base_point_mul()),
            binding: ser_pt(&eng_bn.base_point_mul()),
        });
        let nonce_vec: Vec<NonceMsg> = pubkeys.iter().filter_map(|k| nonces.get(k).cloned()).collect();
        for (account, _, _, _) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::AggNonces { session: session_id.clone(), nonces: nonce_vec.clone() });
        }

        let engine_partial = session.partial_sign(engine_sec, eng_hn, eng_bn).ok_or("engine partial_sign")?;
        session.insert_partial_sig(engine_pub, engine_partial);

        let mut partials: HashMap<String, ()> = HashMap::new();
        if self
            .collect(&mut inbox_rx, round_timeout, |input, st| match input {
                SessionInput::Partial { pubkey, partial } => {
                    if let (Some(k), Ok(sc)) = (pt(&pubkey), Scalar::from_hex(&partial)) {
                        if session.insert_partial_sig(k, sc) { st.insert(pubkey.clone(), ()); }
                    }
                    st.len() == want
                }
                _ => false,
            }, &mut partials, want)
            .await
            .is_err()
        {
            self.abort(&session_id, &sockets, "timed out collecting partials").await;
            return Err("timed out collecting partials".into());
        }

        let agg_sig = session.full_agg_sig().ok_or("full_agg_sig failed")?;
        for (account, _, _, _) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::Complete {
                session: session_id.clone(),
                agg_sig: hex::encode(agg_sig),
                txid: None,
            });
        }
        self.sessions.lock().await.remove(&session_id);
        Ok(agg_sig)
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
        kind: &str, // client verifier to run: "deposit" (genesis) or "join" (absorb)
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
            kind: kind.to_string(),
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
        let agg_sig = self.cosign_deposit_input(p.account_key, sighash, ctx, label, "deposit", round_timeout).await?;

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
                .cosign_deposit_input(d.account_key, sighashes[j], ctx, "genesis", "deposit", round_timeout)
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

    /// JOIN: absorb new deposits into the EXISTING pot covenant — spend [covenant +
    /// each new LiftV2 deposit] into one bigger covenant whose allocations include
    /// the new depositors, so post-genesis deposits become covenant-backed (and the
    /// settle reconcile can then attribute winnings to them). Input 0 (the covenant)
    /// is an N-of-N key-path MuSig2 of the OLD members + engine; inputs 1..N are each
    /// depositor's 2-of-2 LiftV2 spend. Every signer gets a "join" ctx describing the
    /// whole tx and verifies its own input's sighash before signing (trustless).
    pub async fn run_join(
        &self,
        mut old_allocations: Vec<([u8; 32], u64)>,
        old_expiry: u32,
        prev_txid: [u8; 32],
        prev_vout: u32,
        prev_value: u64,
        deposits: Vec<GenesisDeposit>,
        mut new_allocations: Vec<([u8; 32], u64)>,
        new_expiry: u32,
        fee: u64,
        round_timeout: Duration,
    ) -> Result<RefreshResult, String> {
        if deposits.is_empty() {
            return Err("join needs at least one deposit".into());
        }
        old_allocations.sort_by(|a, b| a.0.cmp(&b.0));
        new_allocations.sort_by(|a, b| a.0.cmp(&b.0));

        // --- build the multi-input tx: covenant (0) + deposits (1..N) -> new covenant ---
        let old_taproot = funding_taproot(self.engine_key, &old_allocations, old_expiry)
            .ok_or("funding_taproot(old) failed")?;
        let old_spk = ScriptBuf::from_bytes(old_taproot.spk().ok_or("old spk")?);
        let new_spk = covenant_scriptpubkey(self.engine_key, &new_allocations, new_expiry)
            .ok_or("covenant_scriptpubkey(new) failed")?;
        let out_value: u64 = new_allocations.iter().map(|(_, v)| v).sum();
        let total_in: u64 = prev_value + deposits.iter().map(|d| d.prev_value).sum::<u64>();
        if total_in != out_value + fee {
            return Err(format!("join value mismatch: in {} != out {} + fee {}", total_in, out_value, fee));
        }

        let mut prevouts: Vec<TxOut> = vec![TxOut { value: Amount::from_sat(prev_value), script_pubkey: old_spk }];
        let mut txins: Vec<TxIn> = vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(prev_txid), prev_vout),
            script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new(),
        }];
        for d in &deposits {
            let dt = return_liftv2_taproot(d.account_key, self.engine_key).ok_or("liftv2 taproot")?;
            prevouts.push(TxOut { value: Amount::from_sat(d.prev_value), script_pubkey: ScriptBuf::from_bytes(dt.spk().ok_or("deposit spk")?) });
            txins.push(TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(d.prev_txid), d.prev_vout),
                script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO, input: txins,
            output: vec![TxOut { value: Amount::from_sat(out_value), script_pubkey: ScriptBuf::from_bytes(new_spk) }],
        };
        let sighashes: Vec<[u8; 32]> = {
            let cache = SighashCache::new(&tx);
            let mut v = Vec::with_capacity(prevouts.len());
            for j in 0..prevouts.len() {
                v.push(SighashCache::new(&tx)
                    .taproot_key_spend_signature_hash(j, &Prevouts::All(&prevouts), TapSighashType::Default)
                    .map_err(|e| format!("sighash[{j}]: {e}"))?
                    .to_byte_array());
            }
            let _ = cache;
            v
        };

        // shared "join" ctx so every signer rebuilds the same tx + verifies its input.
        let alloc_json = |allocs: &[([u8; 32], u64)]| -> Value {
            Value::Array(allocs.iter().map(|(k, v)| json!({ "account": hex::encode(k), "value": v })).collect())
        };
        let deposits_json: Vec<Value> = deposits.iter().map(|d| json!({
            "account": hex::encode(d.account_key), "txid": hex::encode(d.prev_txid), "vout": d.prev_vout, "value": d.prev_value,
        })).collect();
        let base_ctx = json!({
            "kind": "join",
            "engine": hex::encode(self.engine_key),
            "lock_time": 0,
            "covenant_in": { "txid": hex::encode(prev_txid), "vout": prev_vout, "value": prev_value, "allocations": alloc_json(&old_allocations), "expiry": old_expiry },
            "deposits": deposits_json,
            "out_value": out_value,
            "new_allocations": alloc_json(&new_allocations),
            "new_expiry": new_expiry,
        });

        // ---- input 0: covenant key-path MuSig2 (old members + engine) ----
        let keyagg = refresh_keyagg(self.engine_key, &old_allocations, old_expiry).ok_or("refresh_keyagg failed")?;
        let tweak_hex = hex::encode(old_taproot.tap_tweak());
        let engine_pub = engine_projected_pubkey(self.engine_key.into_point().map_err(|_| "engine point")?, &old_allocations).ok_or("engine_projected_pubkey")?;
        let engine_sec = engine_projected_secret((*self.engine_secret).into_scalar().map_err(|_| "engine scalar")?.lift(), &old_allocations).ok_or("engine_projected_secret")?;
        let mut participant_pubs: Vec<([u8; 32], Point, u64, u32)> = Vec::new();
        for (i, (account, value)) in old_allocations.iter().enumerate() {
            let base = account.into_point().map_err(|_| "account point")?;
            let proj = participant_projected_pubkey(base, *value, i as u32).ok_or("participant_projected_pubkey")?;
            participant_pubs.push((*account, proj, *value, i as u32));
        }
        let mut pubkeys: Vec<String> = participant_pubs.iter().map(|(_, p, _, _)| ser_pt(p)).collect();
        pubkeys.push(ser_pt(&engine_pub));
        let session_id = { let mut c = self.counter.lock().await; *c += 1; format!("join-{}", *c) };
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<SessionInput>();
        self.sessions.lock().await.insert(session_id.clone(), inbox_tx);
        let sockets = {
            let parts = self.participants.lock().await;
            let mut map: HashMap<[u8; 32], mpsc::UnboundedSender<ServerMsg>> = HashMap::new();
            for (account, _, _, _) in &participant_pubs {
                match parts.get(account) {
                    Some(tx) => { map.insert(*account, tx.clone()); }
                    None => { self.sessions.lock().await.remove(&session_id); return Err(format!("participant {} not connected", hex::encode(account))); }
                }
            }
            map
        };
        let mut session = MusigSessionCtx::new(&keyagg, sighashes[0]).ok_or("session new")?;
        let (eng_hn, eng_bn) = self.engine_nonces(&sighashes[0]);
        if !session.insert_nonce(engine_pub, eng_hn.base_point_mul(), eng_bn.base_point_mul()) {
            self.sessions.lock().await.remove(&session_id);
            return Err("engine nonce rejected by keyagg".into());
        }
        let mut cov_ctx = base_ctx.clone(); cov_ctx["input_index"] = json!(0);
        for (account, proj, value, index) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::Start {
                session: session_id.clone(), label: "join".to_string(), kind: "join".to_string(),
                project: true, message: hex::encode(sighashes[0]), pubkeys: pubkeys.clone(), tweak: tweak_hex.clone(),
                your_pubkey: ser_pt(proj), your_value: *value, your_index: *index, ctx: cov_ctx.clone(),
            });
        }
        let mut nonces: HashMap<String, NonceMsg> = HashMap::new();
        let want = participant_pubs.len();
        if self.collect(&mut inbox_rx, round_timeout, |input, st| match input {
            SessionInput::Nonce(n) => { if let (Some(k), Some(h), Some(b)) = (pt(&n.pubkey), pt(&n.hiding), pt(&n.binding)) { if session.insert_nonce(k, h, b) { st.insert(n.pubkey.clone(), n); } } st.len() == want }
            _ => false,
        }, &mut nonces, want).await.is_err() {
            self.abort(&session_id, &sockets, "timed out collecting join nonces").await;
            return Err("timed out collecting join nonces".into());
        }
        nonces.insert(ser_pt(&engine_pub), NonceMsg { pubkey: ser_pt(&engine_pub), hiding: ser_pt(&eng_hn.base_point_mul()), binding: ser_pt(&eng_bn.base_point_mul()) });
        let nonce_vec: Vec<NonceMsg> = pubkeys.iter().filter_map(|k| nonces.get(k).cloned()).collect();
        for (account, _, _, _) in &participant_pubs {
            let _ = sockets[account].send(ServerMsg::AggNonces { session: session_id.clone(), nonces: nonce_vec.clone() });
        }
        let engine_partial = session.partial_sign(engine_sec, eng_hn, eng_bn).ok_or("engine partial_sign failed")?;
        session.insert_partial_sig(engine_pub, engine_partial);
        let mut partials: HashMap<String, ()> = HashMap::new();
        if self.collect(&mut inbox_rx, round_timeout, |input, st| match input {
            SessionInput::Partial { pubkey, partial } => { if let (Some(k), Ok(sc)) = (pt(&pubkey), Scalar::from_hex(&partial)) { if session.insert_partial_sig(k, sc) { st.insert(pubkey.clone(), ()); } } st.len() == want }
            _ => false,
        }, &mut partials, want).await.is_err() {
            self.abort(&session_id, &sockets, "timed out collecting join partials").await;
            return Err("timed out collecting join partials".into());
        }
        let agg_sig = session.full_agg_sig().ok_or("full_agg_sig failed")?;
        self.sessions.lock().await.remove(&session_id);
        { let mut w = Witness::new(); w.push(agg_sig.to_vec()); tx.input[0].witness = w; }

        // ---- inputs 1..N: each deposit's 2-of-2 LiftV2 spend ----
        for (i, d) in deposits.iter().enumerate() {
            let mut c = base_ctx.clone(); c["input_index"] = json!(i + 1); c["account"] = json!(hex::encode(d.account_key));
            let sig = self.cosign_deposit_input(d.account_key, sighashes[i + 1], c, "join", "join", round_timeout).await?;
            let mut w = Witness::new(); w.push(sig.to_vec());
            tx.input[i + 1].witness = w;
        }

        Ok(RefreshResult {
            agg_sig: [0u8; 64], message: [0u8; 32], agg_key_xonly: [0u8; 32], valid: true,
            signed_tx_hex: hex::encode(bitcoin::consensus::encode::serialize(&tx)),
            txid: tx.compute_txid().to_string(),
        })
    }

    /// EPOCH REFORM: like `run_join`, but spend the covenant via its ENGINE-ONLY
    /// EXPIRY script path (`<expiry> CLTV DROP <engine> CHECKSIG`) instead of the
    /// N-of-N key path — so the engine carries every member's balance into a fresh
    /// covenant AND absorbs online joiners WITHOUT any existing member cosigning
    /// (they may be offline/abandoned). Valid on-chain only once tip >= `old_expiry`
    /// (CLTV); the tx sets nLockTime = old_expiry. Deposit inputs are still each
    /// depositor's own 2-of-2 (they're online). Members keep their pre-signed unroll
    /// to exit before expiry if they distrust the reform.
    pub async fn run_epoch_reform(
        &self,
        mut old_allocations: Vec<([u8; 32], u64)>,
        old_expiry: u32,
        prev_txid: [u8; 32],
        prev_vout: u32,
        prev_value: u64,
        deposits: Vec<GenesisDeposit>,
        mut new_allocations: Vec<([u8; 32], u64)>,
        new_expiry: u32,
        fee: u64,
        round_timeout: Duration,
    ) -> Result<RefreshResult, String> {
        old_allocations.sort_by(|a, b| a.0.cmp(&b.0));
        new_allocations.sort_by(|a, b| a.0.cmp(&b.0));
        let old_taproot = funding_taproot(self.engine_key, &old_allocations, old_expiry).ok_or("funding_taproot(old) failed")?;
        let old_spk = ScriptBuf::from_bytes(old_taproot.spk().ok_or("old spk")?);
        // the engine-spendable expiry leaf (the single script path on the covenant).
        let tree = old_taproot.tree().ok_or("old tree")?;
        let leaf = tree.leaves().into_iter().next().ok_or("expiry leaf")?;
        let expiry_script = leaf.tap_script();
        let expiry_cb = old_taproot.control_block(0).ok_or("expiry control block")?.to_vec();
        let new_spk = covenant_scriptpubkey(self.engine_key, &new_allocations, new_expiry).ok_or("covenant_scriptpubkey(new) failed")?;
        let out_value: u64 = new_allocations.iter().map(|(_, v)| v).sum();
        let total_in: u64 = prev_value + deposits.iter().map(|d| d.prev_value).sum::<u64>();
        if total_in != out_value + fee {
            return Err(format!("reform value mismatch: in {} != out {} + fee {}", total_in, out_value, fee));
        }

        let mut prevouts: Vec<TxOut> = vec![TxOut { value: Amount::from_sat(prev_value), script_pubkey: old_spk }];
        let mut txins: Vec<TxIn> = vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(prev_txid), prev_vout),
            script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new(),
        }];
        for d in &deposits {
            let dt = return_liftv2_taproot(d.account_key, self.engine_key).ok_or("liftv2 taproot")?;
            prevouts.push(TxOut { value: Amount::from_sat(d.prev_value), script_pubkey: ScriptBuf::from_bytes(dt.spk().ok_or("deposit spk")?) });
            txins.push(TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(d.prev_txid), d.prev_vout),
                script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(old_expiry).map_err(|_| "bad expiry height")?,
            input: txins,
            output: vec![TxOut { value: Amount::from_sat(out_value), script_pubkey: ScriptBuf::from_bytes(new_spk) }],
        };
        // input 0: engine signs the expiry SCRIPT path (no member cosign needed).
        let leaf_hash = TapLeafHash::from_script(bitcoin::Script::from_bytes(&expiry_script), LeafVersion::TapScript);
        let sighash0 = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), leaf_hash, TapSighashType::Default)
            .map_err(|e| format!("sighash0: {e}"))?
            .to_byte_array();
        let engine_sig = sign(*self.engine_secret, sighash0, SchnorrSigningMode::BIP340).ok_or("engine expiry sign failed")?;
        { let mut w = Witness::new(); w.push(engine_sig.to_vec()); w.push(expiry_script.clone()); w.push(expiry_cb.clone()); tx.input[0].witness = w; }

        // deposit inputs (1..N): each depositor's 2-of-2, verified via the "join" ctx
        // (carrying nLockTime = old_expiry so the depositor recomputes the same sighash).
        let alloc_json = |allocs: &[([u8; 32], u64)]| -> Value {
            Value::Array(allocs.iter().map(|(k, v)| json!({ "account": hex::encode(k), "value": v })).collect())
        };
        let deposits_json: Vec<Value> = deposits.iter().map(|d| json!({
            "account": hex::encode(d.account_key), "txid": hex::encode(d.prev_txid), "vout": d.prev_vout, "value": d.prev_value,
        })).collect();
        let base_ctx = json!({
            "kind": "join",
            "engine": hex::encode(self.engine_key),
            "lock_time": old_expiry,
            "covenant_in": { "txid": hex::encode(prev_txid), "vout": prev_vout, "value": prev_value, "allocations": alloc_json(&old_allocations), "expiry": old_expiry },
            "deposits": deposits_json,
            "out_value": out_value,
            "new_allocations": alloc_json(&new_allocations),
            "new_expiry": new_expiry,
        });
        for (i, d) in deposits.iter().enumerate() {
            let sighash_i = SighashCache::new(&tx)
                .taproot_key_spend_signature_hash(i + 1, &Prevouts::All(&prevouts), TapSighashType::Default)
                .map_err(|e| format!("sighash[{}]: {e}", i + 1))?
                .to_byte_array();
            let mut c = base_ctx.clone(); c["input_index"] = json!(i + 1); c["account"] = json!(hex::encode(d.account_key));
            let sig = self.cosign_deposit_input(d.account_key, sighash_i, c, "epoch-reform", "join", round_timeout).await?;
            let mut w = Witness::new(); w.push(sig.to_vec()); tx.input[i + 1].witness = w;
        }

        Ok(RefreshResult {
            agg_sig: [0u8; 64], message: [0u8; 32], agg_key_xonly: [0u8; 32], valid: true,
            signed_tx_hex: hex::encode(bitcoin::consensus::encode::serialize(&tx)),
            txid: tx.compute_txid().to_string(),
        })
    }

    /// DISSOLVE: spend the covenant via its ENGINE-ONLY expiry script path (no member
    /// cosign) into ONE LiftV2 output per member — returning every member to an output
    /// they can unilaterally sweep with their own key. Used when liveness has failed
    /// (a member offline at/after expiry): instead of trapping everyone in a covenant
    /// nobody can refresh, dissolve it so each member is individually exitable. Online
    /// members get re-pooled afterward by a fresh genesis (which re-arms a presigned
    /// unroll). Valid on-chain only once tip >= old_expiry (CLTV); sets nLockTime.
    pub async fn run_dissolve(
        &self,
        mut allocations: Vec<([u8; 32], u64)>,
        old_expiry: u32,
        prev_txid: [u8; 32],
        prev_vout: u32,
        prev_value: u64,
        fee: u64,
    ) -> Result<DissolveResult, String> {
        if allocations.is_empty() { return Err("no members to dissolve".into()); }
        if prev_value <= fee { return Err("covenant too small to cover the dissolve fee".into()); }
        allocations.sort_by(|a, b| a.0.cmp(&b.0));
        let old_taproot = funding_taproot(self.engine_key, &allocations, old_expiry).ok_or("funding_taproot failed")?;
        let old_spk = ScriptBuf::from_bytes(old_taproot.spk().ok_or("old spk")?);
        let tree = old_taproot.tree().ok_or("old tree")?;
        let leaf = tree.leaves().into_iter().next().ok_or("expiry leaf")?;
        let expiry_script = leaf.tap_script();
        let expiry_cb = old_taproot.control_block(0).ok_or("expiry control block")?.to_vec();

        // one LiftV2 output per member, valued at their allocation; the leaver-pays
        // model doesn't apply (this is a forced eviction), so the fee + any drift come
        // off the largest allocation so Σ outputs == prev_value − fee exactly.
        let mut out_vals: Vec<u64> = allocations.iter().map(|(_, v)| *v).collect();
        let target = prev_value - fee;
        let cur: u64 = out_vals.iter().sum();
        let diff = target as i64 - cur as i64;
        let big = out_vals.iter().enumerate().max_by_key(|(_, v)| **v).map(|(i, _)| i).ok_or("no outputs")?;
        let adj = out_vals[big] as i64 + diff;
        if adj < 0 { return Err("dissolve value mismatch".into()); }
        out_vals[big] = adj as u64;

        let mut outs: Vec<TxOut> = Vec::with_capacity(allocations.len());
        for (i, (acct, _)) in allocations.iter().enumerate() {
            let dt = return_liftv2_taproot(*acct, self.engine_key).ok_or("return_liftv2_taproot failed")?;
            outs.push(TxOut { value: Amount::from_sat(out_vals[i]), script_pubkey: ScriptBuf::from_bytes(dt.spk().ok_or("liftv2 spk")?) });
        }
        let prevout = TxOut { value: Amount::from_sat(prev_value), script_pubkey: old_spk };
        let txin = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array(prev_txid), prev_vout),
            script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new(),
        };
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(old_expiry).map_err(|_| "bad expiry height")?,
            input: vec![txin], output: outs,
        };
        let leaf_hash = TapLeafHash::from_script(bitcoin::Script::from_bytes(&expiry_script), LeafVersion::TapScript);
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prevout]), leaf_hash, TapSighashType::Default)
            .map_err(|e| format!("sighash: {e}"))?
            .to_byte_array();
        let sig = sign(*self.engine_secret, sighash, SchnorrSigningMode::BIP340).ok_or("engine expiry sign failed")?;
        { let mut w = Witness::new(); w.push(sig.to_vec()); w.push(expiry_script.clone()); w.push(expiry_cb.clone()); tx.input[0].witness = w; }

        let outputs: Vec<([u8; 32], u32, u64)> = allocations.iter().enumerate().map(|(i, (a, _))| (*a, i as u32, out_vals[i])).collect();
        Ok(DissolveResult {
            signed_tx_hex: hex::encode(bitcoin::consensus::encode::serialize(&tx)),
            txid: tx.compute_txid().to_string(),
            outputs,
        })
    }

    /// DEPOSIT WITHDRAW: spend one account's un-pooled LiftV2 deposit UTXOs (each a
    /// 2-of-2 account+engine key path) straight to `dest_spk`, paying the whole sum
    /// minus `fee`. Covenant-independent and liveness-independent (only the one
    /// depositor cosigns) — so a freshly-deposited, not-yet-pooled balance is always
    /// recoverable cooperatively. Each input is cosigned by the depositor via the
    /// "deposit-withdraw" client verifier (which checks the output is the address
    /// they authorized).
    pub async fn run_deposit_withdraw(
        &self,
        account_key: [u8; 32],
        deposits: Vec<([u8; 32], u32, u64)>, // (prev_txid, prev_vout, prev_value)
        dest_spk: Vec<u8>,
        fee: u64,
        round_timeout: Duration,
    ) -> Result<RefreshResult, String> {
        if deposits.is_empty() { return Err("no deposits to withdraw".into()); }
        let total_in: u64 = deposits.iter().map(|(_, _, v)| v).sum();
        if total_in <= fee { return Err("deposit too small to cover its on-chain exit fee".into()); }
        let out_value = total_in - fee;

        let dt = return_liftv2_taproot(account_key, self.engine_key).ok_or("return_liftv2_taproot failed")?;
        let dspk = ScriptBuf::from_bytes(dt.spk().ok_or("deposit spk")?);
        let mut prevouts: Vec<TxOut> = Vec::with_capacity(deposits.len());
        let mut txins: Vec<TxIn> = Vec::with_capacity(deposits.len());
        for (txid, vout, value) in &deposits {
            prevouts.push(TxOut { value: Amount::from_sat(*value), script_pubkey: dspk.clone() });
            txins.push(TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(*txid), *vout),
                script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO, lock_time: LockTime::ZERO, input: txins,
            output: vec![TxOut { value: Amount::from_sat(out_value), script_pubkey: ScriptBuf::from_bytes(dest_spk.clone()) }],
        };

        let inputs_json: Vec<Value> = deposits.iter().map(|(t, v, val)| json!({
            "account": hex::encode(account_key), "txid": hex::encode(t), "vout": v, "value": val,
        })).collect();
        let base_ctx = json!({
            "kind": "deposit-withdraw",
            "engine": hex::encode(self.engine_key),
            "account": hex::encode(account_key),
            "lock_time": 0,
            "inputs": inputs_json,
            "outputs": [{ "value": out_value, "spk": hex::encode(&dest_spk) }],
        });
        for i in 0..deposits.len() {
            let sighash_i = SighashCache::new(&tx)
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                .map_err(|e| format!("sighash[{i}]: {e}"))?
                .to_byte_array();
            let mut c = base_ctx.clone(); c["input_index"] = json!(i);
            let sig = self.cosign_deposit_input(account_key, sighash_i, c, "deposit-withdraw", "deposit-withdraw", round_timeout).await?;
            let mut w = Witness::new(); w.push(sig.to_vec()); tx.input[i].witness = w;
        }

        Ok(RefreshResult {
            agg_sig: [0u8; 64], message: [0u8; 32], agg_key_xonly: [0u8; 32], valid: true,
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
