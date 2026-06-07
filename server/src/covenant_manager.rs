//! Crash-safe, idempotent persistence for the on-chain pot covenant.
//!
//! The arcade tracks ONE pot covenant UTXO on Bitcoin whose allocations mirror
//! the L2 lottery contract's shadow state. This module owns that pointer (and the
//! pre-signed unroll that guarantees liveness-free exit) and persists it
//! atomically so a restart never loses the covenant or double-broadcasts a
//! refresh. Phase 0: the state container + atomic load/save + idempotency marker.
//! Population (deposits, refresh, unroll) lands in Phase 1.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The current pot covenant outpoint + the allocation state it commits to.
/// `allocations` is canonical (sorted by account key hex) — the same order the
/// engine uses to build the covenant, so the spk is reproducible.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct CovenantState {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub allocations: Vec<(String, u64)>, // (account x-only hex, value)
    pub expiry: u32,
}

/// A fully-signed unroll of a covenant (covenant -> per-participant VTXO leaves),
/// pre-signed N-of-N at covenant creation so ANYONE can broadcast it later with
/// nobody online. Handed to the watchtower.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PreSignedUnroll {
    pub covenant_txid: String, // the covenant this unroll spends (must match current)
    pub unroll_txid: String,
    pub unroll_tx_hex: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PersistedState {
    /// The confirmed current pot covenant, if any.
    pub covenant: Option<CovenantState>,
    /// The pre-signed unroll for `covenant` (kept in lockstep).
    pub unroll: Option<PreSignedUnroll>,
    /// Idempotency: a refresh tx we have signed + broadcast but not yet seen
    /// confirmed as the new covenant. On restart, reconcile this against the
    /// chain (confirmed -> promote to `covenant`; missing -> safe to retry)
    /// instead of blindly re-signing and risking a double-spend attempt.
    pub pending_refresh_txid: Option<String>,
}

#[derive(Clone)]
pub struct CovenantManager {
    path: PathBuf,
    state: Arc<Mutex<PersistedState>>,
}

impl CovenantManager {
    /// Load persisted state from `path` (or start empty if absent/unreadable).
    pub fn load(path: PathBuf) -> Self {
        let state = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedState>(&b).ok())
            .unwrap_or_default();
        if state.covenant.is_some() {
            eprintln!("covenant: loaded persisted covenant from {}", path.display());
        }
        CovenantManager { path, state: Arc::new(Mutex::new(state)) }
    }

    /// A snapshot of the current persisted state.
    pub async fn snapshot(&self) -> PersistedState {
        self.state.lock().await.clone()
    }

    /// The current covenant, if any.
    pub async fn current(&self) -> Option<CovenantState> {
        self.state.lock().await.covenant.clone()
    }

    /// Mutate the state and persist atomically. The closure runs under the lock;
    /// the write (temp file + rename) happens before the lock is released so a
    /// crash can never leave RAM ahead of disk.
    pub async fn update<F: FnOnce(&mut PersistedState)>(&self, f: F) -> std::io::Result<()> {
        let mut guard = self.state.lock().await;
        f(&mut guard);
        self.persist(&guard)
    }

    fn persist(&self, st: &PersistedState) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(st)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path)?; // atomic on the same filesystem
        Ok(())
    }
}
