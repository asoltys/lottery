// Phase 0 checkpoint: the on-chain covenant pointer survives restarts (atomic
// write + reload) and supports the idempotency marker that prevents
// double-broadcasting a refresh after a crash.

use lottery_arcade::covenant_manager::{CovenantManager, CovenantState, PreSignedUnroll};

fn temp_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("arcade-covenant-test-{}-{}.json", std::process::id(), tag));
    let _ = std::fs::remove_file(&p);
    p
}

#[tokio::test]
async fn persists_and_reloads_covenant() {
    let path = temp_path("reload");

    // empty to start
    let m = CovenantManager::load(path.clone());
    assert!(m.current().await.is_none());

    // set a covenant + pre-signed unroll + pending marker, persisting.
    let cov = CovenantState {
        txid: "aa".repeat(32),
        vout: 0,
        value: 50_000,
        allocations: vec![("bb".repeat(32), 30_000), ("cc".repeat(32), 20_000)],
        expiry: 800_000,
    };
    let unroll = PreSignedUnroll {
        covenant_txid: cov.txid.clone(),
        unroll_txid: "dd".repeat(32),
        unroll_tx_hex: "00".repeat(10),
    };
    m.update(|st| {
        st.covenant = Some(cov.clone());
        st.unroll = Some(unroll.clone());
        st.pending_refresh_txid = Some("ee".repeat(32));
    })
    .await
    .unwrap();

    // a FRESH manager (simulating a restart) reloads identical state.
    let reloaded = CovenantManager::load(path.clone());
    let snap = reloaded.snapshot().await;
    assert_eq!(snap.covenant, Some(cov));
    assert_eq!(snap.unroll, Some(unroll));
    assert_eq!(snap.pending_refresh_txid.as_deref(), Some("ee".repeat(32).as_str()));

    // clearing the pending marker (refresh confirmed) persists too.
    reloaded.update(|st| st.pending_refresh_txid = None).await.unwrap();
    let snap2 = CovenantManager::load(path.clone()).snapshot().await;
    assert!(snap2.pending_refresh_txid.is_none());
    assert!(snap2.covenant.is_some());

    // no leftover temp file.
    assert!(!path.with_extension("tmp").exists());

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn corrupt_or_missing_file_starts_empty() {
    let path = temp_path("corrupt");
    std::fs::write(&path, b"not json at all").unwrap();
    let m = CovenantManager::load(path.clone());
    assert!(m.current().await.is_none(), "corrupt state must not crash; start empty");
    let _ = std::fs::remove_file(&path);
}
