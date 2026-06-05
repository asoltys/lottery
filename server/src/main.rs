// Launches a (forked) Cube engine with the lottery arcade attached.
//
// Same CLI as the cube engine binary:
//   lottery-engine <pruned|archival> <chain> <node|engine> <rpc-url> <rpc-user> <rpc-pass> <syncinflight?>
//
// On the engine path, cube invokes our registered post-init hook with handles to
// its in-memory managers; we spawn the arcade web server (browser-signed play)
// against them. Config via env: CUBE_ARCADE_PORT, CUBE_LOTTERY_CONTRACT,
// CUBE_MINE_ADDRESS, CUBE_ARCADE_ASSETS.

use cube::communicative::rpc::bitcoin_rpc::bitcoin_rpc_holder::BitcoinRPCHolder;
use cube::operative::run_args::{
    chain::Chain, operating_kind::OperatingKind, resource_mode::ResourceMode, sync_mode::SyncMode,
};
use cube::operative::runner::hook::{set_engine_hook, EngineHandles};
use cube::operative::runner::runner;
use cube::transmutative::key::{FromNostrKeyStr, KeyHolder};
use std::env;
use std::io::BufRead;

// Lottery v3: 2-minute rounds, ~1% per-round win odds, guaranteed winner at
// least once a day, and a 1% operator rake on wins. Registered on startup.
const DEFAULT_CONTRACT: &str = "e55b4ace29c3f3260fca569f2ffb487ebc4763c091723e06efa03491b52ea51a";
const DEFAULT_MINE_ADDR: &str = "bcrt1q6eveccs27r8ckn76chzwz0ajhe2qje5yp8ks8t";

fn main() {
    // Attach the arcade when the engine's managers come up.
    set_engine_hook(Box::new(|h: EngineHandles| {
        let port: u16 = env::var("CUBE_ARCADE_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8090);
        let contract_hex = env::var("CUBE_LOTTERY_CONTRACT").unwrap_or_else(|_| DEFAULT_CONTRACT.to_string());
        let mine_address = env::var("CUBE_MINE_ADDRESS").unwrap_or_else(|_| DEFAULT_MINE_ADDR.to_string());
        if let Ok(bytes) = hex::decode(&contract_hex) {
            if let Ok(contract_id) = <[u8; 32]>::try_from(bytes) {
                tokio::spawn(lottery_arcade::run_arcade(h, port, contract_id, mine_address));
            }
        }
    }));

    let args: Vec<String> = env::args().collect();
    if args.len() != 8 {
        eprintln!(
            "Usage: lottery-engine <pruned|archival> <chain> <node|engine> <rpc-url> <rpc-user> <rpc-pass> <syncinflight?>"
        );
        return;
    }
    let resource_mode = match args[1].to_lowercase().as_str() {
        "pruned" => ResourceMode::Pruned,
        "archival" => ResourceMode::Archival,
        _ => return eprintln!("invalid resource mode"),
    };
    let chain = match args[2].to_lowercase().as_str() {
        "signet" => Chain::Signet,
        "mainnet" => Chain::Mainnet,
        "regtest" => Chain::Regtest,
        _ => return eprintln!("invalid chain"),
    };
    let operating_kind = match args[3].to_lowercase().as_str() {
        "node" => OperatingKind::Node,
        "engine" => OperatingKind::Engine,
        _ => return eprintln!("invalid kind"),
    };
    let rpc_holder = BitcoinRPCHolder::new(args[4].clone(), args[5].clone(), args[6].clone());
    let sync_mode = match args[7].to_lowercase().as_str() {
        "true" | "yes" | "1" => SyncMode::InFlight,
        _ => SyncMode::ConfirmedOnly,
    };

    // Engine nsec: from CUBE_ENGINE_NSEC env (headless/container) or stdin prompt.
    let mut secret = [0xffu8; 32];
    if let Ok(nsec) = env::var("CUBE_ENGINE_NSEC") {
        match nsec.trim().from_nsec() {
            Some(s) => secret = s,
            None => return eprintln!("invalid CUBE_ENGINE_NSEC"),
        }
    } else {
        println!("Enter nsec:");
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let line = line.unwrap();
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            match t.from_nsec() {
                Some(s) => secret = s,
                None => return eprintln!("invalid nsec"),
            }
            break;
        }
    }
    let key_holder = match KeyHolder::new(secret) {
        Some(k) => k,
        None => return eprintln!("invalid nsec"),
    };

    runner::run(resource_mode, chain, operating_kind, rpc_holder, sync_mode, key_holder);
}
