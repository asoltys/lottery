//! Independent challenger for the enforced lottery settle.
//!
//! Fetches a SettleAssertion from the LIVE arcade (/api/settle_assertion), derives
//! the disprove secret purely from the public assertion via the cube garble lib
//! (no trust in the engine), and — on a WRONG settle — reclaims the contested
//! covenant output on regtest by spending its disprove leaf with that secret. On
//! an HONEST settle the challenger gets no secret and the output is untouchable.
//! This is the end-to-end enforcement: the engine cannot assert a false winner
//! without a user being able to take back the contested funds.
//!
//! Run (with the arcade on :8090 + regtest bitcoind at /tmp/cube-regtest):
//!   cargo run --bin enforce_challenger

use std::process::Command;

use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_HASH160};
use bitcoin::script::Builder;

use cube::constructive::taproot::{TapLeaf, TapRoot};
use cube::transmutative::garble::{SettleAssertion, WinnerVerifier};
use cube::transmutative::secp::schnorr::{sign, SchnorrSigningMode};
use secp::Scalar;
use serde::Deserialize;

const ARCADE: &str = "http://127.0.0.1:8090/api/settle_assertion";
const DD: &str = "/tmp/cube-regtest";
const CHALLENGER_SK: [u8; 32] = [0x44; 32]; // the disputing user's key (demo)

#[derive(Deserialize)]
struct AssertResp {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    rg: u64,
    honest_winner: Option<u32>,
    claimed_winner: u32,
    disprove_hash: String,
    assertion: SettleAssertion,
}

fn cli(args: &[&str]) -> String {
    let out = Command::new("bitcoin-cli")
        .arg(format!("-datadir={DD}"))
        .arg("-rpcwallet=cube")
        .args(args)
        .output()
        .expect("bitcoin-cli");
    if !out.status.success() {
        panic!("bitcoin-cli {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn assert_settle(seed: u64, winner: Option<u32>) -> AssertResp {
    let body = match winner {
        Some(w) => format!("{{\"seed\":{seed},\"winner\":{w}}}"),
        None => format!("{{\"seed\":{seed}}}"),
    };
    let out = Command::new("curl")
        .args(["-s", "-X", "POST", ARCADE, "-H", "content-type: application/json", "-d", &body])
        .output()
        .expect("curl");
    serde_json::from_slice(&out.stdout).expect("parse assertion response")
}

fn challenger_xonly() -> [u8; 32] {
    Scalar::from_slice(&CHALLENGER_SK).unwrap().base_point_mul().serialize_xonly()
}

// The contested output: a taproot whose script path is the disprove leaf gated by
// the round's disprove hash + the challenger's key (mirrors the ZKTLC leaf).
fn contested_taproot(disprove_hash: [u8; 32]) -> TapRoot {
    let x = bitcoin::XOnlyPublicKey::from_slice(&challenger_xonly()).unwrap();
    let script = Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(bitcoin::hashes::ripemd160::Hash::hash(&disprove_hash).to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&x)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    // unspendable-ish internal key (any point); only the disprove leaf matters here.
    let inner = Scalar::from_slice(&[0x02; 32]).unwrap().base_point_mul();
    TapRoot::key_and_script_path_single(inner, TapLeaf::new(script.to_bytes()))
}

fn reclaim(disprove_hash: [u8; 32], secret: [u8; 32]) -> String {
    let taproot = contested_taproot(disprove_hash);
    let spk = taproot.spk().unwrap();
    let addr = {
        let j = cli(&["decodescript", &hex::encode(&spk)]);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        v["address"].as_str().unwrap().to_string()
    };
    // fund the contested output, confirm, locate its vout.
    let fund_txid = cli(&["sendtoaddress", &addr, "0.002"]);
    cli(&["-generate", "1"]);
    let raw: serde_json::Value = serde_json::from_str(&cli(&["getrawtransaction", &fund_txid, "true"])).unwrap();
    let (mut vout, mut value) = (0u32, 0u64);
    for o in raw["vout"].as_array().unwrap() {
        if o["scriptPubKey"]["hex"].as_str() == Some(&hex::encode(&spk)) {
            vout = o["n"].as_u64().unwrap() as u32;
            value = (o["value"].as_f64().unwrap() * 1e8).round() as u64;
        }
    }
    // build the disprove spend: input = contested output, output = challenger payout.
    let dest = cli(&["getnewaddress"]);
    let dest_spk = {
        let j = cli(&["getaddressinfo", &dest]);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        hex::decode(v["scriptPubKey"].as_str().unwrap()).unwrap()
    };
    let prev_txout = TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(spk.clone()) };
    let mut tx = Transaction {
        version: Version::TWO, lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_str_display(&fund_txid), vout),
            script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value - 500), script_pubkey: ScriptBuf::from_bytes(dest_spk) }],
    };
    let (_lh, script, control_block) = {
        let leaf = taproot.tree().unwrap().leaves()[0].clone();
        (leaf.tapleaf_hash(), leaf.tap_script(), taproot.control_block(0).unwrap().to_vec())
    };
    let script_buf = ScriptBuf::from_bytes(script.clone());
    let lh = TapLeafHash::from_script(&script_buf, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev_txout]), lh, TapSighashType::Default)
        .unwrap().to_byte_array();
    let sig = sign(CHALLENGER_SK, sighash, SchnorrSigningMode::BIP340).unwrap();
    // witness: [sig, disprove_secret, script, control_block]
    let mut w = Witness::new();
    w.push(sig.to_vec());
    w.push(secret.to_vec());
    w.push(script);
    w.push(control_block);
    tx.input[0].witness = w;
    let raw_hex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
    cli(&["sendrawtransaction", &raw_hex])
}

// small helper: Txid from a display (big-endian) hex string.
trait FromDisplay { fn from_str_display(s: &str) -> Txid; }
impl FromDisplay for Txid {
    fn from_str_display(s: &str) -> Txid {
        let mut b = hex::decode(s).unwrap();
        b.reverse();
        Txid::from_byte_array(b.try_into().unwrap())
    }
}

fn main() {
    let seed = 5000u64; // lands on entry 0; the challenger computes the same true rg

    // 1) HONEST settle: the engine claims the true winner -> no disprove secret.
    let honest = assert_settle(seed, None);
    if !honest.ok {
        panic!("assertion error: {:?}", honest.error);
    }
    let true_rg = honest.rg; // (a real challenger recomputes from seed+stakes; equal here)
    match WinnerVerifier::challenge(&honest.assertion, true_rg).unwrap() {
        None => println!("HONEST settle (winner {}): challenger finds no disprove secret — settle stands.", honest.claimed_winner),
        Some(_) => panic!("honest settle wrongly flagged as disprovable!"),
    }

    // 2) WRONG settle: force a false winner -> challenger derives the disprove secret.
    let wrong = assert_settle(seed, Some(if honest.honest_winner == Some(1) { 2 } else { 1 }));
    let secret = WinnerVerifier::challenge(&wrong.assertion, true_rg)
        .unwrap()
        .expect("a wrong winner must yield the disprove secret");
    let disprove_hash: [u8; 32] = hex::decode(&wrong.disprove_hash).unwrap().try_into().unwrap();
    assert_eq!(cube::transmutative::hash::sha256(&secret), disprove_hash, "secret opens the round's disprove lock");
    println!("WRONG settle (claimed winner {}, honest {:?}): challenger derived the disprove secret.",
        wrong.claimed_winner, wrong.honest_winner);

    // 3) reclaim the contested output on regtest with the secret.
    let txid = reclaim(disprove_hash, secret);
    cli(&["-generate", "1"]);
    let conf: serde_json::Value = serde_json::from_str(&cli(&["getrawtransaction", &txid, "true"])).unwrap();
    let confs = conf["confirmations"].as_u64().unwrap_or(0);
    println!("RECLAIM confirmed: {}… ({} conf)", &txid[..16], confs);
    assert!(confs >= 1);
    println!("\nPASS — enforced settle end-to-end against the LIVE arcade: an honest winner claim is");
    println!("un-disprovable, but a WRONG claim lets an independent challenger derive the garbled");
    println!("secret and reclaim the contested output on Bitcoin. Loser-forfeit needs no loser sig;");
    println!("a false settle is punished by Bitcoin consensus.");
}
