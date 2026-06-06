// Test helper: derive a player's keys from a secret and emit curl-ready JSON for
// (1) the faucet and (2) a BLS-signed `enter` call — so the non-custodial
// enter -> exitable-claim path can be driven without a browser.
//
//   sign_enter <secret_hex32> <registery_index> <contract_id_hex32> <amount> <target>
//
// Run faucet first (prints registery_index), then re-run with that index for CALL.

use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
use cube::constructive::core_types::method_index::method_index::MethodIndex;
use cube::constructive::core_types::ops_budget::ops_budget::OpsBudget;
use cube::constructive::core_types::ops_price::ops_price::OpsPrice;
use cube::constructive::core_types::target::target::Target;
use cube::constructive::entity::account::root_account::registered_and_configured_root_account::registered_and_configured_root_account::RegisteredAndConfiguredRootAccount;
use cube::constructive::entity::account::root_account::root_account::RootAccount;
use cube::constructive::entity::contract::contract::Contract;
use cube::constructive::entry::entry_kinds::call::call::Call;
use cube::transmutative::key::KeyHolder;
use std::env;

fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() != 7 {
        eprintln!("usage: sign_enter <secret_hex32> <reg_index> <contract_id_hex32> <amount> <target> <contract_reg_index>");
        return;
    }
    let secret: [u8; 32] = hex::decode(&a[1]).unwrap().try_into().unwrap();
    let reg_index: u64 = a[2].parse().unwrap();
    let cid: [u8; 32] = hex::decode(&a[3]).unwrap().try_into().unwrap();
    let amount: u32 = a[4].parse().unwrap();
    let target: u64 = a[5].parse().unwrap();
    let contract_reg_index: u64 = a[6].parse().unwrap();

    let kh = KeyHolder::new(secret).expect("keyholder");
    let account_key = kh.secp_public_key_bytes();
    let bls_key = kh.bls_public_key_bytes();

    println!(
        "FAUCET={}",
        serde_json::json!({"account_key": hex::encode(account_key), "bls_key": hex::encode(bls_key)})
    );

    let account = RootAccount::RegisteredAndConfiguredRootAccount(
        RegisteredAndConfiguredRootAccount::new(account_key, reg_index, bls_key),
    );
    let contract = Contract::new(cid, contract_reg_index);
    let call = Call::new(
        account,
        contract,
        MethodIndex::new(0),
        vec![CalldataElement::Payable(amount)],
        OpsBudget::new(None),
        OpsPrice::new(100),
        Target::new(target),
    );
    let sig = call.bls_sign(&kh).expect("bls sign");
    eprintln!("self bls_verify: {:?}  sighash={}", call.bls_verify(sig).is_ok(), hex::encode(call.sighash().unwrap()));

    println!(
        "CALL={}",
        serde_json::json!({
            "account_key": hex::encode(account_key),
            "registery_index": reg_index,
            "bls_key": hex::encode(bls_key),
            "method_index": 0,
            "calldata": [{"type": "payable", "value": amount}],
            "ops_price": 100,
            "target": target,
            "bls_signature": hex::encode(sig),
        })
    );
}
