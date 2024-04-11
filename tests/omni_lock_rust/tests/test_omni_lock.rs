#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    bytes::Bytes,
    bytes::BytesMut,
    core::{
        cell::ResolvedTransaction, hardfork::HardForkSwitch, EpochNumberWithFraction, HeaderView,
    },
    packed::WitnessArgs,
    prelude::*,
    H256,
};
use ed25519_dalek::SigningKey;
use lazy_static::lazy_static;
use misc::*;

//
// owner lock section
//
#[test]
fn test_simple_owner_lock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    // For ckb 0.40.0
    // let mut verifier =
    //     TransactionScriptsVerifier::new(&resolved_tx, &data_loader);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_owner_lock_mismatched() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme = TestScheme::OwnerLockMismatched;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_LOCK_SCRIPT_HASH_NOT_FOUND)
}

#[test]
fn test_owner_lock_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_owner_lock_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NOT_ON_WHITE_LIST)
}

#[test]
fn test_owner_lock_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    // only black list is used, but not on it.
    // but omni_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_WHITE_LIST)
}

#[test]
fn test_owner_lock_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ON_BLACK_LIST)
}

#[test]
fn test_owner_lock_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RCE_EMERGENCY_HALT)
}

//
// pubkey hash section
//

#[test]
fn test_pubkey_hash_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_without_omni_identity() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.set_omni_identity(false);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_pubkey_hash_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NOT_ON_WHITE_LIST)
}

#[test]
fn test_pubkey_hash_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    // only black list is used, but not on it.
    // but omni_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_WHITE_LIST)
}

#[test]
fn test_pubkey_hash_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ON_BLACK_LIST)
}

#[test]
fn test_pubkey_hash_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RCE_EMERGENCY_HALT)
}

#[test]
fn test_rsa_via_dl_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rsa_via_dl_wrong_sig() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.scheme = TestScheme::RsaWrongSignature;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RSA_VERIFY_FAILED);
}

#[test]
fn test_rsa_via_dl_unlock_with_time_lock() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 200;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rsa_via_dl_unlock_with_time_lock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 100;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
}

// currently, the signature can only be signed via hardware.
// Here we can only provide a failed case.
#[test]
fn test_iso9796_2_batch_via_dl_unlock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_iso9796_2();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_eth_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM, false);
    config.set_chain_config(Box::new(EthereumConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_btc_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_btc_err_pubkey(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: true,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

fn test_btc(vtype: u8) {
    test_btc_success(vtype);
    test_btc_err_pubkey(vtype);
}

#[test]
fn test_btc_unlock() {
    test_btc(BITCOIN_V_TYPE_P2PKHUNCOMPRESSED);
    test_btc(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
    test_btc(BITCOIN_V_TYPE_SEGWITP2SH);
    test_btc(BITCOIN_V_TYPE_SEGWITBECH32);
}

#[test]
fn test_dogecoin_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DOGECOIN, false);
    config.set_chain_config(Box::new(DogecoinConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dogecoin_err_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DOGECOIN, false);
    let mut dogecoin = DogecoinConfig::default();
    dogecoin.0.pubkey_err = true;
    config.set_chain_config(Box::new(dogecoin));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err())
}

fn test_eos_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_EOS, false);
    let mut eos = EOSConfig::default();
    eos.0.sign_vtype = vtype;
    config.set_chain_config(Box::new(EOSConfig::default()));

    let tx: ckb_types::core::TransactionView = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_eos_err_pubkey(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_EOS, false);
    let mut eos = EOSConfig::default();
    eos.0.sign_vtype = vtype;
    eos.0.pubkey_err = true;
    config.set_chain_config(Box::new(eos));

    let tx: ckb_types::core::TransactionView = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

fn test_eos(vtype: u8) {
    test_eos_success(vtype);
    test_eos_err_pubkey(vtype)
}

#[test]
fn test_eos_unlock() {
    test_eos(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
    test_eos(BITCOIN_V_TYPE_P2PKHUNCOMPRESSED);
}

#[test]
fn test_tron_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_TRON, false);
    config.set_chain_config(Box::new(TronConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_tron_err_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_TRON, false);
    let mut tron = TronConfig::default();
    tron.pubkey_err = true;
    config.set_chain_config(Box::new(tron));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

#[test]
fn test_eth_displaying_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM_DISPLAYING, false);
    config.set_chain_config(Box::new(EthereumDisplayConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_solana_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_SOLANA, false);
    config.solana_secret_key = [0x01u8; 32];
    config.sig_len = 96;

    let signing_key = SigningKey::from_bytes(&config.solana_secret_key);
    let verifying_key = signing_key.verifying_key();
    let blake160 = blake160(&verifying_key.to_bytes());
    let auth = Identity {
        flags: IDENTITY_FLAGS_SOLANA,
        blake160,
    };
    config.id = auth;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_solana_wrong_auth() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_SOLANA, false);
    config.solana_secret_key = [0x01u8; 32];
    config.sig_len = 96;

    let signing_key = SigningKey::from_bytes(&config.solana_secret_key);
    let verifying_key = signing_key.verifying_key();
    let blake160 = blake160(&verifying_key.to_bytes());
    let mut blake160: Vec<u8> = blake160.into();
    blake160[0] ^= 0x01;
    let blake160: Bytes = blake160.into();
    let auth = Identity {
        flags: IDENTITY_FLAGS_SOLANA,
        blake160,
    };
    config.id = auth;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

#[test]
fn test_solana_wrong_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_SOLANA, false);
    config.solana_secret_key = [0x01u8; 32];
    config.sig_len = 96;
    config.scheme = TestScheme::SolanaWrongPubkey;

    let signing_key = SigningKey::from_bytes(&config.solana_secret_key);
    let verifying_key = signing_key.verifying_key();
    let blake160 = blake160(&verifying_key.to_bytes());
    let auth = Identity {
        flags: IDENTITY_FLAGS_SOLANA,
        blake160,
    };
    config.id = auth;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MISMATCHED);
}

#[test]
fn test_solana_wrong_signature() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_SOLANA, false);
    config.solana_secret_key = [0x01u8; 32];
    config.sig_len = 96;
    config.scheme = TestScheme::SolanaWrongSignature;

    let signing_key = SigningKey::from_bytes(&config.solana_secret_key);
    let verifying_key = signing_key.verifying_key();
    let blake160 = blake160(&verifying_key.to_bytes());
    let auth = Identity {
        flags: IDENTITY_FLAGS_SOLANA,
        blake160,
    };
    config.id = auth;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MISMATCHED);
}

/// Steps to update this test case:
///
/// 1. Install Phantom wallet from: [Phantom Wallet](https://phantom.app/)
/// 2. Create an account on the wallet and obtain the Solana address. Update it
///    to the variable `address`.
/// 3. Run `cargo test test_solana_phantom_wallet -- --nocapture`. Find the
///    message to sign, for example:
///    ```
///    Message to be signed by ed25519: CKB transaction:
///    0xd3f012c170b17dc3af2287800a36326c115a82106ded34a05c925345007a988c
///    ```
/// 4. Sign the message using [Phantom's message signing functionality](https://docs.phantom.app/solana/signing-a-message), e.g.:
///    ```
///    provider.signMessage(new TextEncoder().encode("CKB transaction:
///    0xd3f012c170b17dc3af2287800a36326c115a82106ded34a05c925345007a988c"),
///    "utf8")
///    ```
/// 5. Update the variable `sig` with the obtained signature.
///
#[test]
fn test_solana_phantom_wallet() {
    let mut data_loader = DummyDataLoader::new();
    let address = "FK577f9qN4jiUJkQoiXvjuCcwmwLmB3sWwzBzX3ij8wG";
    let mut sig = vec![
        110, 136, 73, 29, 91, 65, 30, 129, 36, 62, 6, 82, 128, 173, 75, 247, 131, 116, 154, 120,
        51, 37, 32, 32, 164, 43, 243, 66, 75, 190, 219, 196, 209, 118, 29, 0, 84, 117, 118, 5, 155,
        225, 113, 168, 41, 244, 10, 197, 216, 17, 213, 53, 114, 196, 39, 8, 17, 34, 54, 71, 12,
        133, 200, 6,
    ];

    let verifying_key = bs58::decode(address).into_vec().unwrap();
    sig.extend(verifying_key.clone());

    let mut config = TestConfig::new(IDENTITY_FLAGS_SOLANA, false);
    config.random_tx = false;
    config.sig_len = 96;

    let blake160 = blake160(&verifying_key);
    let auth = Identity {
        flags: IDENTITY_FLAGS_SOLANA,
        blake160,
    };
    config.id = auth;
    assert_eq!(sig.len(), 96);
    config.solana_phantom_sig = Some(sig);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = misc::gen_consensus();
    let tx_env = misc::gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
