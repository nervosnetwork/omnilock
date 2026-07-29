#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    bytes::Bytes,
    bytes::BytesMut,
    core::{
        cell::ResolvedTransaction, hardfork::HardForkSwitch, EpochNumberWithFraction, HeaderView,
    },
    packed::{CellInput, WitnessArgs},
    prelude::*,
    H256,
};
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

#[test]
fn test_since_relative_epoch() {
    let mut data_loader = DummyDataLoader::new();

    let since_epoch = EpochNumberWithFraction::new(200, 5, 100);
    // relative epoch flag: 0b10100000 << 56
    let args_since = 0xa000_0000_0000_0000u64 + since_epoch.full_value();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, 0);

    let raw_tx = gen_tx(&mut data_loader, &mut config);

    {
        // default since is 0, flags mismatch
        let tx = sign_tx(&mut data_loader, raw_tx.clone(), &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_FLAGS);
    }
    {
        // absolute epoch flag instead of relative
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + since_epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_FLAGS);
    }
    {
        // smaller fraction: 200 + 2/200 < 200 + 5/100
        let epoch = EpochNumberWithFraction::new(200, 2, 200);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0xa000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
    }
    {
        // larger fraction with different encoding: 200 + 6/50 > 200 + 5/100
        let epoch = EpochNumberWithFraction::new(200, 6, 50);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0xa000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        // larger fraction: 200 + 1/2 > 200 + 5/100
        let epoch = EpochNumberWithFraction::new(200, 1, 2);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0xa000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        // exact match
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(args_since.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        // larger value
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since((args_since + 1).pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
}

#[test]
fn test_since_epoch_length_zero() {
    let mut data_loader = DummyDataLoader::new();

    let since_epoch = EpochNumberWithFraction::new(200, 5, 100);
    let args_since = 0x2000_0000_0000_0000u64 + since_epoch.full_value();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, 0);

    let raw_tx = gen_tx(&mut data_loader, &mut config);

    {
        // input since has length=0, index=100, epoch=200
        // Since len=0 is treated as len=1, 100/1 > 5/100, so it should fail
        let input_since = 0x2000_0000_0000_0000u64 | (100u64 << 24) | 200u64;
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(input_since.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
    }
    {
        // input since has epoch=201, length=0
        // epoch 201 > 200, so it should pass
        let input_since = 0x2000_0000_0000_0000u64 | 201u64;
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(input_since.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        // input has epoch 200, index 4, length 100 → 4/100 < 5/100, should fail
        let epoch = EpochNumberWithFraction::new(200, 4, 100);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
    }
    {
        // input has epoch 200, index 6, length 100 → 6/100 > 5/100, should pass
        let epoch = EpochNumberWithFraction::new(200, 6, 100);
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| {
                i.as_builder()
                    .since((0x2000_0000_0000_0000u64 + epoch.full_value()).pack())
                    .build()
            })
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        // exact match
        let inputs: Vec<CellInput> = raw_tx
            .inputs()
            .into_iter()
            .map(|i| i.as_builder().since(args_since.pack()).build())
            .collect();
        let raw_tx = raw_tx.as_advanced_builder().set_inputs(inputs).build();
        let tx = sign_tx(&mut data_loader, raw_tx, &mut config);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let mut verifier =
            TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
        verifier.set_debug_printer(debug_printer);
        let verify_result = verifier.verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
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
