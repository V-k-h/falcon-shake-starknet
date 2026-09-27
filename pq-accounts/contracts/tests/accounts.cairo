//! End-to-end tests of the deployable Falcon-512 SHAKE-256 accounts (hint and direct):
//! key validation at deployment, transaction and deploy validation, SNIP-6 signature
//! checks, the `__execute__` guards, public-key rotation with proof of possession, and
//! class upgrades. Every scenario runs against both accounts with genuine falcon.py
//! signatures.

use core::poseidon::poseidon_hash_span;
use pq_accounts::utils::account::PqAccountComponent;
use pq_accounts::utils::interface::{
    IFeltArrayDeployableSafeDispatcher, IFeltArrayDeployableSafeDispatcherTrait,
    IFeltArrayPublicKeyDispatcher, IFeltArrayPublicKeyDispatcherTrait,
    IFeltArrayPublicKeySafeDispatcher, IFeltArrayPublicKeySafeDispatcherTrait, IPqAccountDispatcher,
    IPqAccountDispatcherTrait, IPqAccountSafeDispatcher, IPqAccountSafeDispatcherTrait, ISRC5_ID,
    ISRC6_ID, IUpgradeableSafeDispatcher, IUpgradeableSafeDispatcherTrait,
};
use pqbench_falcon_512::fixtures::shake;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, get_class_hash,
    spy_events, start_cheat_caller_address, start_cheat_chain_id_global, start_cheat_signature,
    start_cheat_transaction_hash, start_cheat_transaction_version,
};
use starknet::{ClassHash, ContractAddress};
use crate::fixtures;

const HINT: felt252 = 'hint';
const DIRECT: felt252 = 'direct';

fn contract_name(variant: felt252) -> ByteArray {
    if variant == HINT {
        "Falcon512ShakeAccount"
    } else {
        "Falcon512ShakeDirectAccount"
    }
}

/// `signature` in the variant's layout: all 60 felts for hint, the 31-felt prefix for direct.
fn layout(variant: felt252, signature: Array<felt252>) -> Array<felt252> {
    if variant == HINT {
        return signature;
    }
    let mut out = array![];
    let mut prefix = signature.span().slice(0, 31);
    while let Some(f) = prefix.pop_front() {
        out.append(*f);
    }
    out
}

fn account_address() -> ContractAddress {
    fixtures::ACCOUNT_ADDRESS.try_into().unwrap()
}

fn calldata(public_key: Array<felt252>) -> Array<felt252> {
    let mut calldata = array![];
    public_key.serialize(ref calldata);
    calldata
}

/// Deploys the variant's account with `public_key` at the fixture address, on the fixture
/// chain id.
fn deploy(variant: felt252, public_key: Array<felt252>) -> Result<ContractAddress, Array<felt252>> {
    deploy_at(variant, public_key, account_address())
}

/// Deploys the variant's account with `public_key` at `address`, on the fixture chain id.
fn deploy_at(
    variant: felt252, public_key: Array<felt252>, address: ContractAddress,
) -> Result<ContractAddress, Array<felt252>> {
    start_cheat_chain_id_global(fixtures::CHAIN_ID);
    let class = declare(contract_name(variant)).unwrap().contract_class();
    match class.deploy_at(@calldata(public_key), address) {
        Ok((address, _)) => Ok(address),
        Err(panic_data) => Err(panic_data),
    }
}

/// Deploys the variant's account with the bench key and sets the transaction it validates:
/// the bench message hash and `signature`.
fn deploy_bench(variant: felt252, signature: Array<felt252>) -> ContractAddress {
    let address = deploy(variant, shake::public_key()).unwrap();
    start_cheat_transaction_hash(address, shake::msg());
    start_cheat_signature(address, layout(variant, signature).span());
    address
}

/// Copy of `values` with `values[index]` replaced by `value`.
fn with_felt(values: Array<felt252>, index: u32, value: felt252) -> Array<felt252> {
    let mut out = array![];
    let mut i = 0;
    for v in values {
        out.append(if i == index {
            value
        } else {
            v
        });
        i += 1;
    }
    out
}

fn first_word(data: Array<felt252>) -> felt252 {
    *data.at(0)
}

// --- Deployment ---

fn assert_deploy_stores_key_and_emits(variant: felt252) {
    let mut spy = spy_events();
    let address = deploy(variant, shake::public_key()).unwrap();
    let account = IFeltArrayPublicKeyDispatcher { contract_address: address };
    assert_eq!(account.get_public_key(), shake::public_key());
    let added = PqAccountComponent::PublicKeyAdded {
        key_hash: poseidon_hash_span(shake::public_key().span()),
    };
    spy.assert_emitted(@array![(address, PqAccountComponent::Event::PublicKeyAdded(added))]);
}

fn assert_deploy_rejects_malformed_keys(variant: felt252) {
    // Each attempt uses its own address: a failed deployment still claims its address in
    // the test environment.
    let mut short = shake::public_key();
    let _ = short.pop_front();
    let err = deploy_at(variant, short, 0x111.try_into().unwrap()).unwrap_err();
    assert_eq!(first_word(err), 'Account: invalid public key');
    // A low half at or above Q^9 is not a canonical base-Q digit string.
    let noncanonical = with_felt(shake::public_key(), 4, 0xffffffffffffffffffffffffffffffff);
    let err = deploy_at(variant, noncanonical, 0x222.try_into().unwrap()).unwrap_err();
    assert_eq!(first_word(err), 'Account: invalid public key');
    let err = deploy_at(variant, array![], 0x333.try_into().unwrap()).unwrap_err();
    assert_eq!(first_word(err), 'Account: invalid public key');
}

#[test]
fn test_hint_deploy_stores_key_and_emits() {
    assert_deploy_stores_key_and_emits(HINT);
}

#[test]
fn test_direct_deploy_stores_key_and_emits() {
    assert_deploy_stores_key_and_emits(DIRECT);
}

#[test]
fn test_hint_deploy_rejects_malformed_keys() {
    assert_deploy_rejects_malformed_keys(HINT);
}

#[test]
fn test_direct_deploy_rejects_malformed_keys() {
    assert_deploy_rejects_malformed_keys(DIRECT);
}

// --- Validation and SNIP-6 ---

#[feature("safe_dispatcher")]
fn assert_validation(variant: felt252) {
    let address = deploy_bench(variant, shake::signature());
    let account = IPqAccountSafeDispatcher { contract_address: address };
    assert_eq!(account.__validate__(array![]).unwrap(), starknet::VALIDATED);
    assert_eq!(account.__validate_declare__(0x1234).unwrap(), starknet::VALIDATED);
    let deployable = IFeltArrayDeployableSafeDispatcher { contract_address: address };
    assert_eq!(
        deployable.__validate_deploy__(0x1, 0x2, shake::public_key()).unwrap(), starknet::VALIDATED,
    );

    // The same signature under a different transaction hash.
    start_cheat_transaction_hash(address, 'OTHER_MSG');
    assert_eq!(
        first_word(account.__validate__(array![]).unwrap_err()), 'Account: invalid signature',
    );

    // A tampered salt under the right transaction hash.
    start_cheat_transaction_hash(address, shake::msg());
    let sig = shake::signature();
    let salt = *sig.at(29);
    start_cheat_signature(address, layout(variant, with_felt(sig, 29, salt + 1)).span());
    assert_eq!(
        first_word(account.__validate__(array![]).unwrap_err()), 'Account: invalid signature',
    );
}

fn assert_is_valid_signature(variant: felt252) {
    let address = deploy(variant, shake::public_key()).unwrap();
    let account = IPqAccountDispatcher { contract_address: address };
    let sig = layout(variant, shake::signature());
    assert_eq!(account.is_valid_signature(shake::msg(), sig.clone()), starknet::VALIDATED);
    assert_eq!(account.is_valid_signature('OTHER_MSG', sig), 0);
    assert_eq!(account.is_valid_signature(shake::msg(), array![]), 0);
    assert_eq!(account.is_valid_signature(shake::msg(), shake::public_key()), 0);
    assert!(account.supports_interface(ISRC5_ID));
    assert!(account.supports_interface(ISRC6_ID));
    assert!(!account.supports_interface(0x123));
}

#[feature("safe_dispatcher")]
fn assert_execute_guards(variant: felt252) {
    let address = deploy_bench(variant, shake::signature());
    let account = IPqAccountSafeDispatcher { contract_address: address };
    // Called by another contract.
    start_cheat_caller_address(address, 0xbad.try_into().unwrap());
    assert_eq!(first_word(account.__execute__(array![]).unwrap_err()), 'Account: invalid caller');
    // Called by the protocol with an unsupported transaction version.
    start_cheat_caller_address(address, 0.try_into().unwrap());
    start_cheat_transaction_version(address, 0);
    assert_eq!(
        first_word(account.__execute__(array![]).unwrap_err()), 'Account: invalid tx version',
    );
    // Called by the protocol with a supported version.
    start_cheat_transaction_version(address, 3);
    account.__execute__(array![]).unwrap();
}

#[test]
fn test_hint_validation() {
    assert_validation(HINT);
}

#[test]
fn test_direct_validation() {
    assert_validation(DIRECT);
}

#[test]
fn test_hint_is_valid_signature() {
    assert_is_valid_signature(HINT);
}

#[test]
fn test_direct_is_valid_signature() {
    assert_is_valid_signature(DIRECT);
}

#[test]
fn test_hint_execute_guards() {
    assert_execute_guards(HINT);
}

#[test]
fn test_direct_execute_guards() {
    assert_execute_guards(DIRECT);
}

// --- Public-key rotation ---

#[feature("safe_dispatcher")]
fn assert_rotation_rejections(variant: felt252) {
    let address = deploy(variant, shake::public_key()).unwrap();
    let keys = IFeltArrayPublicKeySafeDispatcher { contract_address: address };
    let proof = layout(variant, fixtures::rotation_proof());

    // Not a self-call.
    assert_eq!(
        first_word(keys.set_public_key(fixtures::new_public_key(), proof.clone()).unwrap_err()),
        'Account: unauthorized',
    );

    start_cheat_caller_address(address, address);
    // Malformed new key.
    let mut short = fixtures::new_public_key();
    let _ = short.pop_front();
    assert_eq!(
        first_word(keys.set_public_key(short, proof.clone()).unwrap_err()),
        'Account: invalid public key',
    );
    // A valid signature by the new key, but of another message.
    let wrong = layout(variant, fixtures::new_key_signature());
    assert_eq!(
        first_word(keys.set_public_key(fixtures::new_public_key(), wrong).unwrap_err()),
        'Account: invalid key proof',
    );
    // The right proof is bound to the chain id: it fails on another chain.
    start_cheat_chain_id_global('SN_SEPOLIA');
    assert_eq!(
        first_word(keys.set_public_key(fixtures::new_public_key(), proof.clone()).unwrap_err()),
        'Account: invalid key proof',
    );
    // Nothing changed.
    start_cheat_chain_id_global(fixtures::CHAIN_ID);
    assert_eq!(keys.get_public_key().unwrap(), shake::public_key());
}

#[feature("safe_dispatcher")]
fn assert_rotation(variant: felt252) {
    let address = deploy_bench(variant, shake::signature());
    let keys = IFeltArrayPublicKeyDispatcher { contract_address: address };
    let account = IPqAccountSafeDispatcher { contract_address: address };

    // The off-chain rotation hash (Python Poseidon) matches the account's own.
    assert_eq!(
        keys.get_public_key_rotation_hash(fixtures::new_public_key()), fixtures::ROTATION_HASH,
    );

    let mut spy = spy_events();
    start_cheat_caller_address(address, address);
    keys.set_public_key(fixtures::new_public_key(), layout(variant, fixtures::rotation_proof()));
    assert_eq!(keys.get_public_key(), fixtures::new_public_key());
    let removed = PqAccountComponent::PublicKeyRemoved {
        key_hash: poseidon_hash_span(shake::public_key().span()),
    };
    let added = PqAccountComponent::PublicKeyAdded {
        key_hash: poseidon_hash_span(fixtures::new_public_key().span()),
    };
    spy
        .assert_emitted(
            @array![
                (address, PqAccountComponent::Event::PublicKeyRemoved(removed)),
                (address, PqAccountComponent::Event::PublicKeyAdded(added)),
            ],
        );

    // The old key no longer validates; the new key does.
    assert_eq!(
        first_word(account.__validate__(array![]).unwrap_err()), 'Account: invalid signature',
    );
    start_cheat_signature(address, layout(variant, fixtures::new_key_signature()).span());
    assert_eq!(account.__validate__(array![]).unwrap(), starknet::VALIDATED);
}

#[test]
fn test_hint_rotation_rejections() {
    assert_rotation_rejections(HINT);
}

#[test]
fn test_direct_rotation_rejections() {
    assert_rotation_rejections(DIRECT);
}

#[test]
fn test_hint_rotation() {
    assert_rotation(HINT);
}

#[test]
fn test_direct_rotation() {
    assert_rotation(DIRECT);
}

// --- Upgrades ---

#[feature("safe_dispatcher")]
fn assert_upgrade(variant: felt252, target: felt252) {
    let address = deploy(variant, shake::public_key()).unwrap();
    let upgradeable = IUpgradeableSafeDispatcher { contract_address: address };
    let target_class: ClassHash = *declare(contract_name(target))
        .unwrap()
        .contract_class()
        .class_hash;

    assert_eq!(first_word(upgradeable.upgrade(target_class).unwrap_err()), 'Account: unauthorized');

    start_cheat_caller_address(address, address);
    let zero: ClassHash = 0.try_into().unwrap();
    assert_eq!(first_word(upgradeable.upgrade(zero).unwrap_err()), 'Account: invalid class hash');

    let mut spy = spy_events();
    upgradeable.upgrade(target_class).unwrap();
    assert_eq!(get_class_hash(address), target_class);
    let upgraded = PqAccountComponent::Upgraded { class_hash: target_class };
    spy.assert_emitted(@array![(address, PqAccountComponent::Event::Upgraded(upgraded))]);
    // The key survives the class change.
    let keys = IFeltArrayPublicKeyDispatcher { contract_address: address };
    assert_eq!(keys.get_public_key(), shake::public_key());
}

#[test]
fn test_hint_upgrade_to_direct() {
    assert_upgrade(HINT, DIRECT);
}

#[test]
fn test_direct_upgrade_to_hint() {
    assert_upgrade(DIRECT, HINT);
}
