//! Benchmark scenarios for the ECDSA-STARK baseline verifier.
//!
//! Measurement method (paired-test subtraction): the harness runs `bench_verify_*` and
//! `bench_baseline_*`, which build IDENTICAL inputs; only the former calls `verify`. The
//! per-scheme verification cost is `verify_total - baseline_total` for each metric (steps,
//! L2 gas), which cancels out test-harness and input-construction overhead.

use openzeppelin_testing::constants::stark::KEY_PAIR;
use openzeppelin_testing::signing::SerializedSigning;
use pqbench_ecdsa_stark::EcdsaStarkVerifier;
use pqbench_interface::PqSignatureVerifier;

const MSG: felt252 = 'BENCH_MSG';

/// Builds the inputs but does NOT verify — the subtraction baseline.
#[test]
fn bench_baseline_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let public_key = array![key_pair.public_key];
    assert!(signature.len() == 2);
    assert!(public_key.len() == 1);
}

/// Builds the inputs and verifies — the measured scenario.
#[test]
fn bench_verify_ecdsa_stark() {
    let key_pair = KEY_PAIR();
    let signature = key_pair.serialized_sign(MSG);
    let public_key = array![key_pair.public_key];
    let valid = EcdsaStarkVerifier::verify(MSG, public_key.span(), signature.span());
    assert!(valid);
}

#[test]
fn test_is_valid_public_key() {
    let key_pair = KEY_PAIR();
    assert!(EcdsaStarkVerifier::is_valid_public_key(array![key_pair.public_key].span()));
    assert!(!EcdsaStarkVerifier::is_valid_public_key(array![].span()));
    assert!(!EcdsaStarkVerifier::is_valid_public_key(array![key_pair.public_key, 1].span()));
    // Not every felt is the x-coordinate of a curve point; at least one of 1..=16 is not.
    let mut found_invalid = false;
    for x in 1_u8..17 {
        if !EcdsaStarkVerifier::is_valid_public_key(array![x.into()].span()) {
            found_invalid = true;
        }
    }
    assert!(found_invalid);
}
