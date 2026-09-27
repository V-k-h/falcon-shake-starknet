//! Benchmarks for the public felt-coefficient verifiers, `verify_512_with_hint` and
//! `verify_512_direct`, by paired-test subtraction: each baseline builds the same unpacked
//! inputs from the SHAKE-256 fixture (the coefficients and the message point) and omits
//! only the call, so the measured cost is the input validation plus the verification core.

use pqbench_falcon_512::falcon::{verify_512_direct, verify_512_with_hint};
use pqbench_falcon_512::fixtures::shake::{msg, public_key, signature};
use pqbench_falcon_512::hashing::hash_to_point::hash_to_point_shake_512;
use pqbench_falcon_512::packing::unpack_512;

/// The fixture as felt coefficients: `s1`, NTT-domain `h`, `mul_hint`, and the message
/// point.
fn inputs() -> (Array<felt252>, Array<felt252>, Array<felt252>, Array<u16>) {
    let (pk, sig) = (public_key(), signature());
    let s1 = unpack_512(sig.span().slice(0, 29)).unwrap();
    let h_ntt = unpack_512(pk.span()).unwrap();
    let mul_hint = unpack_512(sig.span().slice(31, 29)).unwrap();
    let point = hash_to_point_shake_512(msg(), *sig.at(29), *sig.at(30)).unwrap();
    (s1, h_ntt, mul_hint, point)
}

#[test]
fn bench_baseline_verify_512_with_hint() {
    let (s1, h_ntt, mul_hint, point) = inputs();
    assert!(s1.len() + h_ntt.len() + mul_hint.len() + point.len() == 2048);
}

#[test]
fn bench_verify_512_with_hint() {
    let (s1, h_ntt, mul_hint, point) = inputs();
    assert!(s1.len() + h_ntt.len() + mul_hint.len() + point.len() == 2048);
    assert!(verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), point.span()));
}

#[test]
fn bench_baseline_verify_512_direct() {
    let (s1, h_ntt, mul_hint, point) = inputs();
    assert!(s1.len() + h_ntt.len() + mul_hint.len() + point.len() == 2048);
}

#[test]
fn bench_verify_512_direct() {
    let (s1, h_ntt, mul_hint, point) = inputs();
    assert!(s1.len() + h_ntt.len() + mul_hint.len() + point.len() == 2048);
    assert!(verify_512_direct(s1.span(), h_ntt.span(), point.span()));
}
