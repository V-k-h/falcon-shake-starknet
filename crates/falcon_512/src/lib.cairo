//! Falcon-512 (FN-DSA) signature verifiers with the standard SHAKE-256 hash-to-point:
//! a hint variant and a direct (hint-free) variant.
//!
//! Verification runs entirely on-chain: the message point is derived from `message_hash`
//! and the signature salt with the Falcon SHAKE-256 hash-to-point (see
//! `hashing/hash_to_point.cairo`), the packed inputs are validated canonical on unpack, and
//! the polynomial product `s1 * h` is either bound to the signer-supplied hint through two
//! forward NTTs and a pointwise check, or computed directly as `INTT(NTT(s1) ∘ h_ntt)`.
//!
//! Fixture generation for tests/benchmarks: `scripts/gen_falcon_fixture.py`.

pub mod falcon;
pub mod fixtures;
pub mod hashing;
pub mod packing;
pub mod zq;
use hashing::hash_to_point;
use pqbench_interface::PqSignatureVerifier;

/// Hint-variant signature layout: packed s1 (29 felts) || salt (2 felts, 20 LE bytes
/// each) || packed mul_hint = s1*h mod (q, x^512+1) (29 felts).
pub const SIG_FELTS: u32 = 60;
/// Direct-variant signature layout: packed s1 (29 felts) || salt (2 felts) — a prefix
/// of the hint-variant layout, so one signer output serves both schemes.
pub const SIG_FELTS_DIRECT: u32 = 31;
/// Public key layout: packed NTT-domain h (29 felts).
pub const PUBKEY_FELTS: u32 = 29;

/// Standard SHAKE-256 hint variant.
///
/// Encoding: `public_key` = 29 felts (512 NTT coeffs, base-Q packed); `signature` = 60
/// felts (s1, salt, mul hint). The message point uses the Falcon SHAKE-256 hash-to-point
/// ([`hash_to_point::hash_to_point_shake_512`]), so signatures are interoperable with any
/// standards-compliant Falcon signer. Returns `false` on any malformed input (wrong
/// length, non-canonical packing, oversized salt), bad hint, or norm above the Falcon-512
/// bound.
pub impl Falcon512ShakeVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        if public_key.len() != PUBKEY_FELTS || signature.len() != SIG_FELTS {
            return false;
        }
        let h_ntt = match packing::unpack_512_u16(public_key) {
            Some(v) => v,
            None => { return false; },
        };
        let s1 = match packing::unpack_512_u16(signature.slice(0, 29)) {
            Some(v) => v,
            None => { return false; },
        };
        let salt_a = *signature.at(29);
        let salt_b = *signature.at(30);
        let mul_hint = match packing::unpack_512_u16(signature.slice(31, 29)) {
            Some(v) => v,
            None => { return false; },
        };
        let msg_point = match hash_to_point::hash_to_point_shake_512(message_hash, salt_a, salt_b) {
            Some(v) => v,
            None => { return false; },
        };
        falcon::verify_512_with_hint_u16(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span())
    }
}

/// Standard SHAKE-256 direct variant: the SHAKE-256 hash-to-point of
/// [`Falcon512ShakeVerifier`] over the hint-free core (`s1*h = INTT(NTT(s1) ∘ h_ntt)`,
/// 31-felt signature). This is the closest on-chain match to a bare standard Falcon
/// signature: standard hash, one short polynomial, and no signer-supplied product, so the
/// smallest input trust surface. Same public key as [`Falcon512ShakeVerifier`].
pub impl Falcon512ShakeDirectVerifier of PqSignatureVerifier {
    fn verify(message_hash: felt252, public_key: Span<felt252>, signature: Span<felt252>) -> bool {
        if public_key.len() != PUBKEY_FELTS || signature.len() != SIG_FELTS_DIRECT {
            return false;
        }
        let h_ntt = match packing::unpack_512_u16(public_key) {
            Some(v) => v,
            None => { return false; },
        };
        let s1 = match packing::unpack_512_u16(signature.slice(0, 29)) {
            Some(v) => v,
            None => { return false; },
        };
        let salt_a = *signature.at(29);
        let salt_b = *signature.at(30);
        let msg_point = match hash_to_point::hash_to_point_shake_512(message_hash, salt_a, salt_b) {
            Some(v) => v,
            None => { return false; },
        };
        falcon::verify_512_direct_u16(s1.span(), h_ntt.span(), msg_point.span())
    }
}
