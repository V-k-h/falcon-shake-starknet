//! Falcon-512 hash-to-point with the standard SHAKE-256 construction of the Falcon
//! specification (the FN-DSA hash-to-point): absorb `salt || message_hash` with SHAKE-256,
//! then read the squeezed stream as big-endian 16-bit words, accepting `word % Q` while
//! `word < 5Q`, until 512 coefficients are collected. Signatures are therefore
//! interoperable with any standards-compliant Falcon signer (e.g. falcon.py).
//!
//! The message hash is absorbed as its 32 little-endian bytes and the 40-byte salt as two
//! felts of 20 little-endian bytes each.

use super::shake256::keccak_f1600;

/// Rejection bound: the largest multiple of Q below 2^16 (5 * 12289).
const REJECT_BOUND: u32 = 61445;

/// Each salt felt must fit in 20 bytes.
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000_u256;

/// Rejection-sample one 16-bit candidate: accept `candidate % Q` while below the
/// bound and 512 coefficients have not been collected yet.
#[inline(always)]
fn push_candidate(candidate: u32, q32: NonZero<u32>, ref coeffs: Array<u16>) {
    if coeffs.len() != 512 && candidate < REJECT_BOUND {
        let (_, r) = DivRem::div_rem(candidate, q32);
        coeffs.append(r.try_into().unwrap());
    }
}

/// ## Construction
///
/// The standard Falcon construction (FN-DSA; FIPS 206 is pending): absorb
/// `salt || message_hash` with SHAKE-256, then consume the squeezed stream as big-endian
/// 16-bit words, applying the [`push_candidate`] rule (accept `word % Q` while
/// `word < 5Q`) until 512 coefficients are collected. This is interoperable with any
/// standards-compliant Falcon signer (e.g. falcon.py). The message hash is absorbed as
/// its 32 little-endian bytes, the salt as its two 20-byte little-endian halves.
///
/// The sponge is driven directly on the Keccak lanes: the 72-byte input fits a single
/// rate block whose padded lanes are assembled straight from the salt and message-hash
/// limbs, and squeezing reads candidate words from the 17 rate lanes in place
/// ([`push_lane_words`]), permuting again only while more candidates are needed.

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)` with the standard
/// SHAKE-256 construction. Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_shake_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let mh: u256 = message_hash.into();

    // The absorbed block, assembled directly as little-endian lanes: bytes 0..40 hold
    // the salt, 40..72 the message hash, byte 72 the 0x1F SHAKE domain byte, and byte
    // 135 the pad10*1 terminator. The sponge state starts at zero, so this first
    // (and only) absorbed block IS the pre-permutation state.
    let two64: NonZero<u128> = 0x10000000000000000_u128.try_into().unwrap();
    let two32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (a1, a0) = DivRem::div_rem(sa.low, two64); // salt_a bytes 0..8 and 8..16
    let (sbq, sb0) = DivRem::div_rem(sb.low, two32); // salt_b bytes 0..4 and 4..16
    let (sb12, l3) = DivRem::div_rem(sbq, two64); // salt_b bytes 4..12 -> lane 3
    let (m1, m0) = DivRem::div_rem(mh.low, two64);
    let (m3, m2) = DivRem::div_rem(mh.high, two64);
    // Lane 2: salt_a bytes 16..20 in the low half, salt_b bytes 0..4 in the high half.
    let l2: u128 = (sa.high.into() + sb0.into() * 0x100000000).try_into().unwrap();
    // Lane 4: salt_b bytes 12..16 in the low half, salt_b bytes 16..20 in the high half.
    let l4: u128 = (sb12.into() + sb.high.into() * 0x100000000).try_into().unwrap();

    let mut state = keccak_f1600(
        [
            a0, a1, l2, l3, l4, m0, m1, m2, m3, 0x1f, 0, 0, 0, 0, 0, 0, 0x8000000000000000, 0, 0, 0,
            0, 0, 0, 0, 0,
        ],
    );

    let q32: NonZero<u32> = 12289_u32.try_into().unwrap();
    let two16: NonZero<u64> = 0x10000_u64.try_into().unwrap();
    let b256: NonZero<u64> = 0x100_u64.try_into().unwrap();
    let mut coeffs: Array<u16> = array![];
    loop {
        let mut lanes = state.span().slice(0, 17);
        while let Some(lane) = lanes.pop_front() {
            push_lane_words(*lane, two16, b256, q32, ref coeffs);
        }
        if coeffs.len() == 512 {
            break;
        }
        state = keccak_f1600(state);
    }
    Some(coeffs)
}

/// Read one squeezed rate lane (< 2^64) as four big-endian 16-bit candidate words. The
/// lane's bytes are little-endian, so each 16-bit chunk holds its stream word
/// byte-swapped: chunk = b0 + 256*b1 for the stream word 256*b0 + b1.
#[inline(always)]
fn push_lane_words(
    lane: u128, two16: NonZero<u64>, b256: NonZero<u64>, q32: NonZero<u32>, ref coeffs: Array<u16>,
) {
    let lane64: u64 = lane.try_into().unwrap();
    let (rest, c0) = DivRem::div_rem(lane64, two16);
    let (rest, c1) = DivRem::div_rem(rest, two16);
    let (c3, c2) = DivRem::div_rem(rest, two16);
    let (b1, b0) = DivRem::div_rem(c0, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
    let (b1, b0) = DivRem::div_rem(c1, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
    let (b1, b0) = DivRem::div_rem(c2, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
    let (b1, b0) = DivRem::div_rem(c3, b256);
    push_candidate((b0 * 256 + b1).try_into().unwrap(), q32, ref coeffs);
}

#[cfg(test)]
mod tests {
    use super::{TWO_POW_160, hash_to_point_shake_512};

    const MSG: felt252 = 'BENCH_MSG';

    #[test]
    fn test_hash_to_point_shake_domain_separation() {
        // Different message, salt halves, or salt order all change the point.
        let base = hash_to_point_shake_512(MSG, 1, 2).unwrap();
        let other_msg = hash_to_point_shake_512('OTHER_MSG', 1, 2).unwrap();
        let other_salt = hash_to_point_shake_512(MSG, 2, 1).unwrap();
        assert_eq!(base.len(), 512);
        assert_ne!(base.span(), other_msg.span());
        assert_ne!(base.span(), other_salt.span());
    }

    #[test]
    fn test_hash_to_point_shake_rejects_oversized_salt() {
        let too_big: felt252 = TWO_POW_160.try_into().unwrap();
        assert!(hash_to_point_shake_512(MSG, too_big, 0).is_none());
        assert!(hash_to_point_shake_512(MSG, 0, too_big).is_none());
        // 2^160 - 1 is the largest valid salt half.
        assert!(hash_to_point_shake_512(MSG, too_big - 1, too_big - 1).is_some());
    }
}
