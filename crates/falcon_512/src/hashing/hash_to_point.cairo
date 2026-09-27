//! Falcon-512 hash-to-point with the SHAKE-256 construction of the Falcon round-3
//! specification: absorb `salt || message_hash` with SHAKE-256, then read the squeezed
//! stream as big-endian 16-bit words, accepting `word % Q` while `word < 5Q`, until 512
//! coefficients are collected. Signatures from round-3 Falcon signers (falcon.py,
//! PQClean, liboqs) are therefore accepted; FN-DSA (the FIPS 206 draft) frames the
//! message differently and is not.
//!
//! The message hash is absorbed as its 32 little-endian bytes and the 40-byte salt as two
//! felts of 20 little-endian bytes each.

use corelib_imports::bounded_int::bounded_int::{add, mul};
use corelib_imports::bounded_int::{
    AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, bounded_int_div_rem, downcast, upcast,
};
use super::shake256::keccak_f1600;

/// A squeezed rate lane: 64 bits.
type Lane = BoundedInt<0, 18446744073709551615>;
/// Quotients left after peeling one and two 16-bit chunks off a lane.
type Lane48 = BoundedInt<0, 281474976710655>;
type Lane32 = BoundedInt<0, 4294967295>;
/// A 16-bit chunk of a lane, or a 16-bit stream word.
type Word16 = BoundedInt<0, 65535>;
type Byte = BoundedInt<0, 255>;
/// A byte shifted into the high half of a 16-bit word.
type HighByte = BoundedInt<0, 65280>;
/// Stream words the rejection rule accepts: below 5q, the largest multiple of q under 2^16.
type AcceptedWord = BoundedInt<0, 61444>;
type Base16 = UnitInt<65536>;
type Base8 = UnitInt<256>;
type FalconQ = UnitInt<12289>;
type FalconZq = BoundedInt<0, 12288>;

const BASE16_NZ: NonZero<Base16> = 65536;
const BASE8_NZ: NonZero<Base8> = 256;
const BASE8: Base8 = 256;
const FALCON_Q_NZ: NonZero<FalconQ> = 12289;

impl LaneDivRemImpl of DivRemHelper<Lane, Base16> {
    type DivT = Lane48;
    type RemT = Word16;
}

impl Lane48DivRemImpl of DivRemHelper<Lane48, Base16> {
    type DivT = Lane32;
    type RemT = Word16;
}

impl Lane32DivRemImpl of DivRemHelper<Lane32, Base16> {
    type DivT = Word16;
    type RemT = Word16;
}

impl Word16DivRemImpl of DivRemHelper<Word16, Base8> {
    type DivT = Byte;
    type RemT = Byte;
}

impl ByteShiftImpl of MulHelper<Byte, Base8> {
    type Result = HighByte;
}

impl HighByteAddImpl of AddHelper<HighByte, Byte> {
    type Result = Word16;
}

impl AcceptedWordDivRemImpl of DivRemHelper<AcceptedWord, FalconQ> {
    type DivT = BoundedInt<0, 4>;
    type RemT = FalconZq;
}

/// Each salt felt must fit in 20 bytes.
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000_u256;

/// ## Construction
///
/// The Falcon round-3 construction: absorb `salt || message_hash` with SHAKE-256,
/// then consume the squeezed stream as big-endian 16-bit words, applying the rejection
/// rule (accept `word % Q` while `word < 5Q`) until 512 coefficients are collected,
/// matching round-3 Falcon signers (falcon.py, PQClean, liboqs). The message hash is
/// absorbed as its 32 little-endian bytes, the salt as its two 20-byte little-endian
/// halves.
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

    let mut coeffs: Array<u16> = array![];
    loop {
        let mut lanes = state.span().slice(0, 17);
        while let Some(lane) = lanes.pop_front() {
            push_lane_words(*lane, ref coeffs);
            if coeffs.len() == 512 {
                break;
            }
        }
        if coeffs.len() == 512 {
            break;
        }
        state = keccak_f1600(state);
    }
    Some(coeffs)
}

/// Read one squeezed rate lane as four big-endian 16-bit stream words and apply the
/// rejection rule to each. The lane's bytes are little-endian, so each 16-bit chunk
/// holds its stream word byte-swapped: chunk = b0 + 256*b1 for the stream word
/// 256*b0 + b1. Keccak lanes are below 2^64 by construction (see `shake256.cairo`).
#[inline(always)]
fn push_lane_words(lane: u128, ref coeffs: Array<u16>) {
    let lane: Lane = match downcast(lane) {
        Some(lane) => lane,
        None => panic!("Keccak lane exceeds 64 bits"),
    };
    let (rest, c0) = bounded_int_div_rem(lane, BASE16_NZ);
    let (rest, c1) = bounded_int_div_rem(rest, BASE16_NZ);
    let (c3, c2) = bounded_int_div_rem(rest, BASE16_NZ);
    push_word(c0, ref coeffs);
    push_word(c1, ref coeffs);
    push_word(c2, ref coeffs);
    push_word(c3, ref coeffs);
}

/// Byte-swap one lane chunk into its stream word and, while fewer than 512 coefficients
/// are collected, accept `word % Q` when `word < 5Q`.
#[inline(always)]
fn push_word(chunk: Word16, ref coeffs: Array<u16>) {
    if coeffs.len() == 512 {
        return;
    }
    let (b1, b0) = bounded_int_div_rem(chunk, BASE8_NZ);
    let word: Word16 = add(mul(b0, BASE8), b1);
    if let Some(accepted) = downcast::<Word16, AcceptedWord>(word) {
        let (_, r) = bounded_int_div_rem(accepted, FALCON_Q_NZ);
        coeffs.append(upcast(r));
    }
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
