//! Falcon-512 signer for the falcon-shake-starknet accounts.
//!
//! Keys and signatures come from PQClean's Falcon-512 (through `pqcrypto-falcon`). Its
//! hash-to-point is SHAKE-256 over `nonce || message`, as in the Falcon round-3
//! specification, which is the construction the on-chain verifier implements. This crate
//! converts PQClean's byte encodings into the accounts' felt layout:
//!
//! - public key: 29 felts, the NTT-domain `h` packed base q, 18 coefficients per felt;
//! - signature: packed `s1` (29 felts), the 40-byte salt as two felts of 20 little-endian
//!   bytes, and packed `s1 * h` (29 felts). The first 31 felts are the direct account's
//!   layout.
//!
//! The signed message is the transaction hash as 32 little-endian bytes. Before a signature
//! is returned it is checked twice: by PQClean's verifier, and against the exact equations
//! the contract evaluates.

mod codec;
mod ntt_points;

use std::fmt;

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const Q: u32 = 12289;
pub const N: usize = 512;
/// Falcon-512 bound on `||s0||^2 + ||s1||^2`.
pub const SIG_BOUND: u64 = 34_034_726;
pub const PUBLIC_KEY_FELTS: usize = 29;
pub const SIGNATURE_FELTS: usize = 60;
pub const DIRECT_SIGNATURE_FELTS: usize = 31;

const NONCE_LEN: usize = 40;
const SIGNATURE_HEADER: u8 = 0x30 + 9;
const SHAKE_RATE: usize = 136;
const ACCEPT_BELOW: u32 = 5 * Q;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidHex(String),
    NotAFelt(String),
    InvalidPublicKey(&'static str),
    InvalidSecretKey,
    InvalidSignature(&'static str),
    Rejected(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidHex(s) => write!(f, "invalid hex: {s}"),
            Error::NotAFelt(s) => write!(f, "not a field element: {s}"),
            Error::InvalidPublicKey(why) => write!(f, "invalid public key: {why}"),
            Error::InvalidSecretKey => write!(f, "invalid secret key"),
            Error::InvalidSignature(why) => write!(f, "invalid signature encoding: {why}"),
            Error::Rejected(why) => write!(f, "signature failed a check: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A Starknet field element, `hi * 2^128 + lo`, below the STARK prime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Felt {
    hi: u128,
    lo: u128,
}

/// The STARK prime `2^251 + 17 * 2^192 + 1`, as limbs.
const PRIME_HI: u128 = (1 << 123) + (17 << 64);
const PRIME_LO: u128 = 1;

impl Felt {
    pub const fn from_u128(lo: u128) -> Self {
        Felt { hi: 0, lo }
    }

    /// Parses `0x`-prefixed or bare hex, rejecting values at or above the STARK prime.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let digits = s.strip_prefix("0x").unwrap_or(s);
        if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::InvalidHex(s.to_string()));
        }
        let (hi, lo) = digits.split_at(digits.len().saturating_sub(32));
        let parse = |h: &str| {
            if h.is_empty() {
                Ok(0)
            } else {
                u128::from_str_radix(h, 16)
            }
        };
        let felt = Felt {
            hi: parse(hi).map_err(|_| Error::InvalidHex(s.to_string()))?,
            lo: parse(lo).map_err(|_| Error::InvalidHex(s.to_string()))?,
        };
        if (felt.hi, felt.lo) >= (PRIME_HI, PRIME_LO) {
            return Err(Error::NotAFelt(s.to_string()));
        }
        Ok(felt)
    }

    pub fn to_hex(&self) -> String {
        if self.hi == 0 {
            format!("{:#x}", self.lo)
        } else {
            format!("{:#x}{:032x}", self.hi, self.lo)
        }
    }

    /// The 32 little-endian bytes the contract absorbs for a message hash.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.lo.to_le_bytes());
        out[16..].copy_from_slice(&self.hi.to_le_bytes());
        out
    }

    /// A felt from 20 little-endian bytes (one salt half).
    fn from_le_bytes_20(bytes: &[u8]) -> Self {
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&bytes[..16]);
        hi[..4].copy_from_slice(&bytes[16..20]);
        Felt {
            hi: u128::from_le_bytes(hi),
            lo: u128::from_le_bytes(lo),
        }
    }
}

impl fmt::Display for Felt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A Falcon-512 keypair in PQClean's encodings.
pub struct Keypair {
    public: falcon512::PublicKey,
    secret: falcon512::SecretKey,
}

/// A signature in the accounts' felt layout.
#[derive(Clone, Debug)]
pub struct Signature {
    felts: Vec<Felt>,
    /// SHAKE-256 output blocks (Keccak permutations) the on-chain hash-to-point consumes.
    pub blocks: usize,
}

impl Signature {
    /// The 60-felt layout of the hint account.
    pub fn hint(&self) -> &[Felt] {
        &self.felts
    }

    /// The 31-felt layout of the direct account: `s1 || salt`.
    pub fn direct(&self) -> &[Felt] {
        &self.felts[..DIRECT_SIGNATURE_FELTS]
    }
}

impl Keypair {
    pub fn generate() -> Self {
        let (public, secret) = falcon512::keypair();
        Keypair { public, secret }
    }

    pub fn from_bytes(public: &[u8], secret: &[u8]) -> Result<Self, Error> {
        codec::decode_public_key(public)?;
        Ok(Keypair {
            public: falcon512::PublicKey::from_bytes(public)
                .map_err(|_| Error::InvalidPublicKey("wrong length"))?,
            secret: falcon512::SecretKey::from_bytes(secret)
                .map_err(|_| Error::InvalidSecretKey)?,
        })
    }

    pub fn public_bytes(&self) -> &[u8] {
        self.public.as_bytes()
    }

    pub fn secret_bytes(&self) -> &[u8] {
        self.secret.as_bytes()
    }

    /// The account constructor's public key: NTT-domain `h`, packed into 29 felts.
    pub fn public_key_felts(&self) -> Result<Vec<Felt>, Error> {
        let h = codec::decode_public_key(self.public.as_bytes())?;
        Ok(pack_512(&ntt(&h)))
    }

    /// Signs a transaction hash and returns the signature in the accounts' layout.
    pub fn sign(&self, tx_hash: Felt) -> Result<Signature, Error> {
        let message = tx_hash.to_le_bytes();
        let detached = falcon512::detached_sign(&message, &self.secret);
        falcon512::verify_detached_signature(&detached, &message, &self.public)
            .map_err(|_| Error::Rejected("PQClean verification"))?;
        let h = codec::decode_public_key(self.public.as_bytes())?;
        to_account_layout(detached.as_bytes(), &message, &h)
    }
}

/// Converts a PQClean detached signature into the accounts' layout, re-checking the exact
/// equations the contract evaluates.
fn to_account_layout(bytes: &[u8], message: &[u8; 32], h: &[u16]) -> Result<Signature, Error> {
    if bytes.len() <= 1 + NONCE_LEN {
        return Err(Error::InvalidSignature("too short"));
    }
    if bytes[0] != SIGNATURE_HEADER {
        return Err(Error::InvalidSignature(
            "header is not Falcon-512 compressed",
        ));
    }
    let nonce = &bytes[1..1 + NONCE_LEN];
    let s1: Vec<u16> = codec::decompress(&bytes[1 + NONCE_LEN..])?
        .iter()
        .map(|&v| v.rem_euclid(Q as i32) as u16)
        .collect();
    let hint = negacyclic_mul(&s1, h);
    let (point, blocks) = hash_to_point(nonce, message);

    // The hint check, in the NTT domain as the hint account evaluates it.
    let (s1_ntt, h_ntt, hint_ntt) = (ntt(&s1), ntt(h), ntt(&hint));
    if (0..N).any(|i| (s1_ntt[i] as u32 * h_ntt[i] as u32) % Q != hint_ntt[i] as u32) {
        return Err(Error::Rejected("hint is not s1 * h"));
    }
    // The norm check over (point - s1 * h, s1).
    let norm: u64 = (0..N)
        .map(|i| {
            centered_sq((point[i] as u32 + Q - hint[i] as u32) % Q) + centered_sq(s1[i] as u32)
        })
        .sum();
    if norm > SIG_BOUND {
        return Err(Error::Rejected("norm above the Falcon-512 bound"));
    }

    let mut felts = pack_512(&s1);
    felts.push(Felt::from_le_bytes_20(&nonce[..20]));
    felts.push(Felt::from_le_bytes_20(&nonce[20..]));
    felts.extend(pack_512(&hint));
    debug_assert_eq!(felts.len(), SIGNATURE_FELTS);
    Ok(Signature { felts, blocks })
}

fn centered_sq(x: u32) -> u64 {
    let c = if x > (Q - 1) / 2 { Q - x } else { x } as u64;
    c * c
}

/// Falcon round-3 hash-to-point: SHAKE-256 over `nonce || message`, read as big-endian
/// 16-bit words, keeping `word mod q` for words below `5q`. Also returns the number of
/// 136-byte output blocks consumed.
pub fn hash_to_point(nonce: &[u8], message: &[u8]) -> (Vec<u16>, usize) {
    let mut shake = Shake256::default();
    shake.update(nonce);
    shake.update(message);
    let mut reader = shake.finalize_xof();
    let mut out = Vec::with_capacity(N);
    let mut read = 0usize;
    let mut word = [0u8; 2];
    while out.len() < N {
        reader.read(&mut word);
        read += 2;
        let w = u16::from_be_bytes(word) as u32;
        if w < ACCEPT_BELOW {
            out.push((w % Q) as u16);
        }
    }
    (out, read.div_ceil(SHAKE_RATE))
}

/// The on-chain forward NTT: `NTT(f)[i] = f(POINTS[i]) mod q`.
fn ntt(f: &[u16]) -> Vec<u16> {
    ntt_points::POINTS
        .iter()
        .map(|&r| {
            f.iter()
                .rev()
                .fold(0u32, |acc, &c| (acc * r as u32 + c as u32) % Q) as u16
        })
        .collect()
}

/// Schoolbook product in `Z_q[x] / (x^512 + 1)`.
fn negacyclic_mul(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut acc = vec![0i64; N];
    for (i, &x) in a.iter().enumerate().filter(|(_, &x)| x != 0) {
        for (j, &y) in b.iter().enumerate() {
            let p = x as i64 * y as i64;
            if i + j < N {
                acc[i + j] += p;
            } else {
                acc[i + j - N] -= p;
            }
        }
    }
    acc.iter().map(|&v| v.rem_euclid(Q as i64) as u16).collect()
}

/// The base-q packing the contract unpacks: each of the first 28 felts holds coefficients
/// `18j..18j+9` in its low 128 bits and `18j+9..18j+18` above them; the last holds 8.
pub fn pack_512(values: &[u16]) -> Vec<Felt> {
    assert_eq!(values.len(), N);
    let pack = |chunk: &[u16]| {
        chunk
            .iter()
            .rev()
            .fold(0u128, |acc, &c| acc * Q as u128 + c as u128)
    };
    let mut out: Vec<Felt> = (0..28)
        .map(|j| Felt {
            hi: pack(&values[18 * j + 9..18 * j + 18]),
            lo: pack(&values[18 * j..18 * j + 9]),
        })
        .collect();
    out.push(Felt::from_u128(pack(&values[504..])));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unpack_512(felts: &[Felt]) -> Vec<u16> {
        let mut out = Vec::new();
        let mut take = |mut v: u128, count: usize| {
            for _ in 0..count {
                out.push((v % Q as u128) as u16);
                v /= Q as u128;
            }
            assert_eq!(v, 0, "non-canonical half");
        };
        for f in &felts[..28] {
            take(f.lo, 9);
            take(f.hi, 9);
        }
        take(felts[28].lo, 8);
        out
    }

    fn pseudo_random(seed: u64) -> Vec<u16> {
        let mut x = seed;
        (0..N)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((x >> 33) % Q as u64) as u16
            })
            .collect()
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn felt_hex_round_trip_and_prime_bound() {
        for s in [
            "0x0",
            "0x1",
            "0x42454e43485f4d5347",
            "0x800000000000011000000000000000000000000000000000000000000000000",
        ] {
            assert_eq!(Felt::from_hex(s).unwrap().to_hex(), s);
        }
        assert!(matches!(
            Felt::from_hex("0x800000000000011000000000000000000000000000000000000000000000001"),
            Err(Error::NotAFelt(_))
        ));
        assert!(Felt::from_hex("0x").is_err());
        assert!(Felt::from_hex("0xzz").is_err());
        assert_eq!(
            &Felt::from_hex("0x0102").unwrap().to_le_bytes()[..3],
            &[2, 1, 0]
        );
    }

    #[test]
    fn pack_round_trips() {
        for seed in 0..4 {
            let v = pseudo_random(seed);
            assert_eq!(unpack_512(&pack_512(&v)), v);
        }
        assert_eq!(
            unpack_512(&pack_512(&[Q as u16 - 1; N])),
            vec![Q as u16 - 1; N]
        );
    }

    #[test]
    fn ntt_is_negacyclic_and_matches_the_points() {
        let mut x = vec![0u16; N];
        x[1] = 1;
        assert_eq!(ntt(&x), ntt_points::POINTS.to_vec());
        let (a, b) = (pseudo_random(1), pseudo_random(2));
        let (na, nb, nab) = (ntt(&a), ntt(&b), ntt(&negacyclic_mul(&a, &b)));
        assert!((0..N).all(|i| (na[i] as u32 * nb[i] as u32) % Q == nab[i] as u32));
    }

    #[test]
    fn hash_to_point_matches_the_contract_fixture() {
        // The committed contract fixture ('BENCH_MSG' and its salt); expected values computed
        // independently with Python's hashlib, as in scripts/gen_shake_h2p_kat.py.
        let message = Felt::from_hex("0x42454e43485f4d5347")
            .unwrap()
            .to_le_bytes();
        let nonce = hex_bytes(
            "4ad23197d576f705594ac172f4fca80e3338e991b8b55e269d421aa1522cd0aa2490034127651fc2",
        );
        let (point, blocks) = hash_to_point(&nonce, &message);
        assert_eq!(
            &point[..16],
            &[
                9572, 2876, 6432, 6327, 8446, 10849, 3417, 7279, 8664, 11484, 1140, 10213, 9646,
                719, 9261, 12120
            ]
        );
        assert_eq!(&point[N - 4..], &[8441, 7161, 8294, 3571]);
        assert_eq!(point.iter().map(|&v| v as u64).sum::<u64>(), 3_036_307);
        assert_eq!(blocks, 9);
    }

    #[test]
    fn signs_in_the_account_layout() {
        let key = Keypair::generate();
        let pk = key.public_key_felts().unwrap();
        assert_eq!(pk.len(), PUBLIC_KEY_FELTS);
        let h = codec::decode_public_key(key.public_bytes()).unwrap();
        assert_eq!(unpack_512(&pk), ntt(&h));
        for i in 0..4u128 {
            let sig = key.sign(Felt::from_u128(0x5eed_0000 + i)).unwrap();
            assert_eq!(sig.hint().len(), SIGNATURE_FELTS);
            assert_eq!(sig.direct(), &sig.hint()[..DIRECT_SIGNATURE_FELTS]);
            assert!(sig.blocks == 8 || sig.blocks == 9);
            let s1 = unpack_512(&sig.hint()[..29]);
            assert_eq!(unpack_512(&sig.hint()[31..]), negacyclic_mul(&s1, &h));
            // Each salt felt holds at most 20 bytes, as the contract requires.
            assert!(sig.hint()[29..31].iter().all(|salt| salt.hi < 1 << 32));
        }
    }

    #[test]
    fn layout_conversion_rejects_tampering() {
        let key = Keypair::generate();
        let message = Felt::from_u128(7).to_le_bytes();
        let good = falcon512::detached_sign(&message, &key.secret)
            .as_bytes()
            .to_vec();
        let h = codec::decode_public_key(key.public_bytes()).unwrap();
        assert!(to_account_layout(&good, &message, &h).is_ok());

        let other = Felt::from_u128(8).to_le_bytes();
        assert_eq!(
            to_account_layout(&good, &other, &h).unwrap_err(),
            Error::Rejected("norm above the Falcon-512 bound")
        );
        let mut header = good.clone();
        header[0] = 0x29;
        assert!(matches!(
            to_account_layout(&header, &message, &h),
            Err(Error::InvalidSignature(_))
        ));
        let mut longer = good.clone();
        longer.push(0);
        assert!(matches!(
            to_account_layout(&longer, &message, &h),
            Err(Error::InvalidSignature(_))
        ));
    }
}
