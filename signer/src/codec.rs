//! PQClean's Falcon-512 byte encodings, decoded with the same canonicality rules as
//! PQClean's `modq_decode` and `comp_decode`.

use crate::{Error, N, Q};

const PUBLIC_KEY_HEADER: u8 = 9;
const PUBLIC_KEY_BYTES: usize = 1 + N * 14 / 8;

/// Decodes a public key: header `0x09`, then 512 coefficients of 14 bits, big-endian, each
/// below q.
pub(crate) fn decode_public_key(bytes: &[u8]) -> Result<Vec<u16>, Error> {
    if bytes.len() != PUBLIC_KEY_BYTES {
        return Err(Error::InvalidPublicKey("wrong length"));
    }
    if bytes[0] != PUBLIC_KEY_HEADER {
        return Err(Error::InvalidPublicKey("header is not Falcon-512"));
    }
    let mut out = Vec::with_capacity(N);
    let (mut acc, mut acc_len) = (0u32, 0u32);
    for &b in &bytes[1..] {
        acc = (acc << 8) | b as u32;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= Q {
                return Err(Error::InvalidPublicKey("coefficient not below q"));
            }
            out.push(w as u16);
        }
    }
    debug_assert_eq!((out.len(), acc_len), (N, 0));
    Ok(out)
}

/// Decodes the compressed signature value: per coefficient a sign bit, the low 7 bits of
/// the magnitude, then the high bits in unary. Rejects "-0", magnitudes above 2047,
/// non-zero padding bits, and trailing bytes.
pub(crate) fn decompress(bytes: &[u8]) -> Result<Vec<i32>, Error> {
    let mut out = Vec::with_capacity(N);
    let (mut acc, mut acc_len, mut v) = (0u32, 0u32, 0usize);
    let next = |v: &mut usize| -> Result<u32, Error> {
        let b = *bytes.get(*v).ok_or(Error::InvalidSignature("truncated"))?;
        *v += 1;
        Ok(b as u32)
    };
    for _ in 0..N {
        acc = (acc << 8) | next(&mut v)?;
        let b = acc >> acc_len;
        let negative = b & 128 != 0;
        let mut m = b & 127;
        loop {
            if acc_len == 0 {
                acc = (acc << 8) | next(&mut v)?;
                acc_len = 8;
            }
            acc_len -= 1;
            if (acc >> acc_len) & 1 != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return Err(Error::InvalidSignature("coefficient too large"));
            }
        }
        if negative && m == 0 {
            return Err(Error::InvalidSignature("negative zero"));
        }
        out.push(if negative { -(m as i32) } else { m as i32 });
    }
    if acc & ((1u32 << acc_len) - 1) != 0 {
        return Err(Error::InvalidSignature("non-zero padding bits"));
    }
    if v != bytes.len() {
        return Err(Error::InvalidSignature("trailing bytes"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit string PQClean's `comp_encode` writes, before padding.
    fn compress_bits(x: &[i32]) -> Vec<u8> {
        let mut bits: Vec<u8> = Vec::new();
        for &v in x {
            let m = v.unsigned_abs();
            bits.push((v < 0) as u8);
            for k in (0..7).rev() {
                bits.push(((m >> k) & 1) as u8);
            }
            bits.extend(std::iter::repeat_n(0, (m >> 7) as usize));
            bits.push(1);
        }
        bits
    }

    fn to_bytes(mut bits: Vec<u8>) -> Vec<u8> {
        while !bits.len().is_multiple_of(8) {
            bits.push(0);
        }
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b))
            .collect()
    }

    fn compress(x: &[i32]) -> Vec<u8> {
        to_bytes(compress_bits(x))
    }

    fn sample() -> Vec<i32> {
        (0..N as i32).map(|i| ((i * 37) % 401) - 200).collect()
    }

    #[test]
    fn decompress_round_trips_and_rejects_non_canonical_input() {
        let x = sample();
        let enc = compress(&x);
        assert_eq!(decompress(&enc).unwrap(), x);

        let mut trailing = enc.clone();
        trailing.push(0);
        assert_eq!(
            decompress(&trailing),
            Err(Error::InvalidSignature("trailing bytes"))
        );
        assert_eq!(
            decompress(&enc[..enc.len() - 1]),
            Err(Error::InvalidSignature("truncated"))
        );

        let mut negative_zero = x.clone();
        negative_zero[0] = 0;
        let mut enc0 = compress(&negative_zero);
        enc0[0] |= 0x80;
        assert_eq!(
            decompress(&enc0),
            Err(Error::InvalidSignature("negative zero"))
        );

        let mut big = x.clone();
        big[3] = 2048;
        assert_eq!(
            decompress(&compress(&big)),
            Err(Error::InvalidSignature("coefficient too large"))
        );
    }

    #[test]
    fn decompress_rejects_padding_bits() {
        let mut x = sample();
        while compress_bits(&x).len().is_multiple_of(8) {
            x[0] += 1;
        }
        let mut bad = compress(&x);
        *bad.last_mut().unwrap() |= 1;
        assert_eq!(
            decompress(&bad),
            Err(Error::InvalidSignature("non-zero padding bits"))
        );
    }

    #[test]
    fn public_key_decoding_checks_header_length_and_range() {
        let mut bytes = vec![PUBLIC_KEY_HEADER];
        let (mut acc, mut acc_len) = (0u64, 0u32);
        for i in 0..N as u64 {
            acc = (acc << 14) | (i * 23 % Q as u64);
            acc_len += 14;
            while acc_len >= 8 {
                acc_len -= 8;
                bytes.push((acc >> acc_len) as u8);
            }
        }
        let decoded = decode_public_key(&bytes).unwrap();
        assert!(decoded
            .iter()
            .enumerate()
            .all(|(i, &v)| v as u64 == i as u64 * 23 % Q as u64));

        let mut header = bytes.clone();
        header[0] = 0x0a;
        assert!(decode_public_key(&header).is_err());
        assert!(decode_public_key(&bytes[..bytes.len() - 1]).is_err());
        let mut out_of_range = bytes.clone();
        out_of_range[1] = 0xFF;
        out_of_range[2] = 0xFF;
        assert_eq!(
            decode_public_key(&out_of_range),
            Err(Error::InvalidPublicKey("coefficient not below q"))
        );
    }
}
