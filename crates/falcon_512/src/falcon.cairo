//! Falcon-512 signature verification.
//!
//! Hint variant: verifies `s1 * h == mul_hint` via two forward NTTs and a pointwise
//! product check (the NTT is a bijection, so the check binds `mul_hint` to exactly
//! `s1 * h mod (q, phi)`), then accepts iff
//! `||msg_point - mul_hint||^2 + ||s1||^2 <= SIG_BOUND_512` over centered
//! representatives. Since `msg_point - s1*h = s0`, this is the Falcon verification
//! equation with the polynomial multiplication delegated to a signer-supplied hint;
//! a bad hint yields `false`. Both transforms use the generated fixed-parameter
//! Falcon-512 path, and the pointwise check tests `s1n*h == hn (mod q)`.
//!
//! Direct variant: computes `s1 * h` on-chain as `INTT(NTT(s1) ∘ h_ntt)`. Both the
//! forward transform and the inverse run on the generated fixed-parameter Falcon-512
//! graph: the inverse gathers the pointwise products into natural root order with a twist,
//! transforms them forward, and untwists the result (`pqbench_ntt::falcon512_inverse`).
//!
//! The verifier path decodes packed coefficients into canonical `u16` values and keeps
//! that representation through the generated NTT and norm calculation. The public core
//! functions also accept validated felt coefficients for standalone callers.

use pqbench_ntt::{intt_product_falcon512_fast_u16, ntt_falcon512_fast_u16_unchecked};
use crate::zq::{Q, center_sq, centered_difference_sq, mul_mod};

/// Maximum allowed `||s0||^2 + ||s1||^2` for Falcon-512 (the specification's and falcon.py's
/// sig_bound).
pub const SIG_BOUND_512: u64 = 34034726;


#[inline(always)]
/// The 512 coefficients as canonical `u16` values, or `None` unless there are exactly 512
/// and every one lies in `[0, Q)`.
fn canonical_coefficients(mut values: Span<felt252>) -> Option<Array<u16>> {
    if values.len() != 512 {
        return None;
    }
    let mut out: Array<u16> = array![];
    while let Some(value) = values.pop_front() {
        let coefficient: u16 = (*value).try_into()?;
        if coefficient >= Q {
            return None;
        }
        out.append(coefficient);
    }
    Some(out)
}

/// Whether `values` holds exactly 512 coefficients, each in `[0, Q)`.
fn is_canonical_point(mut values: Span<u16>) -> bool {
    if values.len() != 512 {
        return false;
    }
    while let Some(value) = values.pop_front() {
        if *value >= Q {
            return false;
        }
    }
    true
}


/// Verify with a signer-supplied product hint, from unpacked coefficients.
///
/// Every input must hold exactly 512 coefficients in `[0, Q)`; any other input returns
/// `false`. Returns `true` iff `mul_hint` equals `s1 * h` and the centered norm of
/// `(msg_point - mul_hint, s1)` is within the Falcon-512 bound.
pub fn verify_512_with_hint(
    s1: Span<felt252>, h_ntt: Span<felt252>, mul_hint: Span<felt252>, msg_point: Span<u16>,
) -> bool {
    let Some(s1) = canonical_coefficients(s1) else {
        return false;
    };
    let Some(h_ntt) = canonical_coefficients(h_ntt) else {
        return false;
    };
    let Some(mul_hint) = canonical_coefficients(mul_hint) else {
        return false;
    };
    if !is_canonical_point(msg_point) {
        return false;
    }
    verify_512_with_hint_u16(s1.span(), h_ntt.span(), mul_hint.span(), msg_point)
}

/// Verify the hint equation over canonical `u16` coefficients.
pub(crate) fn verify_512_with_hint_u16(
    s1: Span<u16>, h_ntt: Span<u16>, mul_hint: Span<u16>, msg_point: Span<u16>,
) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(mul_hint.len() == 512, 'mul_hint must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    // Both spans came from canonical base-Q unpacking (or the public wrapper's documented
    // canonical-coefficient precondition), so the generated unchecked NTT is sound here.
    let s1_ntt = ntt_falcon512_fast_u16_unchecked(s1);
    let hint_ntt = ntt_falcon512_fast_u16_unchecked(mul_hint);

    let mut s1_ntt_iter = s1_ntt.span();
    let mut hint_ntt_iter = hint_ntt.span();
    let mut h_iter = h_ntt;
    let mut msg_iter = msg_point;
    let mut hint_iter = mul_hint;
    let mut s1_iter = s1;

    // Fused pass, 16-way unrolled (512 = 16 * 32, no remainder): hint check and
    // centered-norm accumulation per coefficient.
    // Max acc = 512 * 2 * 6144^2 < 2^36, so the felt252 accumulator cannot wrap
    // and always fits u64.
    let mut acc: felt252 = 0;
    let mut ok = true;
    while let Some(s1n_c) = s1_ntt_iter.multi_pop_front::<16>() {
        let [
            s1n0,
            s1n1,
            s1n2,
            s1n3,
            s1n4,
            s1n5,
            s1n6,
            s1n7,
            s1n8,
            s1n9,
            s1n10,
            s1n11,
            s1n12,
            s1n13,
            s1n14,
            s1n15,
        ] =
            (*s1n_c)
            .unbox();
        let [hn0, hn1, hn2, hn3, hn4, hn5, hn6, hn7, hn8, hn9, hn10, hn11, hn12, hn13, hn14, hn15] =
            (*hint_ntt_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15] = (*h_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        // mul_mod reduces s1n*h exactly and hn is canonical, so each comparison holds iff
        // the two NTT coordinates agree mod q, which by bijectivity binds mul_hint to s1*h.
        if mul_mod(s1n0, h0) != hn0
            || mul_mod(s1n1, h1) != hn1
            || mul_mod(s1n2, h2) != hn2
            || mul_mod(s1n3, h3) != hn3
            || mul_mod(s1n4, h4) != hn4
            || mul_mod(s1n5, h5) != hn5
            || mul_mod(s1n6, h6) != hn6
            || mul_mod(s1n7, h7) != hn7
            || mul_mod(s1n8, h8) != hn8
            || mul_mod(s1n9, h9) != hn9
            || mul_mod(s1n10, h10) != hn10
            || mul_mod(s1n11, h11) != hn11
            || mul_mod(s1n12, h12) != hn12
            || mul_mod(s1n13, h13) != hn13
            || mul_mod(s1n14, h14) != hn14
            || mul_mod(s1n15, h15) != hn15 {
            ok = false;
            break;
        }
        let [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] = (*msg_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15] = (*hint_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15] = (*s1_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        acc += centered_difference_sq(m0, t0) + center_sq(v0);
        acc += centered_difference_sq(m1, t1) + center_sq(v1);
        acc += centered_difference_sq(m2, t2) + center_sq(v2);
        acc += centered_difference_sq(m3, t3) + center_sq(v3);
        acc += centered_difference_sq(m4, t4) + center_sq(v4);
        acc += centered_difference_sq(m5, t5) + center_sq(v5);
        acc += centered_difference_sq(m6, t6) + center_sq(v6);
        acc += centered_difference_sq(m7, t7) + center_sq(v7);
        acc += centered_difference_sq(m8, t8) + center_sq(v8);
        acc += centered_difference_sq(m9, t9) + center_sq(v9);
        acc += centered_difference_sq(m10, t10) + center_sq(v10);
        acc += centered_difference_sq(m11, t11) + center_sq(v11);
        acc += centered_difference_sq(m12, t12) + center_sq(v12);
        acc += centered_difference_sq(m13, t13) + center_sq(v13);
        acc += centered_difference_sq(m14, t14) + center_sq(v14);
        acc += centered_difference_sq(m15, t15) + center_sq(v15);
    }
    if !ok {
        return false;
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

/// Verify without a hint (direct variant): compute `s1 * h` on-chain as
/// `INTT(NTT(s1) ∘ h_ntt)` — one forward transform of `s1` and one inverse, because the
/// public key is already stored in the NTT domain — then accept iff
/// `||msg_point - s1*h||^2 + ||s1||^2 <= SIG_BOUND_512`. Same trust surface as the
/// textbook equation (no signer-supplied hint) and 29 fewer signature felts than
/// [`verify_512_with_hint`]. Every input must hold exactly 512 coefficients in `[0, Q)`;
/// any other input returns `false`.
pub fn verify_512_direct(s1: Span<felt252>, h_ntt: Span<felt252>, msg_point: Span<u16>) -> bool {
    let Some(s1) = canonical_coefficients(s1) else {
        return false;
    };
    let Some(h_ntt) = canonical_coefficients(h_ntt) else {
        return false;
    };
    if !is_canonical_point(msg_point) {
        return false;
    }
    verify_512_direct_u16(s1.span(), h_ntt.span(), msg_point)
}

/// Verify the direct equation over canonical `u16` coefficients.
pub(crate) fn verify_512_direct_u16(s1: Span<u16>, h_ntt: Span<u16>, msg_point: Span<u16>) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    // `s1` is canonical by the same verifier/wrapper precondition as the hint path.
    let s1_ntt = ntt_falcon512_fast_u16_unchecked(s1);
    // s1 * h mod (q, x^512 + 1), natural order, every coefficient in [0, q).
    let s1h = intt_product_falcon512_fast_u16(s1_ntt.span(), h_ntt);

    let mut s1h_iter = s1h.span();
    let mut msg_iter = msg_point;
    let mut s1_iter = s1;
    // Norm pass, 16-way unrolled (512 = 16 * 32, no remainder).
    // Same accumulator bound argument as in `verify_512_with_hint`.
    let mut acc: felt252 = 0;
    while let Some(pc) = s1h_iter.multi_pop_front::<16>() {
        let [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15] = (*pc).unbox();
        let [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] = (*msg_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15] = (*s1_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        acc += centered_difference_sq(m0, p0) + center_sq(v0);
        acc += centered_difference_sq(m1, p1) + center_sq(v1);
        acc += centered_difference_sq(m2, p2) + center_sq(v2);
        acc += centered_difference_sq(m3, p3) + center_sq(v3);
        acc += centered_difference_sq(m4, p4) + center_sq(v4);
        acc += centered_difference_sq(m5, p5) + center_sq(v5);
        acc += centered_difference_sq(m6, p6) + center_sq(v6);
        acc += centered_difference_sq(m7, p7) + center_sq(v7);
        acc += centered_difference_sq(m8, p8) + center_sq(v8);
        acc += centered_difference_sq(m9, p9) + center_sq(v9);
        acc += centered_difference_sq(m10, p10) + center_sq(v10);
        acc += centered_difference_sq(m11, p11) + center_sq(v11);
        acc += centered_difference_sq(m12, p12) + center_sq(v12);
        acc += centered_difference_sq(m13, p13) + center_sq(v13);
        acc += centered_difference_sq(m14, p14) + center_sq(v14);
        acc += centered_difference_sq(m15, p15) + center_sq(v15);
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

#[cfg(test)]
mod tests {
    use pqbench_ntt::engine::{intt, ntt};
    use pqbench_ntt::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
    use crate::fixtures::shake;
    use crate::hashing::hash_to_point::hash_to_point_shake_512;
    use crate::packing::unpack_512_u16;
    use crate::zq::add_mod;
    use super::{
        verify_512_direct, verify_512_direct_u16, verify_512_with_hint, verify_512_with_hint_u16,
    };

    fn to_u16(mut vals: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        while let Some(v) = vals.pop_front() {
            out.append((*v).try_into().unwrap());
        }
        out
    }

    /// Negacyclic product in Z_q[x]/(x^512 + 1) (test helper).
    fn mul_zq(f: Span<felt252>, g: Span<felt252>) -> Array<felt252> {
        let cfg = config();
        let f_ntt = ntt(f, @cfg);
        let g_ntt = ntt(g, @cfg);
        let mut prods: Array<felt252> = array![];
        let mut fi = f_ntt.span();
        let mut gi = g_ntt.span();
        while let Some(a) = fi.pop_front() {
            prods.append(*a * *gi.pop_front().unwrap());
        }
        intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg)
    }

    fn pseudorandom_coeffs(seed: u64) -> Array<felt252> {
        let mut f: Array<felt252> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            f.append((state % 12289).into());
        }
        f
    }

    fn small_coeffs(seed: u64) -> Array<felt252> {
        // Centered coefficients in [-16, 16]: comfortably inside the norm bound.
        let mut f: Array<felt252> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            let centered = state % 33;
            if centered <= 16 {
                f.append(centered.into());
            } else {
                f.append((12289 - (centered - 16)).into());
            }
        }
        f
    }

    /// msg_point = s0 + prod coefficient-wise, downcast to the norm side's u16 form.
    fn add_points(s0: Span<felt252>, prod: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        let mut s0_iter = to_u16(s0).span();
        let mut prod_iter = to_u16(prod).span();
        while let Some(a) = s0_iter.pop_front() {
            out.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        out
    }

    // Synthetic instance built from the verification equation itself: pick small s1 and
    // small s0, any h, set mul_hint = s1*h and msg_point = s0 + s1*h. A correct verifier
    // must accept it, and reject once the hint or the norm side is broken.
    #[test]
    fn test_verify_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let mul_hint = mul_zq(s1.span(), h.span());
        let msg_point = add_points(s0.span(), mul_hint.span());
        assert!(verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_bad_hint() {
        let s1 = small_coeffs(1);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let good_hint = mul_zq(s1.span(), h.span());
        // Flip one coefficient of the hint.
        let mut hint_iter = good_hint.span();
        let first: u16 = (*hint_iter.pop_front().unwrap()).try_into().unwrap();
        let mut tampered: Array<felt252> = array![((first + 1) % 12289).into()];
        while let Some(c) = hint_iter.pop_front() {
            tampered.append(*c);
        }
        // msg_point = mul_hint would give norm ||s1||^2 only — accepted if hint passed.
        let msg_point = to_u16(mul_zq(s1.span(), h.span()).span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), tampered.span(), msg_point.span()));
    }

    // The direct variant must agree with the hint variant on the same instances.
    #[test]
    fn test_verify_direct_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let prod = mul_zq(s1.span(), h.span());
        let msg_point = add_points(s0.span(), prod.span());
        assert!(verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
        // Perturb one msg_point coefficient far from the lattice point: norm blows up.
        let mut bad_msg: Array<u16> = array![add_mod(*msg_point.span().at(0), 6144)];
        let mut rest = msg_point.span().slice(1, 511);
        while let Some(c) = rest.pop_front() {
            bad_msg.append(*c);
        }
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), bad_msg.span()));
    }

    #[test]
    fn test_verify_direct_rejects_large_norm() {
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        // msg_point = s1*h so s0 = 0; ||s1||^2 alone is far above the bound.
        let msg_point = to_u16(mul_zq(s1.span(), h.span()).span());
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_large_norm() {
        // s1 uniformly random in [0, Q): astronomically above the centered-norm bound,
        // with a consistent hint and msg_point = s1*h (so s0 = 0).
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let mul_hint = mul_zq(s1.span(), h.span());
        let msg_point = to_u16(mul_hint.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }

    // --- Malformed input through the public coefficient API ---

    /// Copy of `values` with `values[index]` replaced by `value`.
    fn with_felt(mut values: Span<felt252>, index: u32, value: felt252) -> Array<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i: u32 = 0;
        while let Some(v) = values.pop_front() {
            out.append(if i == index {
                value
            } else {
                *v
            });
            i += 1;
        }
        out
    }

    #[test]
    fn test_public_api_rejects_non_canonical_coefficients() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let hint = mul_zq(s1.span(), h.span());
        let point = add_points(s0.span(), hint.span());
        assert!(verify_512_with_hint(s1.span(), h_ntt.span(), hint.span(), point.span()));
        assert!(verify_512_direct(s1.span(), h_ntt.span(), point.span()));
        // q itself, the largest u16, and a value that does not fit u16 are all rejected,
        // in every input.
        let bad_values: [felt252; 3] = [12289, 65535, 0x10000];
        for bad in bad_values.span() {
            let s1_bad = with_felt(s1.span(), 5, *bad);
            let h_bad = with_felt(h_ntt.span(), 6, *bad);
            let hint_bad = with_felt(hint.span(), 7, *bad);
            assert!(!verify_512_with_hint(s1_bad.span(), h_ntt.span(), hint.span(), point.span()));
            assert!(!verify_512_with_hint(s1.span(), h_bad.span(), hint.span(), point.span()));
            assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), hint_bad.span(), point.span()));
            assert!(!verify_512_direct(s1_bad.span(), h_ntt.span(), point.span()));
            assert!(!verify_512_direct(s1.span(), h_bad.span(), point.span()));
        }
        let mut point_bad: Array<u16> = array![12289];
        let mut rest = point.span().slice(1, 511);
        while let Some(c) = rest.pop_front() {
            point_bad.append(*c);
        }
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), hint.span(), point_bad.span()));
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), point_bad.span()));
    }

    #[test]
    fn test_public_api_rejects_wrong_lengths() {
        let s1 = small_coeffs(1);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let hint = mul_zq(s1.span(), h.span());
        let point = to_u16(hint.span());
        let short = s1.span().slice(0, 511);
        assert!(!verify_512_with_hint(short, h_ntt.span(), hint.span(), point.span()));
        assert!(
            !verify_512_with_hint(s1.span(), h_ntt.span().slice(0, 511), hint.span(), point.span()),
        );
        assert!(
            !verify_512_with_hint(s1.span(), h_ntt.span(), hint.span().slice(0, 511), point.span()),
        );
        assert!(
            !verify_512_with_hint(s1.span(), h_ntt.span(), hint.span(), point.span().slice(0, 511)),
        );
        assert!(!verify_512_direct(short, h_ntt.span(), point.span()));
        assert!(!verify_512_direct(s1.span(), h_ntt.span().slice(0, 511), point.span()));
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), point.span().slice(0, 511)));
    }

    // --- Exhaustive single-coefficient tampering of a genuine falcon.py signature ---

    /// The SHAKE-256 fixture unpacked: (s1, h_ntt, mul_hint, msg_point).
    fn fixture_instance() -> (Array<u16>, Array<u16>, Array<u16>, Array<u16>) {
        let sig = shake::signature();
        let s1 = unpack_512_u16(sig.span().slice(0, 29)).unwrap();
        let hint = unpack_512_u16(sig.span().slice(31, 29)).unwrap();
        let h_ntt = unpack_512_u16(shake::public_key().span()).unwrap();
        let point = hash_to_point_shake_512(shake::msg(), *sig.at(29), *sig.at(30)).unwrap();
        (s1, h_ntt, hint, point)
    }

    /// Copy of `values` with coefficient `index` moved by +1 or -1 modulo q.
    fn nudged(mut values: Span<u16>, index: u32, up: bool) -> Array<u16> {
        let mut out: Array<u16> = array![];
        let mut i: u32 = 0;
        while let Some(v) = values.pop_front() {
            if i != index {
                out.append(*v);
            } else if up {
                out.append(add_mod(*v, 1));
            } else {
                out.append(add_mod(*v, 12288));
            }
            i += 1;
        }
        out
    }

    /// Every hint coefficient in `[start, end)`, moved by ±1, must be rejected: the NTT is a
    /// bijection, so any other hint fails the pointwise check.
    fn assert_hint_tampering_rejected(start: u32, end: u32) {
        let (s1, h_ntt, hint, point) = fixture_instance();
        assert!(verify_512_with_hint_u16(s1.span(), h_ntt.span(), hint.span(), point.span()));
        for index in start..end {
            let up = nudged(hint.span(), index, true);
            let down = nudged(hint.span(), index, false);
            assert!(!verify_512_with_hint_u16(s1.span(), h_ntt.span(), up.span(), point.span()));
            assert!(!verify_512_with_hint_u16(s1.span(), h_ntt.span(), down.span(), point.span()));
        }
    }

    /// Every s1 coefficient in `[start, end)`, moved by ±1 under the original hint, must be
    /// rejected by the hint verifier.
    fn assert_hint_s1_tampering_rejected(start: u32, end: u32) {
        let (s1, h_ntt, hint, point) = fixture_instance();
        for index in start..end {
            let up = nudged(s1.span(), index, true);
            let down = nudged(s1.span(), index, false);
            assert!(!verify_512_with_hint_u16(up.span(), h_ntt.span(), hint.span(), point.span()));
            assert!(
                !verify_512_with_hint_u16(down.span(), h_ntt.span(), hint.span(), point.span()),
            );
        }
    }

    /// Every s1 coefficient in `[start, end)`, moved by ±1, must be rejected by the direct
    /// verifier.
    fn assert_direct_s1_tampering_rejected(start: u32, end: u32) {
        let (s1, h_ntt, _, point) = fixture_instance();
        assert!(verify_512_direct_u16(s1.span(), h_ntt.span(), point.span()));
        for index in start..end {
            let up = nudged(s1.span(), index, true);
            let down = nudged(s1.span(), index, false);
            assert!(!verify_512_direct_u16(up.span(), h_ntt.span(), point.span()));
            assert!(!verify_512_direct_u16(down.span(), h_ntt.span(), point.span()));
        }
    }

    #[test]
    fn test_hint_tampering_rejected_0_64() {
        assert_hint_tampering_rejected(0, 64);
    }

    #[test]
    fn test_hint_tampering_rejected_64_128() {
        assert_hint_tampering_rejected(64, 128);
    }

    #[test]
    fn test_hint_tampering_rejected_128_192() {
        assert_hint_tampering_rejected(128, 192);
    }

    #[test]
    fn test_hint_tampering_rejected_192_256() {
        assert_hint_tampering_rejected(192, 256);
    }

    #[test]
    fn test_hint_tampering_rejected_256_320() {
        assert_hint_tampering_rejected(256, 320);
    }

    #[test]
    fn test_hint_tampering_rejected_320_384() {
        assert_hint_tampering_rejected(320, 384);
    }

    #[test]
    fn test_hint_tampering_rejected_384_448() {
        assert_hint_tampering_rejected(384, 448);
    }

    #[test]
    fn test_hint_tampering_rejected_448_512() {
        assert_hint_tampering_rejected(448, 512);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_0_64() {
        assert_hint_s1_tampering_rejected(0, 64);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_64_128() {
        assert_hint_s1_tampering_rejected(64, 128);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_128_192() {
        assert_hint_s1_tampering_rejected(128, 192);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_192_256() {
        assert_hint_s1_tampering_rejected(192, 256);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_256_320() {
        assert_hint_s1_tampering_rejected(256, 320);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_320_384() {
        assert_hint_s1_tampering_rejected(320, 384);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_384_448() {
        assert_hint_s1_tampering_rejected(384, 448);
    }

    #[test]
    fn test_hint_s1_tampering_rejected_448_512() {
        assert_hint_s1_tampering_rejected(448, 512);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_0_32() {
        assert_direct_s1_tampering_rejected(0, 32);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_32_64() {
        assert_direct_s1_tampering_rejected(32, 64);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_64_96() {
        assert_direct_s1_tampering_rejected(64, 96);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_96_128() {
        assert_direct_s1_tampering_rejected(96, 128);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_128_160() {
        assert_direct_s1_tampering_rejected(128, 160);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_160_192() {
        assert_direct_s1_tampering_rejected(160, 192);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_192_224() {
        assert_direct_s1_tampering_rejected(192, 224);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_224_256() {
        assert_direct_s1_tampering_rejected(224, 256);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_256_288() {
        assert_direct_s1_tampering_rejected(256, 288);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_288_320() {
        assert_direct_s1_tampering_rejected(288, 320);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_320_352() {
        assert_direct_s1_tampering_rejected(320, 352);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_352_384() {
        assert_direct_s1_tampering_rejected(352, 384);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_384_416() {
        assert_direct_s1_tampering_rejected(384, 416);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_416_448() {
        assert_direct_s1_tampering_rejected(416, 448);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_448_480() {
        assert_direct_s1_tampering_rejected(448, 480);
    }

    #[test]
    fn test_direct_s1_tampering_rejected_480_512() {
        assert_direct_s1_tampering_rejected(480, 512);
    }
}
