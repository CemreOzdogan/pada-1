//! FIPS 204 Algorithms 35-40 (Decompose/HighBits/LowBits/MakeHint/UseHint), ported with
//! q/gamma2 as runtime parameters instead of compile-time constants.

use crate::poly::{Poly, N};

/// Hint bits: one Vec<bool> of length N per polynomial in the k-length hint vector.
pub type Hint = Vec<Vec<bool>>;

fn mod_pm(r: i64, alpha: i64) -> i64 {
    let mut r0 = r.rem_euclid(alpha);
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
    r0
}

/// Splits r (any representative, reduced mod q internally) into (r1, r0) such that
/// r = r1*alpha + r0 (mod q), with r0 in (-alpha/2, alpha/2], alpha = 2*gamma2. Handles the
/// edge case where r1 would wrap to a value equal to (q-1)/alpha by folding it back to r1=0.
pub fn decompose(r: i32, gamma2: i32, q: i32) -> (i32, i32) {
    let alpha = 2 * gamma2 as i64;
    let r_mod = (r as i64).rem_euclid(q as i64);
    let mut r0 = mod_pm(r_mod, alpha);
    let r1 = if r_mod - r0 == (q as i64) - 1 {
        r0 -= 1;
        0
    } else {
        (r_mod - r0) / alpha
    };
    (r1 as i32, r0 as i32)
}

/// FIPS 204 Algorithm 35 (Power2Round): splits r into (r1, r0) with r = r1*2^13 + r0 (mod q),
/// r0 in (-2^12, 2^12]. d=13 is a fixed global FIPS 204 constant (same for all three standard
/// parameter sets, not derived from k/l/q/gamma1).
pub fn power2round(r: i32, q: i32) -> (i32, i32) {
    const D: i64 = 13;
    let pow2d = 1i64 << D;
    let r_mod = (r as i64).rem_euclid(q as i64);
    let r0 = mod_pm(r_mod, pow2d);
    let r1 = (r_mod - r0) >> D;
    (r1 as i32, r0 as i32)
}

pub fn power2round_vec(v: &[Poly], q: i32) -> (Vec<Poly>, Vec<Poly>) {
    let mut t1 = Vec::with_capacity(v.len());
    let mut t0 = Vec::with_capacity(v.len());
    for p in v {
        let mut p1 = Poly::zero();
        let mut p0 = Poly::zero();
        for i in 0..N {
            let (r1, r0) = power2round(p.coeffs[i], q);
            p1.coeffs[i] = r1;
            p0.coeffs[i] = r0;
        }
        t1.push(p1);
        t0.push(p0);
    }
    (t1, t0)
}

pub fn high_bits(r: i32, gamma2: i32, q: i32) -> i32 {
    decompose(r, gamma2, q).0
}

pub fn low_bits(r: i32, gamma2: i32, q: i32) -> i32 {
    decompose(r, gamma2, q).1
}

/// True iff adding correction z to r changes the high bits — i.e. a hint is needed to recover
/// the correct high bits at verify time from a value that was rounded/compressed differently.
pub fn make_hint(z: i32, r: i32, gamma2: i32, q: i32) -> bool {
    let r1 = high_bits(r, gamma2, q);
    let v1 = high_bits(r + z, gamma2, q);
    r1 != v1
}

/// Recovers the corrected high bits of r using a hint bit produced by `make_hint`.
pub fn use_hint(h: bool, r: i32, gamma2: i32, q: i32) -> i32 {
    let alpha = 2 * gamma2;
    let m = (q - 1) / alpha;
    let (r1, r0) = decompose(r, gamma2, q);
    if !h {
        return r1;
    }
    if r0 > 0 {
        (r1 + 1).rem_euclid(m)
    } else {
        (r1 - 1).rem_euclid(m)
    }
}

pub fn high_bits_vec(v: &[Poly], gamma2: i32, q: i32) -> Vec<Poly> {
    v.iter()
        .map(|p| {
            let mut out = Poly::zero();
            for i in 0..N {
                out.coeffs[i] = high_bits(p.coeffs[i], gamma2, q);
            }
            out
        })
        .collect()
}

pub fn low_bits_vec(v: &[Poly], gamma2: i32, q: i32) -> Vec<Poly> {
    v.iter()
        .map(|p| {
            let mut out = Poly::zero();
            for i in 0..N {
                out.coeffs[i] = low_bits(p.coeffs[i], gamma2, q);
            }
            out
        })
        .collect()
}

pub fn make_hint_vec(z: &[Poly], r: &[Poly], gamma2: i32, q: i32) -> Hint {
    z.iter()
        .zip(r.iter())
        .map(|(zp, rp)| {
            (0..N)
                .map(|i| make_hint(zp.coeffs[i], rp.coeffs[i], gamma2, q))
                .collect()
        })
        .collect()
}

pub fn use_hint_vec(h: &Hint, r: &[Poly], gamma2: i32, q: i32) -> Vec<Poly> {
    h.iter()
        .zip(r.iter())
        .map(|(hp, rp)| {
            let mut out = Poly::zero();
            for ((o, &h_bit), &r_coeff) in out.coeffs.iter_mut().zip(hp.iter()).zip(rp.coeffs.iter()) {
                *o = use_hint(h_bit, r_coeff, gamma2, q);
            }
            out
        })
        .collect()
}

pub fn hint_weight(h: &Hint) -> u32 {
    h.iter()
        .flat_map(|p| p.iter())
        .filter(|&&b| b)
        .count() as u32
}

/// Reduces every coefficient to its centered representative in (-q/2, q/2]. `Poly::add`/`sub`
/// (and NTT multiplication) always normalize into [0, q); anything that gets bit-packed as a
/// small signed value (e.g. the signature's `z`) must be centered first, or packing silently
/// truncates values that are "small" mathematically but stored near q.
pub fn to_centered(p: &Poly, q: i32) -> Poly {
    let mut out = Poly::zero();
    for i in 0..N {
        let r = p.coeffs[i].rem_euclid(q);
        out.coeffs[i] = if r > q / 2 { r - q } else { r };
    }
    out
}

pub fn to_centered_vec(v: &[Poly], q: i32) -> Vec<Poly> {
    v.iter().map(|p| to_centered(p, q)).collect()
}

/// Centered infinity norm: max over coefficients of min(c mod q, q - (c mod q)).
pub fn infinity_norm_centered(p: &Poly, q: i32) -> i32 {
    p.coeffs
        .iter()
        .map(|&c| {
            let r = c.rem_euclid(q);
            r.min(q - r)
        })
        .max()
        .unwrap_or(0)
}

pub fn infinity_norm_centered_vec(v: &[Poly], q: i32) -> i32 {
    v.iter()
        .map(|p| infinity_norm_centered(p, q))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_reconstructs_r() {
        let q = 8380417;
        let gamma2 = 130944;
        let alpha = 2 * gamma2;
        for r in [0, 1, q - 1, gamma2, q - gamma2, 12345678] {
            let (r1, r0) = decompose(r, gamma2, q);
            let reconstructed = ((r1 as i64) * (alpha as i64) + r0 as i64).rem_euclid(q as i64);
            assert_eq!(reconstructed, (r as i64).rem_euclid(q as i64));
        }
    }

    #[test]
    fn power2round_reconstructs_r_and_bounds_r0() {
        let q = 8380417;
        for r in [0, 1, q - 1, 4096, 8191, 8192, 8193, 4_000_000] {
            let (r1, r0) = power2round(r, q);
            let reconstructed = ((r1 as i64) * (1i64 << 13) + r0 as i64).rem_euclid(q as i64);
            assert_eq!(reconstructed, (r as i64).rem_euclid(q as i64), "r={r}");
            assert!((-4096..=4096).contains(&r0), "r0={r0} out of range for r={r}");
        }
    }

    #[test]
    fn use_hint_recovers_high_bits_of_perturbed_value() {
        // Precondition for the MakeHint/UseHint recovery guarantee: |z| <= gamma2.
        let q = 8380417;
        let gamma2 = 130944;
        for (r, z) in [(55555, 50000), (55555, -50000), (200000, 129000), (q - 1, 60000)] {
            let h = make_hint(z, r, gamma2, q);
            let expected = high_bits(r + z, gamma2, q);
            assert_eq!(use_hint(h, r, gamma2, q), expected, "r={r} z={z}");
        }
    }
}
