//! Runtime NTT over Z_q[x]/(x^256+1), for any prime q with q ≡ 1 (mod 512). Full radix-2
//! split into 256 linear factors (Dilithium-shaped — unlike Kyber's NTT, which stops one
//! layer early), so multiplication in the NTT domain is pure pointwise multiplication with
//! no follow-up base-case step. Used by `dilithium.rs` in place of `poly::Poly::mul`.

use crate::poly::{Poly, N};

pub struct NttTable {
    pub q: i64,
    pub zetas: [i64; N],
    /// zetas_inv[i] = -zetas[i] mod q — the standard "negate and use in reverse order" trick
    /// that turns the forward Cooley-Tukey twiddle table into the inverse Gentleman-Sande one,
    /// without needing a second root-of-unity computation.
    pub zetas_inv: [i64; N],
    pub n_inv: i64,
}

fn mod_pow(base: i64, mut exp: i64, q: i64) -> i64 {
    let mut result = 1i64;
    let mut base = base.rem_euclid(q);
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % q;
        }
        base = base * base % q;
        exp >>= 1;
    }
    result
}

fn mod_inverse(a: i64, q: i64) -> i64 {
    mod_pow(a, q - 2, q)
}

fn bit_reverse(mut x: usize, log_n: u32) -> usize {
    let mut r = 0usize;
    for _ in 0..log_n {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    r
}

/// Find a primitive 2n-th root of unity mod q. Necessary and sufficient check: zeta^n == -1
/// (mod q) — this rules out zeta having any order that's a proper divisor of 2n, and
/// zeta^(2n) == 1 already holds by construction (zeta = h^((q-1)/2n)), so no factorization
/// of q-1 is needed.
fn find_2n_root(q: i64, n: usize) -> Result<i64, String> {
    let two_n = (2 * n) as i64;
    if (q - 1) % two_n != 0 {
        return Err(format!("q={q} has no element of order {two_n} (NTT-unsuitable)"));
    }
    let exp = (q - 1) / two_n;
    for h in 2..100_000i64 {
        let zeta = mod_pow(h, exp, q);
        if zeta == 0 {
            continue;
        }
        if mod_pow(zeta, n as i64, q) == q - 1 {
            return Ok(zeta);
        }
    }
    Err(format!("could not find a primitive {two_n}-th root of unity mod {q}"))
}

pub fn build_table(q: i32) -> Result<NttTable, String> {
    let q = q as i64;
    let zeta = find_2n_root(q, N)?;
    let log_n = N.trailing_zeros();

    let mut zetas = [0i64; N];
    let mut zetas_inv = [0i64; N];
    for i in 0..N {
        let e = bit_reverse(i, log_n) as i64;
        let z = mod_pow(zeta, e, q);
        zetas[i] = z;
        zetas_inv[i] = (q - z) % q;
    }

    Ok(NttTable {
        q,
        zetas,
        zetas_inv,
        n_inv: mod_inverse(N as i64, q),
    })
}

/// In-place forward NTT (decimation-in-time, Cooley-Tukey).
pub fn ntt(a: &mut [i64; N], table: &NttTable) {
    let q = table.q;
    let mut k = 0usize;
    let mut len = N / 2;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = table.zetas[k];
            for j in start..start + len {
                let t = (zeta * a[j + len]).rem_euclid(q);
                a[j + len] = (a[j] - t).rem_euclid(q);
                a[j] = (a[j] + t).rem_euclid(q);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// In-place inverse NTT (decimation-in-frequency, Gentleman-Sande), including the final 1/N
/// scaling.
pub fn inv_ntt(a: &mut [i64; N], table: &NttTable) {
    let q = table.q;
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = table.zetas_inv[k];
            for j in start..start + len {
                let t = a[j];
                a[j] = (t + a[j + len]).rem_euclid(q);
                let diff = (t - a[j + len]).rem_euclid(q);
                a[j + len] = (zeta * diff).rem_euclid(q);
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for x in a.iter_mut() {
        *x = (*x * table.n_inv).rem_euclid(q);
    }
}

fn to_i64_array(p: &Poly) -> [i64; N] {
    let mut out = [0i64; N];
    for i in 0..N {
        out[i] = p.coeffs[i] as i64;
    }
    out
}

/// Negacyclic polynomial multiplication via NTT — drop-in replacement for
/// `poly::Poly::mul` used throughout the DSA path.
pub fn ntt_mul(a: &Poly, b: &Poly, table: &NttTable) -> Poly {
    let mut av = to_i64_array(a);
    let mut bv = to_i64_array(b);
    ntt(&mut av, table);
    ntt(&mut bv, table);

    let mut cv = [0i64; N];
    for i in 0..N {
        cv[i] = (av[i] * bv[i]).rem_euclid(table.q);
    }
    inv_ntt(&mut cv, table);

    let mut out = Poly::zero();
    for i in 0..N {
        out.coeffs[i] = cv[i] as i32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic xorshift32 — no external rand dependency needed for this test.
    struct Xorshift32(u32);
    impl Xorshift32 {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }
    }

    fn random_poly(rng: &mut Xorshift32, q: i32) -> Poly {
        let mut p = Poly::zero();
        for c in p.coeffs.iter_mut() {
            *c = (rng.next() % q as u32) as i32;
        }
        p
    }

    fn check_matches_schoolbook(q: i32) {
        let table = build_table(q).expect("q should be NTT-suitable");
        let mut rng = Xorshift32(0xC0FFEE ^ q as u32);
        for _ in 0..20 {
            let a = random_poly(&mut rng, q);
            let b = random_poly(&mut rng, q);
            let via_ntt = ntt_mul(&a, &b, &table);
            let via_schoolbook = a.mul(&b, q);
            assert_eq!(via_ntt, via_schoolbook, "mismatch for q={q}");
        }
    }

    #[test]
    fn ntt_matches_schoolbook_dilithium_q() {
        check_matches_schoolbook(8380417);
    }

    #[test]
    fn ntt_matches_schoolbook_small_q() {
        check_matches_schoolbook(12289);
    }

    #[test]
    fn rejects_non_ntt_suitable_q() {
        assert!(build_table(3329).is_err());
    }
}
