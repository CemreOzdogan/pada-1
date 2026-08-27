//! Runtime NTT over Z_q[x]/(x^n+1), for any power-of-two n and prime q with q ≡ 1 (mod 2n).
//! Direct generalization of `ntt.rs` (which is hardcoded to n=256 for the DSA path) to a
//! runtime-chosen ring degree — same full radix-2 split algorithm, `Vec<i64>` instead of
//! `[i64; 256]`.

pub struct NttTable {
    pub n: usize,
    pub q: i64,
    pub zetas: Vec<i64>,
    /// zetas_inv[i] = -zetas[i] mod q — see `ntt.rs` for why this avoids a second
    /// root-of-unity computation for the inverse transform.
    pub zetas_inv: Vec<i64>,
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
/// (mod q) — see `ntt.rs::find_2n_root` for the justification (identical logic, n is just a
/// runtime value here instead of a compile-time constant).
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

pub fn build_table(n: usize, q: i32) -> Result<NttTable, String> {
    if !n.is_power_of_two() {
        return Err(format!("n={n} must be a power of two"));
    }
    let q = q as i64;
    let zeta = find_2n_root(q, n)?;
    let log_n = n.trailing_zeros();

    let mut zetas = vec![0i64; n];
    let mut zetas_inv = vec![0i64; n];
    for i in 0..n {
        let e = bit_reverse(i, log_n) as i64;
        let z = mod_pow(zeta, e, q);
        zetas[i] = z;
        zetas_inv[i] = (q - z) % q;
    }

    Ok(NttTable {
        n,
        q,
        zetas,
        zetas_inv,
        n_inv: mod_inverse(n as i64, q),
    })
}

/// In-place forward NTT (decimation-in-time, Cooley-Tukey). `a` must have length `table.n`.
pub fn ntt(a: &mut [i64], table: &NttTable) {
    let (n, q) = (table.n, table.q);
    let mut k = 0usize;
    let mut len = n / 2;
    while len >= 1 {
        let mut start = 0;
        while start < n {
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

/// In-place inverse NTT (decimation-in-frequency, Gentleman-Sande), including 1/n scaling.
pub fn inv_ntt(a: &mut [i64], table: &NttTable) {
    let (n, q) = (table.n, table.q);
    let mut k = n;
    let mut len = 1;
    while len < n {
        let mut start = 0;
        while start < n {
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

/// Negacyclic polynomial multiplication via NTT. `a`, `b` must each have length `table.n`.
pub fn ntt_mul(a: &[i32], b: &[i32], table: &NttTable) -> Vec<i32> {
    let mut av: Vec<i64> = a.iter().map(|&c| c as i64).collect();
    let mut bv: Vec<i64> = b.iter().map(|&c| c as i64).collect();
    ntt(&mut av, table);
    ntt(&mut bv, table);

    let mut cv = vec![0i64; table.n];
    for i in 0..table.n {
        cv[i] = (av[i] * bv[i]).rem_euclid(table.q);
    }
    inv_ntt(&mut cv, table);

    cv.iter().map(|&c| c as i32).collect()
}

/// Schoolbook negacyclic multiplication mod (x^n+1), used only as the cross-check ground
/// truth in tests — never called from the actual keygen/encaps/decaps path.
#[cfg(test)]
fn schoolbook_mul(a: &[i32], b: &[i32], q: i32) -> Vec<i32> {
    let n = a.len();
    let mut wide = vec![0i64; 2 * n];
    for i in 0..n {
        if a[i] == 0 {
            continue;
        }
        let av = a[i] as i64;
        for j in 0..n {
            wide[i + j] += av * b[j] as i64;
        }
    }
    let mut out = vec![0i32; n];
    for i in 0..n {
        let reduced = wide[i] - wide[i + n];
        out[i] = reduced.rem_euclid(q as i64) as i32;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Xorshift32(u32);
    impl Xorshift32 {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }
    }

    fn random_poly(rng: &mut Xorshift32, n: usize, q: i32) -> Vec<i32> {
        (0..n).map(|_| (rng.next() % q as u32) as i32).collect()
    }

    fn check_matches_schoolbook(n: usize, q: i32) {
        let table = build_table(n, q).expect("(n,q) should be NTT-suitable");
        let mut rng = Xorshift32(0xC0FFEE ^ (q as u32) ^ (n as u32));
        for _ in 0..20 {
            let a = random_poly(&mut rng, n, q);
            let b = random_poly(&mut rng, n, q);
            let via_ntt = ntt_mul(&a, &b, &table);
            let via_schoolbook = schoolbook_mul(&a, &b, q);
            assert_eq!(via_ntt, via_schoolbook, "mismatch for n={n} q={q}");
        }
    }

    #[test]
    fn ntt_matches_schoolbook_n256() {
        check_matches_schoolbook(256, 7681);
    }

    #[test]
    fn ntt_matches_schoolbook_n128() {
        check_matches_schoolbook(128, 12289);
    }

    #[test]
    fn ntt_matches_schoolbook_small_n() {
        check_matches_schoolbook(32, 257);
    }

    #[test]
    fn rejects_non_power_of_two_n() {
        assert!(build_table(300, 7681).is_err());
    }

    #[test]
    fn rejects_non_ntt_suitable_q() {
        assert!(build_table(256, 3329).is_err()); // 3329 ≡ 1 (mod 256) but not (mod 512)
    }
}
