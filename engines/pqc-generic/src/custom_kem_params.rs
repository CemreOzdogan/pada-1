//! Custom ML-KEM (Kyber-shaped) parameter derivation. The window only ever asks the user for
//! k, n, q — this module derives eta1/eta2/du/dv and validates that the whole tuple is
//! NTT-suitable and structurally sound. Every failure mode returns a specific `Err`, never a
//! silent clamp of what the user asked for.
//!
//! The derivation formulas below are calibrated to exactly reproduce real ML-KEM-512/768/1024's
//! published (k, eta1, du, dv) at n=256 (verified in tests) — but real ML-KEM's own q=3329 only
//! satisfies q ≡ 1 (mod n), not q ≡ 1 (mod 2n), which is why Kyber's own NTT stops one layer
//! early (a partial split + basemul) instead of doing the full split this engine uses (matching
//! the ML-DSA custom engine). So q=3329 itself won't pass this engine's own NTT-suitability
//! check — expected, and not a bug: the formulas are calibrated via the (q_bits, k*n) shape of
//! the real parameter sets, not tied to 3329 specifically, and are verified empirically via a
//! real encaps/decaps roundtrip test (see `custom_kem.rs`), same posture as the DSA engine's
//! heuristic tau/eta/omega derivation.

use crate::custom_kem_ntt::build_table;
use crate::encode::bits_for_q;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericCustomKemParams {
    pub k: u32,
    pub n: usize,
    pub q: i32,
    pub eta1: u32,
    pub eta2: u32,
    pub du: u32,
    pub dv: u32,
}

fn is_prime(n: i32) -> bool {
    if n < 2 {
        return false;
    }
    if n % 2 == 0 {
        return n == 2;
    }
    let mut d = 3i64;
    while d * d <= n as i64 {
        if n as i64 % d == 0 {
            return false;
        }
        d += 2;
    }
    true
}

pub fn validate_n(n: usize) -> Result<(), String> {
    if !n.is_power_of_two() {
        return Err(format!("n={n} must be a power of two"));
    }
    if !(32..=1024).contains(&n) {
        return Err(format!("n={n} must be between 32 and 1024"));
    }
    Ok(())
}

/// q must be prime, NTT-suitable for the given n (q ≡ 1 mod 2n), and small enough to leave
/// headroom in i32 arithmetic — same posture as `dsa_params::validate_q`.
pub fn validate_q(q: i32, n: usize) -> Result<(), String> {
    if q < 5 {
        return Err(format!("q={q} is too small"));
    }
    if !is_prime(q) {
        return Err(format!("q={q} is not prime"));
    }
    let two_n = 2 * n as i32;
    if (q - 1) % two_n != 0 {
        return Err(format!(
            "q={q} is not usable for NTT: need q \u{2261} 1 (mod {two_n}) for n={n}, but (q-1) mod {two_n} = {}",
            (q - 1) % two_n
        ));
    }
    if q >= 2_000_000_000 {
        return Err(format!("q={q} is too large; must be < 2,000,000,000"));
    }
    Ok(())
}

pub fn build_params(k: u32, n: usize, q: i32) -> Result<GenericCustomKemParams, String> {
    validate_n(n)?;
    validate_q(q, n)?;
    if k == 0 {
        return Err("k must be at least 1".to_string());
    }
    // Confirms an actual primitive root exists (validate_q's mod-2n check is necessary but,
    // in principle, not sufficient — build_table does the real search), surfacing any failure
    // as a normal Err instead of a panic deeper in keygen.
    build_table(n, q)?;

    let d = (k as f64) * (n as f64);
    let eta = (64.0 / d.sqrt()).round().max(1.0) as u32;

    let q_bits = bits_for_q(q);
    let scale = (d.max(512.0) / 512.0).log2().floor() as i64;
    let margin_du = (2 - scale).clamp(1, 2) as u32;
    let margin_dv = (8 - scale).clamp(7, 8) as u32;
    let du = (q_bits as i64 - margin_du as i64).clamp(1, q_bits as i64 - 1).max(1) as u32;
    let dv = (q_bits as i64 - margin_dv as i64).clamp(1, q_bits as i64 - 1).max(1) as u32;

    Ok(GenericCustomKemParams {
        k,
        n,
        q,
        eta1: eta,
        eta2: eta,
        du,
        dv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Calibration prime: 7681 = 15*2^9 + 1, satisfies q ≡ 1 (mod 2n) for n up to 512 — unlike
    // real ML-KEM's own 3329, which only satisfies q ≡ 1 (mod n) (see module docs).
    const CALIBRATION_Q: i32 = 7681;

    #[test]
    fn reproduces_ml_kem_512_shape() {
        let p = build_params(2, 256, CALIBRATION_Q).unwrap();
        assert_eq!(p.eta1, 3);
        assert_eq!(p.eta2, 3);
        assert_eq!(p.du, 11);
        assert_eq!(p.dv, 5);
    }

    #[test]
    fn reproduces_ml_kem_768_shape() {
        let p = build_params(3, 256, CALIBRATION_Q).unwrap();
        assert_eq!(p.eta1, 2);
        assert_eq!(p.eta2, 2);
        assert_eq!(p.du, 11);
        assert_eq!(p.dv, 5);
    }

    #[test]
    fn reproduces_ml_kem_1024_shape() {
        let p = build_params(4, 256, CALIBRATION_Q).unwrap();
        assert_eq!(p.eta1, 2);
        assert_eq!(p.eta2, 2);
        assert_eq!(p.du, 12);
        assert_eq!(p.dv, 6);
    }

    #[test]
    fn rejects_non_power_of_two_n() {
        assert!(build_params(2, 300, CALIBRATION_Q).is_err());
    }

    #[test]
    fn rejects_non_ntt_suitable_q() {
        assert!(build_params(2, 256, 3329).is_err());
    }

    #[test]
    fn rejects_non_prime_q() {
        assert!(build_params(2, 256, 7680).is_err());
    }
}
