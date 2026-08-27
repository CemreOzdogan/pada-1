//! Custom ML-DSA (Dilithium-shaped) parameter derivation. The window only ever asks the
//! user for k, l, q, gamma1 — this module derives eta/gamma2/tau/omega and validates that
//! the whole tuple actually supports a terminating Fiat-Shamir-with-aborts sign loop. Every
//! failure mode returns a specific `Err`, never a silent clamp of what the user asked for.

pub const N: usize = crate::poly::N;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenericDsaParams {
    pub k: u32,
    pub l: u32,
    pub q: i32,
    pub eta: u32,
    pub gamma1: i32,
    pub gamma2: i32,
    pub tau: u32,
    pub omega: u32,
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

/// q must be prime, NTT-suitable for n=256 (q ≡ 1 mod 512), and small enough to keep
/// coefficient arithmetic comfortably inside i32/i64 and the UI's numeric widgets.
pub fn validate_q(q: i32) -> Result<(), String> {
    if q < 5 {
        return Err(format!("q={q} is too small"));
    }
    if !is_prime(q) {
        return Err(format!("q={q} is not prime"));
    }
    if (q - 1) % 512 != 0 {
        return Err(format!(
            "q={q} is not usable for NTT: need q \u{2261} 1 (mod 512) for n=256, but (q-1) mod 512 = {}",
            (q - 1) % 512
        ));
    }
    if q >= (1 << 23) {
        return Err(format!("q={q} is too large; must be < 2^23"));
    }
    Ok(())
}

pub fn build_params(k: u32, l: u32, q: i32, gamma1: i32) -> Result<GenericDsaParams, String> {
    validate_q(q)?;
    if k == 0 || l == 0 {
        return Err("k and l must both be at least 1".to_string());
    }
    if gamma1 <= 0 || gamma1 >= q / 2 {
        return Err(format!("gamma1={gamma1} must be in (0, q/2); q={q}"));
    }

    let n = N as i32;
    let tau = ((k + l) * 5).clamp(20, 60);

    let max_beta = gamma1 / (8 * n);
    if max_beta < 1 {
        return Err(format!(
            "gamma1={gamma1} is too small: need gamma1 >= {} for q={q}",
            8 * n
        ));
    }
    let eta = (max_beta / tau as i32).max(1) as u32;
    let beta = tau as i32 * eta as i32;

    let mut gamma2 = None;
    for e in 1..=9u32 {
        let candidate = (q - 1) / (1i32 << e);
        if candidate > beta && candidate <= gamma1 - beta {
            gamma2 = Some(candidate);
            break;
        }
    }
    let gamma2 = gamma2.ok_or_else(|| {
        format!(
            "no valid gamma2=(q-1)/2^e (e=1..9) satisfies beta < gamma2 <= gamma1-beta for \
             q={q}, gamma1={gamma1}, beta={beta} (tau={tau}, eta={eta}); increase gamma1 or pick a different q"
        )
    })?;

    let raw_omega = (4i64 * k as i64 * N as i64 * beta as i64) / gamma2 as i64;
    let omega = raw_omega.clamp(8, (k as i64) * (N as i64)) as u32;

    Ok(GenericDsaParams {
        k,
        l,
        q,
        eta,
        gamma1,
        gamma2,
        tau,
        omega,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_dilithium_shaped_example() {
        let p = build_params(4, 4, 8380417, 131072).unwrap();
        assert_eq!(p.tau, 40);
        assert_eq!(p.eta, 1);
        assert_eq!(p.gamma2, 130944);
        assert_eq!(p.omega, 8);
    }

    #[test]
    fn derives_larger_gamma1_example() {
        let p = build_params(4, 4, 8380417, 524288).unwrap();
        assert_eq!(p.tau, 40);
        assert_eq!(p.eta, 6);
        assert_eq!(p.gamma2, 523776);
        assert_eq!(p.omega, 8);
    }

    #[test]
    fn derives_small_q_example() {
        let p = build_params(2, 2, 12289, 4096).unwrap();
        assert_eq!(p.tau, 20);
        assert_eq!(p.eta, 1);
        assert_eq!(p.gamma2, 3072);
        assert_eq!(p.omega, 13);
    }

    #[test]
    fn rejects_gamma1_too_small() {
        assert!(build_params(2, 2, 12289, 1024).is_err());
    }

    #[test]
    fn rejects_non_prime_q() {
        assert!(build_params(4, 4, 12288, 4096).is_err());
    }

    #[test]
    fn rejects_q_not_ntt_suitable() {
        assert!(build_params(4, 4, 3329, 512).is_err());
    }
}
