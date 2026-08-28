//! Custom ML-DSA (Dilithium-shaped) parameter derivation. The window always asks for k, l, q,
//! gamma1 — this module derives eta/gamma2/tau/omega/lambda and validates that the whole tuple
//! actually supports a terminating Fiat-Shamir-with-aborts sign loop. Every failure mode returns
//! a specific `Err`, never a silent clamp of what the user asked for.
//!
//! FIPS 204 itself only defines eta/gamma2/tau/omega/lambda for its 3 approved parameter sets —
//! it has no formula for arbitrary (k,l,q,gamma1). So each of these is an explicit optional
//! override (`DsaParamOverrides`): set it to the exact spec constant for a standard set and get
//! real compliance (see the conformance test in `dilithium.rs`), or leave it `None` to fall back
//! to the heuristic below for freeform research tuples. Either way `build_params` validates the
//! resulting tuple's correctness inequalities before returning it, so a bad combination — whether
//! heuristic or user-supplied — fails loudly here rather than hanging in the sign loop.

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
    pub lambda: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DsaParamOverrides {
    pub eta: Option<u32>,
    pub gamma2: Option<i32>,
    pub tau: Option<u32>,
    pub omega: Option<u32>,
    pub lambda: Option<u32>,
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

/// q must be prime, NTT-suitable for n=256 (q ≡ 1 mod 512), and small enough to leave headroom
/// in i32 arithmetic (2*gamma1, etc. all stay comfortably below q). All NTT/rounding math here
/// runs in i64 internally, so there's no correctness reason to cap this near 2^23 the way
/// FIPS 204's own q happens to be sized — well-known larger NTT primes (e.g. 998244353) are
/// intentionally allowed.
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
    if q >= 2_000_000_000 {
        return Err(format!("q={q} is too large; must be < 2,000,000,000"));
    }
    Ok(())
}

pub fn build_params(
    k: u32,
    l: u32,
    q: i32,
    gamma1: i32,
    overrides: &DsaParamOverrides,
) -> Result<GenericDsaParams, String> {
    validate_q(q)?;
    if k == 0 || l == 0 {
        return Err("k and l must both be at least 1".to_string());
    }
    if gamma1 <= 0 || gamma1 >= q / 2 {
        return Err(format!("gamma1={gamma1} must be in (0, q/2); q={q}"));
    }

    let n = N as i32;

    let tau = match overrides.tau {
        Some(t) => t,
        None => ((k + l) * 5).clamp(20, 60),
    };
    if tau == 0 || tau as usize > N {
        return Err(format!("tau={tau} must be in 1..={N}"));
    }

    let eta = match overrides.eta {
        Some(e) => e,
        None => {
            let max_beta = gamma1 / (8 * n);
            if max_beta < 1 {
                return Err(format!(
                    "gamma1={gamma1} is too small: need gamma1 >= {} for q={q}",
                    8 * n
                ));
            }
            (max_beta / tau as i32).max(1) as u32
        }
    };
    if eta == 0 {
        return Err("eta must be at least 1".to_string());
    }
    let beta = tau as i32 * eta as i32;
    if beta >= gamma1 {
        return Err(format!(
            "beta=tau*eta={beta} must be < gamma1={gamma1} (tau={tau}, eta={eta}) — the z-bound \
             check would reject every candidate"
        ));
    }

    let gamma2 = match overrides.gamma2 {
        Some(g) => {
            if g <= beta || g > gamma1 - beta {
                return Err(format!(
                    "gamma2={g} must satisfy beta < gamma2 <= gamma1-beta (beta={beta}, gamma1={gamma1})"
                ));
            }
            if (q - 1) % (2 * g) != 0 {
                return Err(format!(
                    "gamma2={g} must exactly divide (q-1)/2 for Decompose's centered-mod \
                     partition to be exact (q={q}, (q-1) mod (2*gamma2) = {})",
                    (q - 1) % (2 * g)
                ));
            }
            g
        }
        None => {
            let mut found = None;
            for e in 1..=9u32 {
                let candidate = (q - 1) / (1i32 << e);
                if candidate > beta && candidate <= gamma1 - beta {
                    found = Some(candidate);
                    break;
                }
            }
            found.ok_or_else(|| {
                format!(
                    "no valid gamma2=(q-1)/2^e (e=1..9) satisfies beta < gamma2 <= gamma1-beta for \
                     q={q}, gamma1={gamma1}, beta={beta} (tau={tau}, eta={eta}); increase gamma1, pick a \
                     different q, or override gamma2 directly"
                )
            })?
        }
    };

    // c*t0's infinity norm (bounded by the fixed FIPS 204 Power2Round constant d=13, so
    // |t0| <= 2^12=4096 regardless of q) must reliably stay under gamma2 for the sign loop's
    // ||c*t0||∞ < gamma2 rejection check (dilithium.rs) to terminate in a reasonable number of
    // attempts. Its typical magnitude is ~sqrt(tau)*4096 (tau signed ±1 terms summing, not the
    // tau*4096 worst case), so require gamma2 to clear that with roughly the same ~3.7x margin
    // the 3 standard FIPS 204 parameter sets themselves have. Verified empirically: q=12289 with
    // tau=20 makes this check nearly impossible to pass, hanging for all 100k sign attempts.
    const T0_MAX: i64 = 1 << 12;
    if (gamma2 as i64).pow(2) < 9 * tau as i64 * T0_MAX * T0_MAX {
        return Err(format!(
            "gamma2={gamma2} is too small relative to tau={tau} for the fixed Power2Round \
             constant d=13 (max |t0|=2^12=4096): the sign loop's ||c*t0||\u{221e} < gamma2 \
             rejection check would almost never pass. Increase gamma1/q to allow a larger \
             gamma2, or reduce tau."
        ));
    }

    let omega = match overrides.omega {
        Some(o) => {
            if o == 0 || (o as i64) > (k as i64) * (N as i64) {
                return Err(format!("omega={o} must be in 1..={}", (k as i64) * (N as i64)));
            }
            o
        }
        None => {
            // Hint weight is driven by t0's magnitude (Power2Round's low bits, always bounded
            // by 2^12 since d=13 is a fixed FIPS 204 constant — NOT by beta=tau*eta, which has
            // nothing to do with it). Each of the k*N hint positions has roughly a
            // 2^12/gamma2-ish chance of a HighBits boundary crossing; 4x that as a safety
            // margin (matching the old formula's own margin factor), floored at 8, capped at
            // the true maximum k*N.
            const T0_MAGNITUDE: i64 = 1 << 12;
            let raw_omega = (4i64 * k as i64 * N as i64 * T0_MAGNITUDE) / gamma2 as i64;
            raw_omega.clamp(8, (k as i64) * (N as i64)) as u32
        }
    };

    let lambda = match overrides.lambda {
        Some(lam) => {
            if lam == 0 {
                return Err("lambda must be at least 1".to_string());
            }
            lam
        }
        // Heuristic default only — FIPS 204 ties lambda to security category (32/48/64 bytes
        // for ML-DSA-44/65/87), which tracks tau reasonably closely (39/49/60); this is not a
        // security-strength claim, just a plausible fallback. Override for anything that matters.
        None => tau.clamp(16, 64),
    };

    Ok(GenericDsaParams {
        k,
        l,
        q,
        eta,
        gamma1,
        gamma2,
        tau,
        omega,
        lambda,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_dilithium_shaped_example() {
        let p = build_params(4, 4, 8380417, 131072, &DsaParamOverrides::default()).unwrap();
        assert_eq!(p.tau, 40);
        assert_eq!(p.eta, 1);
        assert_eq!(p.gamma2, 130944);
        assert_eq!(p.omega, 128);
    }

    #[test]
    fn derives_larger_gamma1_example() {
        let p = build_params(4, 4, 8380417, 524288, &DsaParamOverrides::default()).unwrap();
        assert_eq!(p.tau, 40);
        assert_eq!(p.eta, 6);
        assert_eq!(p.gamma2, 523776);
        assert_eq!(p.omega, 32);
    }

    #[test]
    fn derives_small_q_example() {
        // q=524801 (~2^19, prime, q≡1 mod 512): small relative to real ML-DSA's q=8380417, but
        // still with enough headroom over the fixed d=13 Power2Round constant to be usable —
        // unlike q=12289, which is too small (see the gamma2-vs-tau validation above) once the
        // ||c*t0||∞ < gamma2 check is real rather than a decorative bitmap.
        let p = build_params(2, 2, 524_801, 131_072, &DsaParamOverrides::default()).unwrap();
        assert_eq!(p.tau, 20);
        assert_eq!(p.eta, 3);
        assert_eq!(p.gamma2, 65600);
        assert_eq!(p.omega, 127);
    }

    #[test]
    fn rejects_gamma2_too_small_relative_to_tau_for_fixed_d13() {
        // q=12289 with the heuristic's default tau=20 makes ||c*t0||∞ < gamma2 nearly
        // impossible to satisfy for any candidate, since gamma2 (derived as (q-1)/2^e) tops
        // out at 3072 — regression coverage for the sign-loop hang this validation prevents.
        assert!(build_params(2, 2, 12289, 4096, &DsaParamOverrides::default()).is_err());
    }

    #[test]
    fn rejects_gamma1_too_small() {
        assert!(build_params(2, 2, 12289, 1024, &DsaParamOverrides::default()).is_err());
    }

    #[test]
    fn rejects_non_prime_q() {
        assert!(build_params(4, 4, 12288, 4096, &DsaParamOverrides::default()).is_err());
    }

    #[test]
    fn rejects_q_not_ntt_suitable() {
        assert!(build_params(4, 4, 3329, 512, &DsaParamOverrides::default()).is_err());
    }

    #[test]
    fn accepts_exact_ml_dsa_44_overrides() {
        let overrides = DsaParamOverrides {
            eta: Some(2),
            gamma2: Some((8380417 - 1) / 88),
            tau: Some(39),
            omega: Some(80),
            lambda: Some(32),
        };
        let p = build_params(4, 4, 8380417, 1 << 17, &overrides).unwrap();
        assert_eq!(p.eta, 2);
        assert_eq!(p.gamma2, 95232);
        assert_eq!(p.tau, 39);
        assert_eq!(p.omega, 80);
        assert_eq!(p.lambda, 32);
    }

    #[test]
    fn accepts_exact_ml_dsa_65_overrides() {
        let overrides = DsaParamOverrides {
            eta: Some(4),
            gamma2: Some((8380417 - 1) / 32),
            tau: Some(49),
            omega: Some(55),
            lambda: Some(48),
        };
        let p = build_params(6, 5, 8380417, 1 << 19, &overrides).unwrap();
        assert_eq!(p.gamma2, 261888);
        assert_eq!(p.omega, 55);
    }

    #[test]
    fn accepts_exact_ml_dsa_87_overrides() {
        let overrides = DsaParamOverrides {
            eta: Some(2),
            gamma2: Some((8380417 - 1) / 32),
            tau: Some(60),
            omega: Some(75),
            lambda: Some(64),
        };
        let p = build_params(8, 7, 8380417, 1 << 19, &overrides).unwrap();
        assert_eq!(p.tau, 60);
        assert_eq!(p.omega, 75);
    }

    #[test]
    fn rejects_gamma2_override_that_doesnt_divide_q_minus_1() {
        let overrides = DsaParamOverrides {
            gamma2: Some(100_000),
            ..Default::default()
        };
        assert!(build_params(4, 4, 8380417, 1 << 17, &overrides).is_err());
    }
}
