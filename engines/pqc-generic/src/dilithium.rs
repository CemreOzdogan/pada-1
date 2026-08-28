//! Dilithium-shaped ML-DSA orchestration, FIPS 204-exact: keygen (Algorithm 6) / sign
//! (Algorithm 7, full Fiat-Shamir-with-aborts, hedged by default) / verify (Algorithm 8), over
//! a runtime-chosen `GenericDsaParams`. Byte-exact against RustCrypto's `ml-dsa` and libcrux's
//! `libcrux-ml-dsa` for the 3 standard parameter sets when their exact constants are supplied
//! via `DsaParamOverrides` â€” see the `fips204_conformance` test module for the cross-check that
//! actually proves this, not just a claim.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::dsa_encode::encode_pk;
use crate::dsa_params::GenericDsaParams;
use crate::dsa_rounding::{
    high_bits_vec, hint_weight, infinity_norm_centered_vec, low_bits_vec, make_hint_vec,
    power2round_vec, to_centered_vec, use_hint_vec, Hint,
};
use crate::dsa_sample::{expand_mask, sample_challenge, sample_eta, sample_uniform_wide};
use crate::encode::bits_for_q;
use crate::ntt::{build_table, ntt_mul, ntt_mul_a, NttTable};
use crate::poly::Poly;

const MAX_SIGN_ATTEMPTS: u32 = 100_000;

pub struct SigningKey {
    pub rho: [u8; 32],
    /// FIPS 204's `K` â€” carried in the signing key, used at signing time to derive that
    /// signature's own rho'' (see `sign`'s local `rho_prime`, a different value from keygen's).
    pub cap_k: [u8; 32],
    pub tr: [u8; 64],
    pub s1: Vec<Poly>,
    pub s2: Vec<Poly>,
    /// Power2Round's low bits â€” NOT full `t`. The public key only ever gets `t1` (see
    /// `VerifyingKey`); `t0` here is what lets `sign` compute the exact hint correction `c*t0`.
    pub t0: Vec<Poly>,
}

pub struct VerifyingKey {
    pub rho: [u8; 32],
    /// Power2Round's high bits â€” the spec's actual compressed public key component, not full `t`.
    pub t1: Vec<Poly>,
}

pub struct Signature {
    /// Length is `params.lambda` bytes (32/48/64 for the standard sets â€” not a fixed 32).
    pub c_tilde: Vec<u8>,
    pub z: Vec<Poly>,
    pub h: Hint,
}

fn squeeze(parts: &[&[u8]], n: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    for p in parts {
        hasher.update(p);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; n];
    reader.read(&mut out);
    out
}

fn squeeze64(parts: &[&[u8]]) -> [u8; 64] {
    squeeze(parts, 64).try_into().unwrap()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

/// FIPS 204 Algorithm 32 (ExpandA): `A[r][s]` for r in 0..k, s in 0..l.
fn expand_a(rho: &[u8; 32], k: usize, l: usize, q: i32) -> Vec<Vec<Poly>> {
    (0..k)
        .map(|r| {
            (0..l)
                .map(|s| sample_uniform_wide(rho, r as u8, s as u8, q))
                .collect()
        })
        .collect()
}

/// k x l matrix (from `expand_a`, already NTT-domain per FIPS 204 Algorithm 32) times an
/// l-length normal-domain vector — see `ntt_mul_a`'s doc comment for why this must NOT use
/// plain `ntt_mul` (which would forward-transform the already-NTT-domain `A` entries again).
fn mat_vec_mul(a: &[Vec<Poly>], v: &[Poly], table: &NttTable, q: i32) -> Vec<Poly> {
    a.iter()
        .map(|row| {
            row.iter()
                .zip(v.iter())
                .fold(Poly::zero(), |acc, (aij, vj)| acc.add(&ntt_mul_a(aij, vj, table), q))
        })
        .collect()
}

fn scalar_vec_mul(c: &Poly, v: &[Poly], table: &NttTable) -> Vec<Poly> {
    v.iter().map(|p| ntt_mul(c, p, table)).collect()
}

fn vec_add(a: &[Poly], b: &[Poly], q: i32) -> Vec<Poly> {
    a.iter().zip(b.iter()).map(|(x, y)| x.add(y, q)).collect()
}

fn vec_sub(a: &[Poly], b: &[Poly], q: i32) -> Vec<Poly> {
    a.iter().zip(b.iter()).map(|(x, y)| x.sub(y, q)).collect()
}

fn vec_neg(a: &[Poly], q: i32) -> Vec<Poly> {
    let zero: Vec<Poly> = a.iter().map(|_| Poly::zero()).collect();
    vec_sub(&zero, a, q)
}

fn high_bits_hash_bytes(w1: &[Poly], gamma2: i32, q: i32) -> Vec<u8> {
    let m = (q - 1) / (2 * gamma2);
    crate::dsa_encode::encode_poly_vec(w1, bits_for_q(m))
}

/// Lets the caller substitute any of the three hash-derived keygen seeds with a chosen value,
/// bypassing the `H(xi||k||l, 1024)` squeeze for that one â€” e.g. supplying `rho` directly hands
/// `ExpandA` an arbitrary matrix A that was never actually derived from `xi` at all. Purely a
/// research/fault-injection affordance for the custom engine; `None` in every field reproduces
/// the normal derivation exactly. Field names follow FIPS 204: `(rho, rho_prime, cap_k) =
/// H(xi||k||l, 1024)`, rho âˆˆ {0,1}^256, rho_prime âˆˆ {0,1}^512, cap_k âˆˆ {0,1}^256.
#[derive(Clone, Default)]
pub struct KeygenOverrides {
    pub rho: Option<[u8; 32]>,
    pub cap_k: Option<[u8; 32]>,
    pub rho_prime: Option<[u8; 64]>,
}

pub fn keygen(params: &GenericDsaParams, xi: [u8; 32]) -> (SigningKey, VerifyingKey) {
    let (sk, vk, _) = keygen_with_overrides(params, xi, &KeygenOverrides::default());
    (sk, vk)
}

/// Resolved seeds are echoed back to the caller (`dsa.rs`) regardless of whether they came from
/// `xi` or an override, so the CLI can report exactly what was used for a given run.
pub struct ResolvedSeeds {
    pub rho: [u8; 32],
    pub cap_k: [u8; 32],
    pub rho_prime: [u8; 64],
}

pub fn keygen_with_overrides(
    params: &GenericDsaParams,
    xi: [u8; 32],
    overrides: &KeygenOverrides,
) -> (SigningKey, VerifyingKey, ResolvedSeeds) {
    let table = build_table(params.q).expect("q already validated by dsa_params::build_params");
    let (k, l) = (params.k as usize, params.l as usize);

    // FIPS 204 Algorithm 6: (rho, rho', K) = H(xi || IntegerToBytes(k,1) || IntegerToBytes(l,1), 1024) â€”
    // one continuous SHAKE256 squeeze, not three independent nonce-indexed calls.
    let mut hasher = Shake256::default();
    hasher.update(&xi);
    hasher.update(&[k as u8]);
    hasher.update(&[l as u8]);
    let mut reader = hasher.finalize_xof();
    let mut rho_derived = [0u8; 32];
    reader.read(&mut rho_derived);
    let mut rho_prime_derived = [0u8; 64];
    reader.read(&mut rho_prime_derived);
    let mut cap_k_derived = [0u8; 32];
    reader.read(&mut cap_k_derived);

    let rho = overrides.rho.unwrap_or(rho_derived);
    let rho_prime = overrides.rho_prime.unwrap_or(rho_prime_derived);
    let cap_k = overrides.cap_k.unwrap_or(cap_k_derived);

    let a = expand_a(&rho, k, l, params.q);

    let s1: Vec<Poly> = (0..l).map(|i| sample_eta(&rho_prime, i as u16, params.eta)).collect();
    let s2: Vec<Poly> = (0..k)
        .map(|i| sample_eta(&rho_prime, (l + i) as u16, params.eta))
        .collect();

    let as1 = mat_vec_mul(&a, &s1, &table, params.q);
    let t = vec_add(&as1, &s2, params.q);

    // FIPS 204: (t1, t0) = Power2Round(t); pk = pkEncode(rho, t1); tr = H(pk, 512).
    let (t1, t0) = power2round_vec(&t, params.q);
    let pk_bytes = encode_pk(&rho, &t1, params);
    let tr = squeeze64(&[&pk_bytes]);

    (
        SigningKey {
            rho,
            cap_k,
            tr,
            s1,
            s2,
            t0,
        },
        VerifyingKey { rho, t1 },
        ResolvedSeeds { rho, cap_k, rho_prime },
    )
}

/// `deterministic`: if false (the spec's default), a fresh random `rnd` is mixed into rho'' for
/// every signature (hedged signing). If true, `rnd = 0` â€” a spec-sanctioned deterministic mode,
/// useful for reproducible testing (including the conformance test below, which needs signatures
/// it can compare byte-for-byte against RustCrypto/libcrux run with the same explicit `rnd`).
pub fn sign(
    params: &GenericDsaParams,
    sk: &SigningKey,
    message: &[u8],
    deterministic: bool,
) -> Result<Signature, String> {
    sign_with_rnd(
        params,
        sk,
        message,
        if deterministic { [0u8; 32] } else { random_bytes(32).try_into().unwrap() },
    )
}

/// Signs with an explicit `rnd` (FIPS 204's hedged-signing randomness) rather than drawing one
/// internally â€” the entry point the conformance test uses to match RustCrypto/libcrux exactly.
pub fn sign_with_rnd(
    params: &GenericDsaParams,
    sk: &SigningKey,
    message: &[u8],
    rnd: [u8; 32],
) -> Result<Signature, String> {
    let table = build_table(params.q).expect("q already validated by dsa_params::build_params");
    let (k, l) = (params.k as usize, params.l as usize);
    let a = expand_a(&sk.rho, k, l, params.q);

    // FIPS 204 Algorithm 2 (ML-DSA.Sign) with an empty context string, matching the plain
    // .sign(message)/sign(key,msg,b"",rnd) entry points RustCrypto's and libcrux's own wrapper
    // crates use (not the bare "internal" algorithm, which skips this wrapping entirely):
    // mu = H(tr || 0x00 || 0x00 || M, 512) — domain-separator byte (0 = not pre-hashed) then
    // context length (0, empty context); no ctx bytes follow since it's empty. rho'' = H(K||rnd||mu, 512).
    let mu = squeeze64(&[&sk.tr, &[0u8], &[0u8], message]);
    let rho_pp = squeeze64(&[&sk.cap_k, &rnd, &mu]);

    let beta = (params.tau * params.eta) as i32;
    let mut kappa: u16 = 0;

    for _ in 0..MAX_SIGN_ATTEMPTS {
        let y = expand_mask(&rho_pp, kappa, params.l, params.gamma1);
        let w = mat_vec_mul(&a, &y, &table, params.q);
        let w1 = high_bits_vec(&w, params.gamma2, params.q);
        let c_tilde = squeeze(&[&mu, &high_bits_hash_bytes(&w1, params.gamma2, params.q)], params.lambda as usize);
        let c = sample_challenge(&c_tilde, params.tau);

        let cs1 = scalar_vec_mul(&c, &sk.s1, &table);
        let z = vec_add(&y, &cs1, params.q);

        kappa = kappa.wrapping_add(params.l as u16);

        if infinity_norm_centered_vec(&z, params.q) >= params.gamma1 - beta {
            continue;
        }

        let cs2 = scalar_vec_mul(&c, &sk.s2, &table);
        let w_minus_cs2 = vec_sub(&w, &cs2, params.q);
        let r0 = low_bits_vec(&w_minus_cs2, params.gamma2, params.q);
        if infinity_norm_centered_vec(&r0, params.q) >= params.gamma2 - beta {
            continue;
        }

        // FIPS 204: ct0 = c*t0; reject if ||ct0||âˆ >= gamma2; hint corrects for -ct0 relative
        // to (w-cs2)+ct0 (recovering HighBits(w) at verify time, which only has t1, not t0).
        let ct0 = scalar_vec_mul(&c, &sk.t0, &table);
        if infinity_norm_centered_vec(&ct0, params.q) >= params.gamma2 {
            continue;
        }
        let neg_ct0 = vec_neg(&ct0, params.q);
        let w_cs2_ct0 = vec_add(&w_minus_cs2, &ct0, params.q);
        let h = make_hint_vec(&neg_ct0, &w_cs2_ct0, params.gamma2, params.q);
        if hint_weight(&h) > params.omega {
            continue;
        }

        return Ok(Signature {
            c_tilde,
            z: to_centered_vec(&z, params.q),
            h,
        });
    }

    Err(format!(
        "sign: no valid signature found within {MAX_SIGN_ATTEMPTS} rejection-sampling attempts \
         (this indicates a bug in the parameter derivation, not an unlucky RNG draw)"
    ))
}

pub fn verify(params: &GenericDsaParams, vk: &VerifyingKey, message: &[u8], sig: &Signature) -> bool {
    let (k, l) = (params.k as usize, params.l as usize);
    if sig.z.len() != l || sig.h.len() != k || sig.c_tilde.len() != params.lambda as usize {
        return false;
    }

    let beta = (params.tau * params.eta) as i32;
    if infinity_norm_centered_vec(&sig.z, params.q) >= params.gamma1 - beta {
        return false;
    }
    if hint_weight(&sig.h) > params.omega {
        return false;
    }

    let table = match build_table(params.q) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let a = expand_a(&vk.rho, k, l, params.q);

    let pk_bytes = encode_pk(&vk.rho, &vk.t1, params);
    let tr = squeeze64(&[&pk_bytes]);
    // Same empty-context ML-DSA.Verify wrapping as sign_with_rnd's mu (see comment there).
    let mu = squeeze64(&[&tr, &[0u8], &[0u8], message]);
    let c = sample_challenge(&sig.c_tilde, params.tau);

    // FIPS 204 Algorithm 8: w' = A*z - c*(t1 << d), d=13 â€” using the compressed t1, not full t.
    let az = mat_vec_mul(&a, &sig.z, &table, params.q);
    let t1_shifted: Vec<Poly> = vk
        .t1
        .iter()
        .map(|p| {
            let mut out = Poly::zero();
            for i in 0..out.coeffs.len() {
                out.coeffs[i] = p.coeffs[i] << 13;
            }
            out
        })
        .collect();
    let ct1 = scalar_vec_mul(&c, &t1_shifted, &table);
    let w_prime = vec_sub(&az, &ct1, params.q);

    let w1_prime = use_hint_vec(&sig.h, &w_prime, params.gamma2, params.q);
    let c_tilde_check = squeeze(&[&mu, &high_bits_hash_bytes(&w1_prime, params.gamma2, params.q)], params.lambda as usize);

    c_tilde_check == sig.c_tilde
}
