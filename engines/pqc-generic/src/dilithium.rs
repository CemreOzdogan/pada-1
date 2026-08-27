//! Dilithium-shaped ML-DSA orchestration: keygen / sign (full Fiat-Shamir-with-aborts
//! rejection loop) / verify, over a runtime-chosen `GenericDsaParams`. Structurally faithful
//! to FIPS 204 (matrix/vector shapes, CBD-generalized noise, high/low-bit decomposition,
//! hint mechanism) but NOT byte-exact spec compliance: the public key stores the full `t`
//! rather than the compressed `t1`/`t0` split, and signing is deterministic (no hedged
//! randomness mixed into rho'). Same "structurally faithful, not spec-exact, research-only"
//! posture this crate's KEM engine (`kem.rs`) already documents for its own simplifications.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::dsa_encode::encode_poly_vec;
use crate::dsa_params::GenericDsaParams;
use crate::dsa_rounding::{
    high_bits_vec, hint_weight, infinity_norm_centered_vec, low_bits_vec, make_hint_vec,
    to_centered_vec, use_hint_vec, Hint,
};
use crate::dsa_sample::{expand_mask, sample_challenge, sample_eta, sample_uniform_wide};
use crate::encode::bits_for_q;
use crate::ntt::{build_table, ntt_mul, NttTable};
use crate::poly::Poly;
use crate::sample::prf;

const MAX_SIGN_ATTEMPTS: u32 = 100_000;

pub struct SigningKey {
    pub rho: [u8; 32],
    pub k_seed: [u8; 32],
    pub tr: [u8; 32],
    pub s1: Vec<Poly>,
    pub s2: Vec<Poly>,
    pub t: Vec<Poly>,
}

pub struct VerifyingKey {
    pub rho: [u8; 32],
    pub t: Vec<Poly>,
}

pub struct Signature {
    pub c_tilde: [u8; 32],
    pub z: Vec<Poly>,
    pub h: Hint,
}

fn derive32(seed: &[u8; 32], nonce: u8) -> [u8; 32] {
    prf(seed, nonce, 32).try_into().unwrap()
}

fn hash32(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    for p in parts {
        hasher.update(p);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn expand_a(rho: &[u8; 32], k: usize, l: usize, q: i32) -> Vec<Vec<Poly>> {
    (0..k)
        .map(|i| {
            (0..l)
                .map(|j| sample_uniform_wide(rho, i as u8, j as u8, q))
                .collect()
        })
        .collect()
}

/// k x l matrix times an l-length vector, entrywise via NTT multiplication.
fn mat_vec_mul(a: &[Vec<Poly>], v: &[Poly], table: &NttTable, q: i32) -> Vec<Poly> {
    a.iter()
        .map(|row| {
            row.iter()
                .zip(v.iter())
                .fold(Poly::zero(), |acc, (aij, vj)| acc.add(&ntt_mul(aij, vj, table), q))
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

fn tr_of(rho: &[u8; 32], t: &[Poly], q: i32) -> [u8; 32] {
    let t_bytes = encode_poly_vec(t, bits_for_q(q));
    hash32(&[rho, &t_bytes])
}

fn high_bits_hash_bytes(w1: &[Poly], gamma2: i32, q: i32) -> Vec<u8> {
    let m = (q - 1) / (2 * gamma2);
    encode_poly_vec(w1, bits_for_q(m))
}

/// Lets the caller substitute any of the three hash-derived keygen seeds with a chosen 32-byte
/// value, bypassing `derive32(seed, nonce)` for that one — e.g. supplying `rho` directly hands
/// `ExpandA` an arbitrary matrix A that was never actually derived from `seed` at all. Purely a
/// research/fault-injection affordance for the custom engine; `None` in every field reproduces
/// the normal derivation exactly.
#[derive(Clone, Copy, Default)]
pub struct KeygenOverrides {
    pub rho: Option<[u8; 32]>,
    pub k_seed: Option<[u8; 32]>,
    pub sigma: Option<[u8; 32]>,
}

pub fn keygen(params: &GenericDsaParams, seed: [u8; 32]) -> (SigningKey, VerifyingKey) {
    let (sk, vk, _) = keygen_with_overrides(params, seed, &KeygenOverrides::default());
    (sk, vk)
}

/// Resolved seeds are echoed back to the caller (`dsa.rs`) regardless of whether they came from
/// `seed` or an override, so the CLI can report exactly what was used for a given run.
pub struct ResolvedSeeds {
    pub rho: [u8; 32],
    pub k_seed: [u8; 32],
    pub sigma: [u8; 32],
}

pub fn keygen_with_overrides(
    params: &GenericDsaParams,
    seed: [u8; 32],
    overrides: &KeygenOverrides,
) -> (SigningKey, VerifyingKey, ResolvedSeeds) {
    let table = build_table(params.q).expect("q already validated by dsa_params::build_params");
    let (k, l) = (params.k as usize, params.l as usize);

    let rho = overrides.rho.unwrap_or_else(|| derive32(&seed, 0));
    let k_seed = overrides.k_seed.unwrap_or_else(|| derive32(&seed, 1));
    let sigma = overrides.sigma.unwrap_or_else(|| derive32(&seed, 2));

    let a = expand_a(&rho, k, l, params.q);

    let s1: Vec<Poly> = (0..l).map(|i| sample_eta(&sigma, i as u16, params.eta)).collect();
    let s2: Vec<Poly> = (0..k)
        .map(|i| sample_eta(&sigma, (l + i) as u16, params.eta))
        .collect();

    let as1 = mat_vec_mul(&a, &s1, &table, params.q);
    let t = vec_add(&as1, &s2, params.q);

    let tr = tr_of(&rho, &t, params.q);

    (
        SigningKey {
            rho,
            k_seed,
            tr,
            s1,
            s2,
            t: t.clone(),
        },
        VerifyingKey { rho, t },
        ResolvedSeeds { rho, k_seed, sigma },
    )
}

pub fn sign(params: &GenericDsaParams, sk: &SigningKey, message: &[u8]) -> Result<Signature, String> {
    let table = build_table(params.q).expect("q already validated by dsa_params::build_params");
    let (k, l) = (params.k as usize, params.l as usize);
    let a = expand_a(&sk.rho, k, l, params.q);

    let mu = hash32(&[&sk.tr, message]);
    let rho_prime = hash32(&[&sk.k_seed, &mu]);

    let beta = (params.tau * params.eta) as i32;
    let mut kappa: u16 = 0;

    for _ in 0..MAX_SIGN_ATTEMPTS {
        let y = expand_mask(&rho_prime, kappa, params.l, params.gamma1);
        let w = mat_vec_mul(&a, &y, &table, params.q);
        let w1 = high_bits_vec(&w, params.gamma2, params.q);
        let c_tilde = hash32(&[&mu, &high_bits_hash_bytes(&w1, params.gamma2, params.q)]);
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

        let h = make_hint_vec(&cs2, &w_minus_cs2, params.gamma2, params.q);
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
    if sig.z.len() != l || sig.h.len() != k {
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

    let tr = tr_of(&vk.rho, &vk.t, params.q);
    let mu = hash32(&[&tr, message]);
    let c = sample_challenge(&sig.c_tilde, params.tau);

    let az = mat_vec_mul(&a, &sig.z, &table, params.q);
    let ct = scalar_vec_mul(&c, &vk.t, &table);
    let w_prime = vec_sub(&az, &ct, params.q);

    let w1_prime = use_hint_vec(&sig.h, &w_prime, params.gamma2, params.q);
    let c_tilde_check = hash32(&[&mu, &high_bits_hash_bytes(&w1_prime, params.gamma2, params.q)]);

    c_tilde_check == sig.c_tilde
}
