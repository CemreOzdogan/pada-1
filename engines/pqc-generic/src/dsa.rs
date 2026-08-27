//! Public API for the custom ML-DSA engine, mirroring `pqc-ml-dsa-rustcrypto`'s shape
//! (`KeyPair`/`keygen`/`sign`/`verify`) plus a `kem.rs`-style timing-harness entry point.

use std::collections::BTreeMap;
use std::time::Instant;

use pqc_contracts::{BenchResult, Engine, KatResult, ParameterSet, Sizes, TimingStats, Validity};

use crate::dilithium::{self, Signature, SigningKey, VerifyingKey};
use crate::dsa_encode::{decode_pk, decode_sig, decode_sk, encode_pk, encode_sig, encode_sk};
use crate::dsa_params::GenericDsaParams;

pub struct KeyPair {
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

/// `keygen_with_overrides`'s result: the byte-encoded keypair plus every seed actually used
/// (whether it came from `xi`/an override or was derived), so a caller doing fault-injection
/// experiments can see and report exactly what fed into `ExpandA`/the noise sampling. Field
/// names follow FIPS 204: `xi` is the master seed, `(rho, rho_prime, cap_k) = H(xi, 1024)`.
pub struct KeyPairWithSeeds {
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Vec<u8>,
    pub xi: [u8; 32],
    pub rho: [u8; 32],
    pub cap_k: [u8; 32],
    pub rho_prime: [u8; 32],
}

pub fn keygen(params: &GenericDsaParams) -> KeyPair {
    let kp = keygen_with_overrides(params, None, dilithium::KeygenOverrides::default());
    KeyPair {
        sk_bytes: kp.sk_bytes,
        pk_bytes: kp.pk_bytes,
    }
}

/// `xi`: the master 256-bit seed, or `None` to draw one from the OS RNG. `overrides`: lets any
/// of rho/cap_k/rho_prime bypass `SHAKE256(xi, nonce)` entirely and use a chosen value instead
/// — see `dilithium::KeygenOverrides`.
pub fn keygen_with_overrides(
    params: &GenericDsaParams,
    xi: Option<[u8; 32]>,
    overrides: dilithium::KeygenOverrides,
) -> KeyPairWithSeeds {
    let xi = xi.unwrap_or_else(|| {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).expect("OS RNG failure");
        s
    });
    let (sk, vk, resolved) = dilithium::keygen_with_overrides(params, xi, &overrides);

    let sk_bytes = encode_sk(&sk.rho, &sk.cap_k, &sk.tr, &sk.s1, &sk.s2, &sk.t, params);
    let pk_bytes = encode_pk(&vk.rho, &vk.t, params);
    KeyPairWithSeeds {
        sk_bytes,
        pk_bytes,
        xi,
        rho: resolved.rho,
        cap_k: resolved.cap_k,
        rho_prime: resolved.rho_prime,
    }
}

pub fn sign(params: &GenericDsaParams, sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let decoded = decode_sk(sk_bytes, params)?;
    let sk = SigningKey {
        rho: decoded.rho,
        cap_k: decoded.cap_k,
        tr: decoded.tr,
        s1: decoded.s1,
        s2: decoded.s2,
        t: decoded.t,
    };
    let sig = dilithium::sign(params, &sk, message)?;
    Ok(encode_sig(&sig.c_tilde, &sig.z, &sig.h, params))
}

pub fn verify(
    params: &GenericDsaParams,
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, String> {
    let (rho, t) = decode_pk(pk_bytes, params)?;
    let vk = VerifyingKey { rho, t };
    let (c_tilde, z, h) = decode_sig(sig_bytes, params)?;
    let sig = Signature { c_tilde, z, h };
    Ok(dilithium::verify(params, &vk, message, &sig))
}

/// Run keygen/sign/verify `iterations` times, timing each phase, and report a research-only,
/// engine-tagged [`BenchResult`]. `parameter_set` must have `scheme == ml-dsa` and carry `dsa`
/// knobs plus `n`/`q`; the caller (pqc-cli) builds and validates it before calling here.
pub fn bench_generic_dsa(parameter_set: ParameterSet, iterations: u64) -> Result<BenchResult, String> {
    let dsa_knobs = parameter_set
        .dsa
        .as_ref()
        .ok_or("parameter_set has no `dsa` knobs")?;
    let params = GenericDsaParams {
        k: dsa_knobs.k,
        l: dsa_knobs.l,
        q: parameter_set.q as i32,
        eta: dsa_knobs.eta,
        gamma1: dsa_knobs.gamma1 as i32,
        gamma2: dsa_knobs.gamma2 as i32,
        tau: dsa_knobs.tau,
        omega: dsa_knobs.omega,
    };

    let message = b"P-KAIDO bench message";

    let mut keygen_ns = Vec::with_capacity(iterations as usize);
    let mut sign_ns = Vec::with_capacity(iterations as usize);
    let mut verify_ns = Vec::with_capacity(iterations as usize);
    let mut roundtrip_ok = true;
    let (mut pk_len, mut sk_len, mut sig_len) = (0u32, 0u32, 0u32);

    // Warmup
    let kp = keygen(&params);
    let sig = sign(&params, &kp.sk_bytes, message)?;
    let _ = verify(&params, &kp.pk_bytes, message, &sig)?;

    for _ in 0..iterations {
        let t0 = Instant::now();
        let kp_i = keygen(&params);
        keygen_ns.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let sig_i = sign(&params, &kp_i.sk_bytes, message)?;
        sign_ns.push(t1.elapsed().as_nanos() as f64);

        let t2 = Instant::now();
        let valid = verify(&params, &kp_i.pk_bytes, message, &sig_i)?;
        verify_ns.push(t2.elapsed().as_nanos() as f64);

        roundtrip_ok &= valid;
        pk_len = kp_i.pk_bytes.len() as u32;
        sk_len = kp_i.sk_bytes.len() as u32;
        sig_len = sig_i.len() as u32;
    }

    let mut timings_ns = BTreeMap::new();
    timings_ns.insert("keygen".to_string(), stats(keygen_ns));
    timings_ns.insert("sign".to_string(), stats(sign_ns));
    timings_ns.insert("verify".to_string(), stats(verify_ns));

    Ok(BenchResult {
        engine: Engine::Generic,
        parameter_set,
        timings_ns,
        sizes_bytes: Sizes {
            pk: pk_len,
            sk: sk_len,
            ct: None,
            sig: Some(sig_len),
        },
        validity: Validity {
            roundtrip: roundtrip_ok,
            kat: KatResult::Na,
        },
        engine_version: Some(format!("pqc-generic {}", env!("CARGO_PKG_VERSION"))),
    })
}

fn stats(mut samples: Vec<f64>) -> TimingStats {
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / n;
    let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = samples[samples.len() / 2];
    TimingStats {
        median,
        mean,
        stddev: variance.sqrt(),
        samples: samples.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa_params::build_params;

    fn roundtrip(params: &GenericDsaParams) {
        let kp = keygen(params);
        let msg = b"P-KAIDO smoke test message";

        let sig = sign(params, &kp.sk_bytes, msg).expect("sign should succeed");
        assert!(
            verify(params, &kp.pk_bytes, msg, &sig).expect("verify should not error"),
            "genuine signature should verify"
        );

        let tampered = b"P-KAIDO smoke test message!";
        assert!(
            !verify(params, &kp.pk_bytes, tampered, &sig).expect("verify should not error"),
            "tampered message should not verify"
        );

        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xFF;
        assert!(
            !verify(params, &kp.pk_bytes, msg, &bad_sig).expect("verify should not error"),
            "tampered signature should not verify"
        );
    }

    #[test]
    fn roundtrip_custom_params_dilithium_shaped() {
        let params = build_params(4, 4, 8380417, 131072).unwrap();
        roundtrip(&params);
    }

    #[test]
    fn roundtrip_custom_params_small_q() {
        let params = build_params(2, 2, 12289, 4096).unwrap();
        roundtrip(&params);
    }

    #[test]
    fn same_seed_without_overrides_reproduces_normal_derivation() {
        let params = build_params(2, 2, 12289, 4096).unwrap();
        let seed = [7u8; 32];

        let a = keygen_with_overrides(&params, Some(seed), dilithium::KeygenOverrides::default());
        let b = keygen_with_overrides(&params, Some(seed), dilithium::KeygenOverrides::default());

        assert_eq!(a.rho, b.rho);
        assert_eq!(a.cap_k, b.cap_k);
        assert_eq!(a.rho_prime, b.rho_prime);
        assert_eq!(a.pk_bytes, b.pk_bytes, "same seed, no overrides, should be fully deterministic");
    }

    #[test]
    fn rho_override_bypasses_derivation_from_seed() {
        let params = build_params(2, 2, 12289, 4096).unwrap();
        let seed = [7u8; 32];
        let faulty_rho = [0xAAu8; 32];

        let normal = keygen_with_overrides(&params, Some(seed), dilithium::KeygenOverrides::default());
        let faulted = keygen_with_overrides(
            &params,
            Some(seed),
            dilithium::KeygenOverrides {
                rho: Some(faulty_rho),
                ..Default::default()
            },
        );

        assert_ne!(normal.rho, faulted.rho, "rho override should not match the normally-derived rho");
        assert_eq!(faulted.rho, faulty_rho, "rho override should be used verbatim");
        // cap_k/rho_prime are independent of rho — same seed, no override on those, so they match.
        assert_eq!(normal.cap_k, faulted.cap_k);
        assert_eq!(normal.rho_prime, faulted.rho_prime);
        assert_ne!(normal.pk_bytes, faulted.pk_bytes, "a different rho means a different matrix A, hence a different public key");
    }

    #[test]
    fn faulted_keypair_is_still_internally_consistent() {
        // The point of the override is to see how the RESULT changes when A wasn't honestly
        // derived from seed — not to produce a broken keypair. Sign/verify must still round-trip.
        let params = build_params(2, 2, 12289, 4096).unwrap();
        let kp = keygen_with_overrides(
            &params,
            Some([1u8; 32]),
            dilithium::KeygenOverrides {
                rho: Some([0x42u8; 32]),
                cap_k: Some([0x43u8; 32]),
                rho_prime: Some([0x44u8; 32]),
            },
        );

        let msg = b"faulted keygen smoke test";
        let sig = sign(&params, &kp.sk_bytes, msg).expect("sign should still succeed with a faulted key");
        assert!(verify(&params, &kp.pk_bytes, msg, &sig).expect("verify should not error"));
    }
}
