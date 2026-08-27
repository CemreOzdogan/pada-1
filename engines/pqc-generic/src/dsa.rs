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

pub fn keygen(params: &GenericDsaParams) -> KeyPair {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS RNG failure");
    let (sk, vk) = dilithium::keygen(params, seed);

    let sk_bytes = encode_sk(&sk.rho, &sk.k_seed, &sk.tr, &sk.s1, &sk.s2, &sk.t, params);
    let pk_bytes = encode_pk(&vk.rho, &vk.t, params);
    KeyPair { sk_bytes, pk_bytes }
}

pub fn sign(params: &GenericDsaParams, sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let decoded = decode_sk(sk_bytes, params)?;
    let sk = SigningKey {
        rho: decoded.rho,
        k_seed: decoded.k_seed,
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
}
