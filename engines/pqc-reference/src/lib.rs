//! Thin wrapper around the RustCrypto `ml-kem` crate — the six standardized ML-KEM sets only.
//! Ground-truth performance. Never modified to accept non-standard parameters; that's what
//! `pqc-generic` is for.

use std::time::Instant;

use ml_kem::{
    MlKem512, MlKem1024, MlKem768,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeySizeUser},
};
use pqc_contracts::{
    BenchResult, Engine, KatResult, KemKnobs, ParameterSet, Scheme, Sizes, TimingStats, Validity,
};
use std::collections::BTreeMap;

/// Benchmark one of the six standardized ML-KEM sets via RustCrypto's crate.
///
/// # Errors
/// If `set` is not one of `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`.
pub fn bench_ml_kem(set: &str, iterations: u64) -> Result<BenchResult, String> {
    match set {
        "ml-kem-512" => Ok(run::<MlKem512>(param_set_512(), iterations)),
        "ml-kem-768" => Ok(run::<MlKem768>(param_set_768(), iterations)),
        "ml-kem-1024" => Ok(run::<MlKem1024>(param_set_1024(), iterations)),
        other => Err(format!(
            "unknown reference set '{other}' (expected ml-kem-512, ml-kem-768, or ml-kem-1024)"
        )),
    }
}

fn run<K>(parameter_set: ParameterSet, iterations: u64) -> BenchResult
where
    K: Kem,
    K::DecapsulationKey: Decapsulate + KeyExport + KeySizeUser,
    K::EncapsulationKey: KeyExport + KeySizeUser,
{
    // Warmup: let branch predictors/caches settle before the timed loop.
    let (dk, ek) = K::generate_keypair();
    let (ct, _) = ek.encapsulate();
    let mut ct_len = ct.len() as u32;
    let _ = dk.decapsulate(&ct);

    let mut keygen_ns = Vec::with_capacity(iterations as usize);
    let mut encaps_ns = Vec::with_capacity(iterations as usize);
    let mut decaps_ns = Vec::with_capacity(iterations as usize);
    let mut roundtrip_ok = true;

    for _ in 0..iterations {
        let t0 = Instant::now();
        let (dk_i, ek_i) = K::generate_keypair();
        keygen_ns.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let (ct_i, k_send) = ek_i.encapsulate();
        encaps_ns.push(t1.elapsed().as_nanos() as f64);

        let t2 = Instant::now();
        let k_recv = dk_i.decapsulate(&ct_i);
        decaps_ns.push(t2.elapsed().as_nanos() as f64);

        roundtrip_ok &= k_send == k_recv;
        ct_len = ct_i.len() as u32;
    }

    let pk_len = K::EncapsulationKey::key_size() as u32;
    let sk_len = K::DecapsulationKey::key_size() as u32;

    let mut timings_ns = BTreeMap::new();
    timings_ns.insert("keygen".to_string(), stats(keygen_ns));
    timings_ns.insert("encaps".to_string(), stats(encaps_ns));
    timings_ns.insert("decaps".to_string(), stats(decaps_ns));

    BenchResult {
        engine: Engine::Reference,
        parameter_set,
        timings_ns,
        sizes_bytes: Sizes {
            pk: pk_len,
            sk: sk_len,
            ct: Some(ct_len),
            sig: None,
        },
        validity: Validity {
            roundtrip: roundtrip_ok,
            kat: KatResult::Na,
        },
        engine_version: Some(format!("ml-kem {}", env!("CARGO_PKG_VERSION"))),
    }
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

fn param_set_512() -> ParameterSet {
    ParameterSet {
        scheme: Scheme::MlKem,
        name: Some("ML-KEM-512".to_string()),
        is_standard: true,
        n: 256,
        q: 3329,
        kem: Some(KemKnobs {
            k: 2,
            eta1: 3,
            eta2: 2,
            du: 10,
            dv: 4,
        }),
        dsa: None,
    }
}

fn param_set_768() -> ParameterSet {
    ParameterSet {
        scheme: Scheme::MlKem,
        name: Some("ML-KEM-768".to_string()),
        is_standard: true,
        n: 256,
        q: 3329,
        kem: Some(KemKnobs {
            k: 3,
            eta1: 2,
            eta2: 2,
            du: 10,
            dv: 4,
        }),
        dsa: None,
    }
}

fn param_set_1024() -> ParameterSet {
    ParameterSet {
        scheme: Scheme::MlKem,
        name: Some("ML-KEM-1024".to_string()),
        is_standard: true,
        n: 256,
        q: 3329,
        kem: Some(KemKnobs {
            k: 4,
            eta1: 2,
            eta2: 2,
            du: 11,
            dv: 5,
        }),
        dsa: None,
    }
}
