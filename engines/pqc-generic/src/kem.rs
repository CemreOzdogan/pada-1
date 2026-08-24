//! KEM wrap around the K-PKE core, and the timing harness used by `pqc-cli`.
//!
//! TODO (spec fidelity, tracked deliberately — not blocking the milestone-1 skeleton):
//! this wrap hashes (message || ciphertext) into the shared secret but does NOT implement
//! FIPS 203's full Fujisaki-Okamoto transform (deterministic coin derivation from the message,
//! re-encryption to check ciphertext consistency, implicit rejection with a secret `z` on
//! mismatch). That transform is what gives ML-KEM IND-CCA2 security; without it this engine
//! is even further from being real crypto than "unstandardized parameters" alone would imply.
//! Round-trip correctness holds regardless. Byte-exact spec/KAT compliance is the same
//! already-flagged later milestone as elsewhere in this engine.

use std::collections::BTreeMap;
use std::time::Instant;

use pqc_contracts::{BenchResult, Engine, KatResult, ParameterSet, Sizes, TimingStats, Validity};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::params::GenericKemParams;
use crate::pke::{self, Ciphertext, PublicKey, SecretKey};

pub struct EncapsulationKey {
    pk: PublicKey,
}

pub struct DecapsulationKey {
    sk: SecretKey,
}

fn random_32() -> [u8; 32] {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

fn kdf(m: &[u8; 32], ct: &Ciphertext) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(m);
    hasher.update(&ct.u_bytes);
    hasher.update(&ct.v_bytes);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

pub fn kem_keygen(params: &GenericKemParams) -> (DecapsulationKey, EncapsulationKey) {
    let (pk, sk) = pke::keygen(params, random_32());
    (DecapsulationKey { sk }, EncapsulationKey { pk })
}

pub fn kem_encapsulate(params: &GenericKemParams, ek: &EncapsulationKey) -> (Ciphertext, [u8; 32]) {
    let m = random_32();
    let coins = random_32();
    let ct = pke::encrypt(params, &ek.pk, &m, &coins);
    let ss = kdf(&m, &ct);
    (ct, ss)
}

pub fn kem_decapsulate(params: &GenericKemParams, dk: &DecapsulationKey, ct: &Ciphertext) -> [u8; 32] {
    let m = pke::decrypt(params, &dk.sk, ct);
    kdf(&m, ct)
}

/// Run keygen/encapsulate/decapsulate `iterations` times, timing each phase, and report a
/// research-only, engine-tagged [`BenchResult`]. `parameter_set` must have `scheme == ml-kem`
/// and carry `kem` knobs; the caller (pqc-cli) is responsible for building it (from a standard
/// set name or from arbitrary JSON) and validating that it's NTT-valid before calling here.
pub fn bench_generic_kem(parameter_set: ParameterSet, iterations: u64) -> Result<BenchResult, String> {
    let knobs = parameter_set
        .kem
        .as_ref()
        .ok_or("parameter_set has no `kem` knobs")?;
    let params = GenericKemParams {
        k: knobs.k,
        eta1: knobs.eta1,
        eta2: knobs.eta2,
        du: knobs.du,
        dv: knobs.dv,
    };

    let mut keygen_ns = Vec::with_capacity(iterations as usize);
    let mut encaps_ns = Vec::with_capacity(iterations as usize);
    let mut decaps_ns = Vec::with_capacity(iterations as usize);
    let mut roundtrip_ok = true;
    let (mut pk_len, mut sk_len, mut ct_len) = (0u32, 0u32, 0u32);

    // Warmup
    let (dk, ek) = kem_keygen(&params);
    let (ct, ss) = kem_encapsulate(&params, &ek);
    let _ = kem_decapsulate(&params, &dk, &ct);
    let _ = ss;

    for _ in 0..iterations {
        let t0 = Instant::now();
        let (dk_i, ek_i) = kem_keygen(&params);
        keygen_ns.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let (ct_i, ss_send) = kem_encapsulate(&params, &ek_i);
        encaps_ns.push(t1.elapsed().as_nanos() as f64);

        let t2 = Instant::now();
        let ss_recv = kem_decapsulate(&params, &dk_i, &ct_i);
        decaps_ns.push(t2.elapsed().as_nanos() as f64);

        roundtrip_ok &= ss_send == ss_recv;
        pk_len = pke::encode_pk_bytes(&ek_i.pk).len() as u32;
        sk_len = pke::encode_sk_bytes(&dk_i.sk).len() as u32;
        ct_len = (ct_i.u_bytes.len() + ct_i.v_bytes.len()) as u32;
    }

    let mut timings_ns = BTreeMap::new();
    timings_ns.insert("keygen".to_string(), stats(keygen_ns));
    timings_ns.insert("encaps".to_string(), stats(encaps_ns));
    timings_ns.insert("decaps".to_string(), stats(decaps_ns));

    Ok(BenchResult {
        engine: Engine::Generic,
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
