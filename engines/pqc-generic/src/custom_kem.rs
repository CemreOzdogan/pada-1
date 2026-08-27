//! KEM wrap around the custom `custom_kem_pke` core, plus the public byte-level API consumed
//! by `pqc-cli`, mirroring `dsa.rs`'s shape (`KeyPair`/`keygen`/... plus a `bench_*` harness).
//!
//! TODO (spec fidelity, tracked deliberately — same posture as `kem.rs`): this wrap hashes
//! (message || ciphertext) into the shared secret but does NOT implement FIPS 203's full
//! Fujisaki-Okamoto transform (deterministic coin derivation from the message, re-encryption
//! check, implicit rejection). Round-trip correctness holds regardless; this is not IND-CCA2
//! secure, consistent with this crate's existing "structurally faithful, research-only" posture.

use std::collections::BTreeMap;
use std::time::Instant;

use pqc_contracts::{BenchResult, Engine, KatResult, ParameterSet, Sizes, TimingStats, Validity};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::custom_kem_encode::{decode_pk, decode_sk, encode_pk, encode_sk};
use crate::custom_kem_params::GenericCustomKemParams;
use crate::custom_kem_pke::{self, Ciphertext, PublicKey, SecretKey};

pub struct KeyPair {
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

fn kdf(m: &[u8], ct: &Ciphertext) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(m);
    hasher.update(&ct.u_bytes);
    hasher.update(&ct.v_bytes);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn ciphertext_lengths(params: &GenericCustomKemParams) -> (usize, usize) {
    let u_len = (params.du as usize * params.n * params.k as usize).div_ceil(8);
    let v_len = (params.dv as usize * params.n).div_ceil(8);
    (u_len, v_len)
}

pub fn keygen(params: &GenericCustomKemParams) -> KeyPair {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS RNG failure");
    let (pk, sk) = custom_kem_pke::keygen(params, seed);

    KeyPair {
        sk_bytes: encode_sk(&sk.s, params),
        pk_bytes: encode_pk(&pk.rho, &pk.t, params),
    }
}

/// Returns (ciphertext_bytes, shared_secret_bytes).
pub fn encapsulate(params: &GenericCustomKemParams, pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (rho, t) = decode_pk(pk_bytes, params)?;
    let pk = PublicKey { rho, t };

    let mut m = vec![0u8; params.n.div_ceil(8)];
    getrandom::fill(&mut m).expect("OS RNG failure");
    let mut coins = [0u8; 32];
    getrandom::fill(&mut coins).expect("OS RNG failure");

    let ct = custom_kem_pke::encrypt(params, &pk, &m, &coins);
    let ss = kdf(&m, &ct);

    let mut ct_bytes = ct.u_bytes;
    ct_bytes.extend(ct.v_bytes);
    Ok((ct_bytes, ss.to_vec()))
}

pub fn decapsulate(params: &GenericCustomKemParams, sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let s = decode_sk(sk_bytes, params)?;
    let sk = SecretKey { s };

    let (u_len, v_len) = ciphertext_lengths(params);
    if ct_bytes.len() != u_len + v_len {
        return Err(format!(
            "ciphertext has wrong length: expected {} bytes, got {}",
            u_len + v_len,
            ct_bytes.len()
        ));
    }
    let ct = Ciphertext {
        u_bytes: ct_bytes[..u_len].to_vec(),
        v_bytes: ct_bytes[u_len..].to_vec(),
    };

    let m = custom_kem_pke::decrypt(params, &sk, &ct);
    Ok(kdf(&m, &ct).to_vec())
}

/// Run keygen/encapsulate/decapsulate `iterations` times, timing each phase, and report a
/// research-only, engine-tagged [`BenchResult`]. `parameter_set` must have `scheme == ml-kem`
/// and carry `kem` knobs plus `n`/`q`.
pub fn bench_generic_custom_kem(parameter_set: ParameterSet, iterations: u64) -> Result<BenchResult, String> {
    let knobs = parameter_set
        .kem
        .as_ref()
        .ok_or("parameter_set has no `kem` knobs")?;
    let params = GenericCustomKemParams {
        k: knobs.k,
        n: parameter_set.n as usize,
        q: parameter_set.q as i32,
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
    let kp = keygen(&params);
    let (ct, ss) = encapsulate(&params, &kp.pk_bytes)?;
    let ss2 = decapsulate(&params, &kp.sk_bytes, &ct)?;
    let _ = (ss, ss2);

    for _ in 0..iterations {
        let t0 = Instant::now();
        let kp_i = keygen(&params);
        keygen_ns.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let (ct_i, ss_send) = encapsulate(&params, &kp_i.pk_bytes)?;
        encaps_ns.push(t1.elapsed().as_nanos() as f64);

        let t2 = Instant::now();
        let ss_recv = decapsulate(&params, &kp_i.sk_bytes, &ct_i)?;
        decaps_ns.push(t2.elapsed().as_nanos() as f64);

        roundtrip_ok &= ss_send == ss_recv;
        pk_len = kp_i.pk_bytes.len() as u32;
        sk_len = kp_i.sk_bytes.len() as u32;
        ct_len = ct_i.len() as u32;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom_kem_params::build_params;

    fn roundtrip(params: &GenericCustomKemParams, trials: usize) {
        for _ in 0..trials {
            let kp = keygen(params);
            let (ct, ss_send) = encapsulate(params, &kp.pk_bytes).expect("encapsulate should succeed");
            let ss_recv = decapsulate(params, &kp.sk_bytes, &ct).expect("decapsulate should succeed");
            assert_eq!(ss_send, ss_recv, "shared secrets should match on a genuine roundtrip");
        }
    }

    #[test]
    fn roundtrip_custom_kem_512_shaped() {
        let params = build_params(2, 256, 7681).unwrap();
        roundtrip(&params, 20);
    }

    #[test]
    fn roundtrip_custom_kem_smaller_ring() {
        let params = build_params(3, 128, 12289).unwrap();
        roundtrip(&params, 20);
    }

    #[test]
    fn decapsulate_with_wrong_key_gives_different_secret() {
        let params = build_params(2, 256, 7681).unwrap();
        let kp_a = keygen(&params);
        let kp_b = keygen(&params);
        let (ct, ss_send) = encapsulate(&params, &kp_a.pk_bytes).unwrap();
        let ss_wrong = decapsulate(&params, &kp_b.sk_bytes, &ct).unwrap();
        assert_ne!(ss_send, ss_wrong);
    }
}
