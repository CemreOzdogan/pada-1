//! Byte-exact conformance test: the actual proof behind this crate's "byte-exact against
//! FIPS 204" doc comments, not just a claim. For all 3 standard ML-DSA parameter sets, builds
//! `GenericDsaParams` via `DsaParamOverrides` set to the exact spec constants, then checks this
//! engine's keygen/sign output is byte-identical to two independent, spec-facing
//! implementations already vendored in this workspace: RustCrypto's `ml-dsa` and Cryspen's
//! `libcrux-ml-dsa`. No internet access here to pull NIST's official ACVP/KAT vectors, so this
//! cross-check is the strongest available substitute.
//!
//! Both reference crates' plain `sign`/`.sign()` entry points use the "external"
//! `ML-DSA.Sign` algorithm with an empty context string and deterministic (`rnd = 0`)
//! randomness — matching this engine's `deterministic: true` signing mode exactly (see
//! `dilithium.rs`'s `mu` computation and its doc comment).

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Seed, Signature as RcSignature, SigningKey as RcSigningKey};

use pqc_generic::dilithium::KeygenOverrides;
use pqc_generic::dsa::{keygen_with_overrides, sign as engine_sign};
use pqc_generic::dsa_params::{build_params, DsaParamOverrides};

const Q: i32 = 8_380_417;
const XI: [u8; 32] = [0x42u8; 32];
const MESSAGE: &[u8] = b"P-KAIDO FIPS 204 conformance message";

#[test]
fn ml_dsa_44_matches_rustcrypto_and_libcrux() {
    let overrides = DsaParamOverrides {
        eta: Some(2),
        gamma2: Some((Q - 1) / 88),
        tau: Some(39),
        omega: Some(80),
        lambda: Some(32),
    };
    let params = build_params(4, 4, Q, 1 << 17, &overrides).expect("ML-DSA-44 params must build");

    let kp = keygen_with_overrides(&params, Some(XI), KeygenOverrides::default());
    let sig_bytes = engine_sign(&params, &kp.sk_bytes, MESSAGE, true).expect("sign should succeed");

    let rc_sk = RcSigningKey::<MlDsa44>::from_seed(&Seed::from(XI));
    let rc_pk = rc_sk.verifying_key().encode().to_vec();
    let rc_sig: RcSignature<MlDsa44> = rc_sk.sign(MESSAGE);
    assert_eq!(kp.pk_bytes, rc_pk, "public key mismatch vs RustCrypto");
    assert_eq!(sig_bytes, rc_sig.encode().to_vec(), "signature mismatch vs RustCrypto");

    let lc_kp = libcrux_ml_dsa::ml_dsa_44::generate_key_pair(XI);
    let lc_randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    let lc_sig = libcrux_ml_dsa::ml_dsa_44::sign(&lc_kp.signing_key, MESSAGE, b"", lc_randomness)
        .expect("libcrux sign should succeed");
    assert_eq!(kp.pk_bytes, lc_kp.verification_key.as_slice().to_vec(), "public key mismatch vs libcrux");
    assert_eq!(sig_bytes, lc_sig.as_slice().to_vec(), "signature mismatch vs libcrux");
}

#[test]
fn ml_dsa_65_matches_rustcrypto_and_libcrux() {
    let overrides = DsaParamOverrides {
        eta: Some(4),
        gamma2: Some((Q - 1) / 32),
        tau: Some(49),
        omega: Some(55),
        lambda: Some(48),
    };
    let params = build_params(6, 5, Q, 1 << 19, &overrides).expect("ML-DSA-65 params must build");

    let kp = keygen_with_overrides(&params, Some(XI), KeygenOverrides::default());
    let sig_bytes = engine_sign(&params, &kp.sk_bytes, MESSAGE, true).expect("sign should succeed");

    let rc_sk = RcSigningKey::<MlDsa65>::from_seed(&Seed::from(XI));
    let rc_pk = rc_sk.verifying_key().encode().to_vec();
    let rc_sig: RcSignature<MlDsa65> = rc_sk.sign(MESSAGE);
    assert_eq!(kp.pk_bytes, rc_pk, "public key mismatch vs RustCrypto");
    assert_eq!(sig_bytes, rc_sig.encode().to_vec(), "signature mismatch vs RustCrypto");

    let lc_kp = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(XI);
    let lc_randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    let lc_sig = libcrux_ml_dsa::ml_dsa_65::sign(&lc_kp.signing_key, MESSAGE, b"", lc_randomness)
        .expect("libcrux sign should succeed");
    assert_eq!(kp.pk_bytes, lc_kp.verification_key.as_slice().to_vec(), "public key mismatch vs libcrux");
    assert_eq!(sig_bytes, lc_sig.as_slice().to_vec(), "signature mismatch vs libcrux");
}

#[test]
fn ml_dsa_87_matches_rustcrypto_and_libcrux() {
    let overrides = DsaParamOverrides {
        eta: Some(2),
        gamma2: Some((Q - 1) / 32),
        tau: Some(60),
        omega: Some(75),
        lambda: Some(64),
    };
    let params = build_params(8, 7, Q, 1 << 19, &overrides).expect("ML-DSA-87 params must build");

    let kp = keygen_with_overrides(&params, Some(XI), KeygenOverrides::default());
    let sig_bytes = engine_sign(&params, &kp.sk_bytes, MESSAGE, true).expect("sign should succeed");

    let rc_sk = RcSigningKey::<MlDsa87>::from_seed(&Seed::from(XI));
    let rc_pk = rc_sk.verifying_key().encode().to_vec();
    let rc_sig: RcSignature<MlDsa87> = rc_sk.sign(MESSAGE);
    assert_eq!(kp.pk_bytes, rc_pk, "public key mismatch vs RustCrypto");
    assert_eq!(sig_bytes, rc_sig.encode().to_vec(), "signature mismatch vs RustCrypto");

    let lc_kp = libcrux_ml_dsa::ml_dsa_87::generate_key_pair(XI);
    let lc_randomness = [0u8; libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE];
    let lc_sig = libcrux_ml_dsa::ml_dsa_87::sign(&lc_kp.signing_key, MESSAGE, b"", lc_randomness)
        .expect("libcrux sign should succeed");
    assert_eq!(kp.pk_bytes, lc_kp.verification_key.as_slice().to_vec(), "public key mismatch vs libcrux");
    assert_eq!(sig_bytes, lc_sig.as_slice().to_vec(), "signature mismatch vs libcrux");
}
