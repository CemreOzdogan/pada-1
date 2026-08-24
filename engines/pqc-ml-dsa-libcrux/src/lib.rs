//! Thin wrapper around Cryspen's `libcrux-ml-dsa` crate, restricted to the three
//! standardized ML-DSA parameter sets (FIPS 204). Mirrors the public API of
//! `pqc-ml-dsa-rustcrypto` (same `Variant`/`KeyPair` shape and function
//! signatures) so `pqc-cli` can select either backend interchangeably.
//!
//! `sk_seed` is the original 32-byte keygen randomness (not the expanded
//! signing key), matching what `pqc-ml-dsa-rustcrypto` persists. The full
//! signing key is re-derived from it before every sign, same as that crate's
//! `sign_generic` does with `SigningKey::from_seed`. Signing uses an all-zero
//! `randomness` input — FIPS 204's deterministic variant — so the same
//! `(sk_seed, message)` always produces the same signature, matching
//! RustCrypto's default (deterministic) `Signer` behavior.

use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Variant {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "ml-dsa-44" => Ok(Self::MlDsa44),
            "ml-dsa-65" => Ok(Self::MlDsa65),
            "ml-dsa-87" => Ok(Self::MlDsa87),
            other => Err(format!(
                "unknown ML-DSA variant '{other}' (expected ml-dsa-44, ml-dsa-65, or ml-dsa-87)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }
}

pub struct KeyPair {
    pub sk_seed: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

pub fn keygen(variant: Variant) -> KeyPair {
    match variant {
        Variant::MlDsa44 => keygen_44(),
        Variant::MlDsa65 => keygen_65(),
        Variant::MlDsa87 => keygen_87(),
    }
}

pub fn sign(variant: Variant, sk_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    match variant {
        Variant::MlDsa44 => sign_44(sk_seed, message),
        Variant::MlDsa65 => sign_65(sk_seed, message),
        Variant::MlDsa87 => sign_87(sk_seed, message),
    }
}

pub fn verify(
    variant: Variant,
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, String> {
    match variant {
        Variant::MlDsa44 => verify_44(pk_bytes, message, sig_bytes),
        Variant::MlDsa65 => verify_65(pk_bytes, message, sig_bytes),
        Variant::MlDsa87 => verify_87(pk_bytes, message, sig_bytes),
    }
}

fn random_seed<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

fn seed_from_slice(sk_seed: &[u8]) -> Result<[u8; KEY_GENERATION_RANDOMNESS_SIZE], String> {
    sk_seed.try_into().map_err(|_| {
        format!(
            "signing key must be exactly {KEY_GENERATION_RANDOMNESS_SIZE} bytes, got {}",
            sk_seed.len()
        )
    })
}

macro_rules! impl_variant {
    ($mod_path:ident, $vk_ty:ident, $sig_ty:ident, $keygen_fn:ident, $sign_fn:ident, $verify_fn:ident) => {
        fn $keygen_fn() -> KeyPair {
            let seed = random_seed::<KEY_GENERATION_RANDOMNESS_SIZE>();
            let kp = libcrux_ml_dsa::$mod_path::generate_key_pair(seed);
            KeyPair {
                sk_seed: seed.to_vec(),
                pk_bytes: kp.verification_key.as_slice().to_vec(),
            }
        }

        fn $sign_fn(sk_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            let seed = seed_from_slice(sk_seed)?;
            let kp = libcrux_ml_dsa::$mod_path::generate_key_pair(seed);
            let randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
            let sig = libcrux_ml_dsa::$mod_path::sign(&kp.signing_key, message, b"", randomness)
                .map_err(|e| format!("signing failed: {e:?}"))?;
            Ok(sig.as_slice().to_vec())
        }

        fn $verify_fn(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<bool, String> {
            let vk_arr = <[u8; libcrux_ml_dsa::$mod_path::$vk_ty::len()]>::try_from(pk_bytes)
                .map_err(|_| format!("public key has wrong length ({} bytes)", pk_bytes.len()))?;
            let vk = libcrux_ml_dsa::$mod_path::$vk_ty::new(vk_arr);

            let sig_arr = <[u8; libcrux_ml_dsa::$mod_path::$sig_ty::len()]>::try_from(sig_bytes)
                .map_err(|_| format!("signature has wrong length ({} bytes)", sig_bytes.len()))?;
            let sig = libcrux_ml_dsa::$mod_path::$sig_ty::new(sig_arr);

            Ok(libcrux_ml_dsa::$mod_path::verify(&vk, message, b"", &sig).is_ok())
        }
    };
}

impl_variant!(
    ml_dsa_44,
    MLDSA44VerificationKey,
    MLDSA44Signature,
    keygen_44,
    sign_44,
    verify_44
);
impl_variant!(
    ml_dsa_65,
    MLDSA65VerificationKey,
    MLDSA65Signature,
    keygen_65,
    sign_65,
    verify_65
);
impl_variant!(
    ml_dsa_87,
    MLDSA87VerificationKey,
    MLDSA87Signature,
    keygen_87,
    sign_87,
    verify_87
);

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(variant: Variant) {
        let kp = keygen(variant);
        let msg = b"P-KAIDO smoke test message";

        let sig = sign(variant, &kp.sk_seed, msg).expect("sign should succeed");
        assert!(verify(variant, &kp.pk_bytes, msg, &sig).expect("verify should not error"));

        let tampered = b"P-KAIDO smoke test message!";
        assert!(!verify(variant, &kp.pk_bytes, tampered, &sig).expect("verify should not error"));
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Variant::MlDsa44);
        roundtrip(Variant::MlDsa65);
        roundtrip(Variant::MlDsa87);
    }
}
