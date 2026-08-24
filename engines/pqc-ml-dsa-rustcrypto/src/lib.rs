//! Thin wrapper around RustCrypto's `ml-dsa` crate, restricted to the three
//! standardized ML-DSA parameter sets (FIPS 204). Private keys are persisted
//! as their 32-byte seed (the crate's preferred serialization); public keys
//! and signatures are persisted in their standard encoded form.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Seed,
    Signature, SigningKey, VerifyingKey,
};
use signature::{Keypair, Signer, Verifier};

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
        Variant::MlDsa44 => keygen_generic::<MlDsa44>(),
        Variant::MlDsa65 => keygen_generic::<MlDsa65>(),
        Variant::MlDsa87 => keygen_generic::<MlDsa87>(),
    }
}

pub fn sign(variant: Variant, sk_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    match variant {
        Variant::MlDsa44 => sign_generic::<MlDsa44>(sk_seed, message),
        Variant::MlDsa65 => sign_generic::<MlDsa65>(sk_seed, message),
        Variant::MlDsa87 => sign_generic::<MlDsa87>(sk_seed, message),
    }
}

pub fn verify(
    variant: Variant,
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, String> {
    match variant {
        Variant::MlDsa44 => verify_generic::<MlDsa44>(pk_bytes, message, sig_bytes),
        Variant::MlDsa65 => verify_generic::<MlDsa65>(pk_bytes, message, sig_bytes),
        Variant::MlDsa87 => verify_generic::<MlDsa87>(pk_bytes, message, sig_bytes),
    }
}

fn keygen_generic<P: MlDsaParams>() -> KeyPair {
    let mut seed_bytes = [0u8; 32];
    getrandom::fill(&mut seed_bytes).expect("OS RNG failure");
    let seed = Seed::from(seed_bytes);

    let sk = SigningKey::<P>::from_seed(&seed);
    let vk = sk.verifying_key();

    KeyPair {
        sk_seed: seed.to_vec(),
        pk_bytes: vk.encode().to_vec(),
    }
}

fn sign_generic<P: MlDsaParams>(sk_seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let seed = Seed::try_from(sk_seed).map_err(|_| {
        format!(
            "signing key must be exactly 32 bytes, got {}",
            sk_seed.len()
        )
    })?;
    let sk = SigningKey::<P>::from_seed(&seed);
    let sig: Signature<P> = sk.sign(message);
    Ok(sig.encode().to_vec())
}

fn verify_generic<P: MlDsaParams>(
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, String> {
    let enc_vk = EncodedVerifyingKey::<P>::try_from(pk_bytes)
        .map_err(|_| format!("public key has wrong length ({} bytes)", pk_bytes.len()))?;
    let vk = VerifyingKey::<P>::decode(&enc_vk);

    let enc_sig = EncodedSignature::<P>::try_from(sig_bytes)
        .map_err(|_| format!("signature has wrong length ({} bytes)", sig_bytes.len()))?;
    let sig = Signature::<P>::decode(&enc_sig).ok_or("signature failed to decode")?;

    Ok(vk.verify(message, &sig).is_ok())
}

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
