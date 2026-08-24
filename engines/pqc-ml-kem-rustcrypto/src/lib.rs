//! Thin wrapper around RustCrypto's `ml-kem` crate, restricted to the three
//! standardized ML-KEM parameter sets (FIPS 203). Private keys are persisted
//! as their 64-byte seed (the crate's preferred serialization); public keys
//! and ciphertexts are persisted in their standard encoded form.

use kem::{Ciphertext, Decapsulate, Encapsulate, FromSeed, Kem, KeyExport, Seed, TryKeyInit};
use ml_kem::{MlKem512, MlKem768, MlKem1024};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Variant {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "ml-kem-512" => Ok(Self::MlKem512),
            "ml-kem-768" => Ok(Self::MlKem768),
            "ml-kem-1024" => Ok(Self::MlKem1024),
            other => Err(format!(
                "unknown ML-KEM variant '{other}' (expected ml-kem-512, ml-kem-768, or ml-kem-1024)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
        }
    }
}

pub struct KeyPair {
    pub sk_seed: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

pub struct Encapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub fn keygen(variant: Variant) -> KeyPair {
    match variant {
        Variant::MlKem512 => keygen_generic::<MlKem512>(),
        Variant::MlKem768 => keygen_generic::<MlKem768>(),
        Variant::MlKem1024 => keygen_generic::<MlKem1024>(),
    }
}

pub fn encapsulate(variant: Variant, pk_bytes: &[u8]) -> Result<Encapsulated, String> {
    match variant {
        Variant::MlKem512 => encapsulate_generic::<MlKem512>(pk_bytes),
        Variant::MlKem768 => encapsulate_generic::<MlKem768>(pk_bytes),
        Variant::MlKem1024 => encapsulate_generic::<MlKem1024>(pk_bytes),
    }
}

pub fn decapsulate(variant: Variant, sk_seed: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    match variant {
        Variant::MlKem512 => decapsulate_generic::<MlKem512>(sk_seed, ciphertext),
        Variant::MlKem768 => decapsulate_generic::<MlKem768>(sk_seed, ciphertext),
        Variant::MlKem1024 => decapsulate_generic::<MlKem1024>(sk_seed, ciphertext),
    }
}

fn keygen_generic<K: Kem + FromSeed>() -> KeyPair {
    let mut seed = Seed::<K>::default();
    getrandom::fill(&mut seed).expect("OS RNG failure");

    let (_dk, ek) = K::from_seed(&seed);

    KeyPair {
        sk_seed: seed.to_vec(),
        pk_bytes: ek.to_bytes().to_vec(),
    }
}

fn encapsulate_generic<K: Kem>(pk_bytes: &[u8]) -> Result<Encapsulated, String> {
    let ek = K::EncapsulationKey::new_from_slice(pk_bytes)
        .map_err(|_| format!("public key has wrong length ({} bytes)", pk_bytes.len()))?;
    let (ct, shared_secret) = ek.encapsulate();

    Ok(Encapsulated {
        ciphertext: ct.to_vec(),
        shared_secret: shared_secret.to_vec(),
    })
}

fn decapsulate_generic<K: Kem + FromSeed>(
    sk_seed: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String>
where
    K::DecapsulationKey: Decapsulate,
{
    let seed = Seed::<K>::try_from(sk_seed).map_err(|_| {
        format!(
            "secret key must be exactly {} bytes, got {}",
            Seed::<K>::default().len(),
            sk_seed.len()
        )
    })?;
    let (dk, _ek) = K::from_seed(&seed);

    let ct = Ciphertext::<K>::try_from(ciphertext)
        .map_err(|_| format!("ciphertext has wrong length ({} bytes)", ciphertext.len()))?;
    let shared_secret = dk.decapsulate(&ct);

    Ok(shared_secret.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(variant: Variant) {
        let kp = keygen(variant);

        let enc = encapsulate(variant, &kp.pk_bytes).expect("encapsulate should succeed");
        let recovered =
            decapsulate(variant, &kp.sk_seed, &enc.ciphertext).expect("decapsulate should succeed");

        assert_eq!(enc.shared_secret, recovered);
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Variant::MlKem512);
        roundtrip(Variant::MlKem768);
        roundtrip(Variant::MlKem1024);
    }
}
