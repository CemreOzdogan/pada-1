//! Thin wrapper around Cryspen's `libcrux-ml-kem` crate, restricted to the three
//! standardized ML-KEM parameter sets (FIPS 203). Mirrors the public API of
//! `pqc-ml-kem-rustcrypto` (same `Variant`/`KeyPair`/`Encapsulated` shape and
//! function signatures) so `pqc-cli` can select either backend interchangeably.

use libcrux_ml_kem::{KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE};

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
        Variant::MlKem512 => keygen_512(),
        Variant::MlKem768 => keygen_768(),
        Variant::MlKem1024 => keygen_1024(),
    }
}

pub fn encapsulate(variant: Variant, pk_bytes: &[u8]) -> Result<Encapsulated, String> {
    match variant {
        Variant::MlKem512 => encapsulate_512(pk_bytes),
        Variant::MlKem768 => encapsulate_768(pk_bytes),
        Variant::MlKem1024 => encapsulate_1024(pk_bytes),
    }
}

pub fn decapsulate(variant: Variant, sk_seed: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    match variant {
        Variant::MlKem512 => decapsulate_512(sk_seed, ciphertext),
        Variant::MlKem768 => decapsulate_768(sk_seed, ciphertext),
        Variant::MlKem1024 => decapsulate_1024(sk_seed, ciphertext),
    }
}

fn random_seed<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS RNG failure");
    buf
}

macro_rules! impl_variant {
    ($mod_path:ident, $pk_ty:ident, $sk_ty:ident, $ct_ty:ident, $keygen_fn:ident, $encap_fn:ident, $decap_fn:ident) => {
        fn $keygen_fn() -> KeyPair {
            let seed = random_seed::<KEY_GENERATION_SEED_SIZE>();
            let kp = libcrux_ml_kem::$mod_path::generate_key_pair(seed);
            KeyPair {
                sk_seed: kp.sk().to_vec(),
                pk_bytes: kp.pk().to_vec(),
            }
        }

        fn $encap_fn(pk_bytes: &[u8]) -> Result<Encapsulated, String> {
            let pk = libcrux_ml_kem::$mod_path::$pk_ty::try_from(pk_bytes)
                .map_err(|_| format!("public key has wrong length ({} bytes)", pk_bytes.len()))?;
            let randomness = random_seed::<SHARED_SECRET_SIZE>();
            let (ct, ss) = libcrux_ml_kem::$mod_path::encapsulate(&pk, randomness);
            Ok(Encapsulated {
                ciphertext: ct.as_slice().to_vec(),
                shared_secret: ss.as_slice().to_vec(),
            })
        }

        fn $decap_fn(sk_seed: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            let sk = libcrux_ml_kem::$mod_path::$sk_ty::try_from(sk_seed).map_err(|_| {
                format!("secret key has wrong length ({} bytes)", sk_seed.len())
            })?;
            let ct = libcrux_ml_kem::$mod_path::$ct_ty::try_from(ciphertext).map_err(|_| {
                format!("ciphertext has wrong length ({} bytes)", ciphertext.len())
            })?;
            let ss = libcrux_ml_kem::$mod_path::decapsulate(&sk, &ct);
            Ok(ss.as_slice().to_vec())
        }
    };
}

impl_variant!(
    mlkem512,
    MlKem512PublicKey,
    MlKem512PrivateKey,
    MlKem512Ciphertext,
    keygen_512,
    encapsulate_512,
    decapsulate_512
);
impl_variant!(
    mlkem768,
    MlKem768PublicKey,
    MlKem768PrivateKey,
    MlKem768Ciphertext,
    keygen_768,
    encapsulate_768,
    decapsulate_768
);
impl_variant!(
    mlkem1024,
    MlKem1024PublicKey,
    MlKem1024PrivateKey,
    MlKem1024Ciphertext,
    keygen_1024,
    encapsulate_1024,
    decapsulate_1024
);

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
