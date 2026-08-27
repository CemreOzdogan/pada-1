use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "lowercase")]
enum Engine {
    Rustcrypto,
    Libcrux,
}

impl Engine {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rustcrypto => "rustcrypto",
            Self::Libcrux => "libcrux",
        }
    }
}

#[derive(Parser)]
#[command(name = "pqc-cli", about = "Sign/verify with ML-DSA, encapsulate/decapsulate with ML-KEM")]
struct Cli {
    #[command(subcommand)]
    scheme: Scheme,
}

#[derive(Subcommand)]
enum Scheme {
    /// ML-DSA (FIPS 204) signing operations
    MlDsa {
        #[command(subcommand)]
        op: MlDsaOp,
    },
    /// ML-KEM (FIPS 203) key encapsulation operations
    MlKem {
        #[command(subcommand)]
        op: MlKemOp,
    },
}

#[derive(Subcommand)]
enum MlDsaOp {
    /// Generate a signing keypair
    Keygen(DsaKeygenArgs),
    /// Sign a file
    Sign(DsaSignArgs),
    /// Verify a file against a signature
    Verify(DsaVerifyArgs),
    /// Generate a signing keypair with custom (non-standard) parameters
    KeygenCustom(DsaKeygenCustomArgs),
    /// Sign a file with a custom-engine key
    SignCustom(DsaSignCustomArgs),
    /// Verify a file against a signature from a custom-engine key
    VerifyCustom(DsaVerifyCustomArgs),
    /// Validate a (k, l, q, gamma1) tuple and preview the derived eta/gamma2/tau/omega,
    /// without running keygen. No file I/O.
    ValidateCustom(DsaValidateCustomArgs),
    /// Check whether a single q is prime and NTT-suitable for n=256 (q ≡ 1 mod 512), without
    /// needing k/l/gamma1. No file I/O.
    CheckQ(DsaCheckQArgs),
}

#[derive(Subcommand)]
enum MlKemOp {
    /// Generate an encapsulation keypair
    Keygen(KemKeygenArgs),
    /// Encapsulate a shared secret against a public key
    Encapsulate(EncapsulateArgs),
    /// Decapsulate a shared secret from a ciphertext
    Decapsulate(DecapsulateArgs),
    /// Generate an encapsulation keypair with custom (non-standard) parameters
    KeygenCustom(KemKeygenCustomArgs),
    /// Encapsulate against a custom-engine public key
    EncapsulateCustom(KemEncapsulateCustomArgs),
    /// Decapsulate a shared secret from a custom-engine ciphertext
    DecapsulateCustom(KemDecapsulateCustomArgs),
    /// Validate a (k, n, q) tuple and preview the derived eta1/eta2/du/dv, without running
    /// keygen. No file I/O.
    ValidateCustom(KemValidateCustomArgs),
    /// Check whether q is prime and NTT-suitable for the given n (q ≡ 1 mod 2n), without
    /// needing k. No file I/O.
    CheckQ(KemCheckQArgs),
}

#[derive(Args)]
struct DsaKeygenArgs {
    /// ml-dsa-44, ml-dsa-65, or ml-dsa-87
    #[arg(long)]
    variant: String,
    #[arg(long, value_enum, default_value_t = Engine::Rustcrypto)]
    engine: Engine,
    #[arg(long)]
    sk_out: PathBuf,
    #[arg(long)]
    pk_out: PathBuf,
}

#[derive(Args)]
struct DsaSignArgs {
    #[arg(long)]
    variant: String,
    #[arg(long, value_enum, default_value_t = Engine::Rustcrypto)]
    engine: Engine,
    #[arg(long)]
    sk: PathBuf,
    /// File to sign
    #[arg(long)]
    file: PathBuf,
    /// Where to write the signature (defaults to <file>.sig)
    #[arg(long)]
    sig_out: Option<PathBuf>,
}

#[derive(Args)]
struct DsaVerifyArgs {
    #[arg(long)]
    variant: String,
    #[arg(long, value_enum, default_value_t = Engine::Rustcrypto)]
    engine: Engine,
    #[arg(long)]
    pk: PathBuf,
    /// File whose signature is being checked
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    sig: PathBuf,
}

#[derive(Args)]
struct DsaKeygenCustomArgs {
    #[arg(long)]
    k: u32,
    #[arg(long)]
    l: u32,
    #[arg(long)]
    q: i32,
    #[arg(long)]
    gamma1: i32,
    #[arg(long)]
    sk_out: PathBuf,
    #[arg(long)]
    pk_out: PathBuf,
    /// Where to write the derived parameter set (JSON) — required by sign-custom/verify-custom
    #[arg(long)]
    params_out: PathBuf,
    /// Override the master 256-bit seed (64 hex chars) instead of drawing one from the OS RNG
    #[arg(long)]
    seed: Option<String>,
    /// Override rho (64 hex chars), bypassing SHAKE256(seed, 0) entirely — feeds an arbitrary
    /// matrix A into ExpandA instead of one honestly derived from seed. Research/fault-injection
    /// only: the resulting key is still internally consistent (sign/verify still round-trip),
    /// it just wasn't derived the normal way.
    #[arg(long)]
    rho: Option<String>,
    /// Override k_seed (64 hex chars), bypassing SHAKE256(seed, 1)
    #[arg(long)]
    k_seed: Option<String>,
    /// Override sigma (64 hex chars), bypassing SHAKE256(seed, 2) — feeds arbitrary noise into
    /// the s1/s2 sampling instead of noise honestly derived from seed
    #[arg(long)]
    sigma: Option<String>,
}

#[derive(Args)]
struct DsaSignCustomArgs {
    /// Parameter set JSON written by keygen-custom
    #[arg(long)]
    params: PathBuf,
    #[arg(long)]
    sk: PathBuf,
    /// File to sign
    #[arg(long)]
    file: PathBuf,
    /// Where to write the signature (defaults to <file>.sig)
    #[arg(long)]
    sig_out: Option<PathBuf>,
}

#[derive(Args)]
struct DsaVerifyCustomArgs {
    /// Parameter set JSON written by keygen-custom
    #[arg(long)]
    params: PathBuf,
    #[arg(long)]
    pk: PathBuf,
    /// File whose signature is being checked
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    sig: PathBuf,
}

#[derive(Args)]
struct DsaValidateCustomArgs {
    #[arg(long)]
    k: u32,
    #[arg(long)]
    l: u32,
    #[arg(long)]
    q: i32,
    #[arg(long)]
    gamma1: i32,
}

#[derive(Args)]
struct DsaCheckQArgs {
    #[arg(long)]
    q: i32,
}

#[derive(Args)]
struct KemKeygenArgs {
    /// ml-kem-512, ml-kem-768, or ml-kem-1024
    #[arg(long)]
    variant: String,
    #[arg(long, value_enum, default_value_t = Engine::Rustcrypto)]
    engine: Engine,
    #[arg(long)]
    sk_out: PathBuf,
    #[arg(long)]
    pk_out: PathBuf,
}

#[derive(Args)]
struct EncapsulateArgs {
    #[arg(long)]
    variant: String,
    #[arg(long, value_enum, default_value_t = Engine::Rustcrypto)]
    engine: Engine,
    #[arg(long)]
    pk: PathBuf,
    #[arg(long)]
    ct_out: PathBuf,
    /// Where to write the raw shared secret (optional; the hex is always printed)
    #[arg(long)]
    ss_out: Option<PathBuf>,
}

#[derive(Args)]
struct DecapsulateArgs {
    #[arg(long)]
    variant: String,
    #[arg(long, value_enum, default_value_t = Engine::Rustcrypto)]
    engine: Engine,
    #[arg(long)]
    sk: PathBuf,
    #[arg(long)]
    ct: PathBuf,
    #[arg(long)]
    ss_out: Option<PathBuf>,
}

#[derive(Args)]
struct KemKeygenCustomArgs {
    #[arg(long)]
    k: u32,
    #[arg(long)]
    n: usize,
    #[arg(long)]
    q: i32,
    #[arg(long)]
    sk_out: PathBuf,
    #[arg(long)]
    pk_out: PathBuf,
    /// Where to write the derived parameter set (JSON) — required by encapsulate-custom/decapsulate-custom
    #[arg(long)]
    params_out: PathBuf,
}

#[derive(Args)]
struct KemEncapsulateCustomArgs {
    /// Parameter set JSON written by keygen-custom
    #[arg(long)]
    params: PathBuf,
    #[arg(long)]
    pk: PathBuf,
    #[arg(long)]
    ct_out: PathBuf,
    #[arg(long)]
    ss_out: Option<PathBuf>,
}

#[derive(Args)]
struct KemDecapsulateCustomArgs {
    /// Parameter set JSON written by keygen-custom
    #[arg(long)]
    params: PathBuf,
    #[arg(long)]
    sk: PathBuf,
    #[arg(long)]
    ct: PathBuf,
    #[arg(long)]
    ss_out: Option<PathBuf>,
}

#[derive(Args)]
struct KemValidateCustomArgs {
    #[arg(long)]
    k: u32,
    #[arg(long)]
    n: usize,
    #[arg(long)]
    q: i32,
}

#[derive(Args)]
struct KemCheckQArgs {
    #[arg(long)]
    q: i32,
    #[arg(long)]
    n: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            println!("{}", json!({ "ok": false, "error": message }));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<serde_json::Value, String> {
    match cli.scheme {
        Scheme::MlDsa { op } => match op {
            MlDsaOp::Keygen(args) => dsa_keygen(args),
            MlDsaOp::Sign(args) => dsa_sign(args),
            MlDsaOp::Verify(args) => dsa_verify(args),
            MlDsaOp::KeygenCustom(args) => dsa_keygen_custom(args),
            MlDsaOp::SignCustom(args) => dsa_sign_custom(args),
            MlDsaOp::VerifyCustom(args) => dsa_verify_custom(args),
            MlDsaOp::ValidateCustom(args) => dsa_validate_custom(args),
            MlDsaOp::CheckQ(args) => dsa_check_q(args),
        },
        Scheme::MlKem { op } => match op {
            MlKemOp::Keygen(args) => kem_keygen(args),
            MlKemOp::Encapsulate(args) => kem_encapsulate(args),
            MlKemOp::Decapsulate(args) => kem_decapsulate(args),
            MlKemOp::KeygenCustom(args) => kem_keygen_custom(args),
            MlKemOp::EncapsulateCustom(args) => kem_encapsulate_custom(args),
            MlKemOp::DecapsulateCustom(args) => kem_decapsulate_custom(args),
            MlKemOp::ValidateCustom(args) => kem_validate_custom(args),
            MlKemOp::CheckQ(args) => kem_check_q(args),
        },
    }
}

fn dsa_keygen(args: DsaKeygenArgs) -> Result<serde_json::Value, String> {
    let (sk_seed, pk_bytes, variant_str) = match args.engine {
        Engine::Rustcrypto => {
            let variant = pqc_ml_dsa_rustcrypto::Variant::parse(&args.variant)?;
            let kp = pqc_ml_dsa_rustcrypto::keygen(variant);
            (kp.sk_seed, kp.pk_bytes, variant.as_str())
        }
        Engine::Libcrux => {
            let variant = pqc_ml_dsa_libcrux::Variant::parse(&args.variant)?;
            let kp = pqc_ml_dsa_libcrux::keygen(variant);
            (kp.sk_seed, kp.pk_bytes, variant.as_str())
        }
    };

    write_file(&args.sk_out, &sk_seed)?;
    write_file(&args.pk_out, &pk_bytes)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "keygen",
        "variant": variant_str,
        "engine": args.engine.as_str(),
        "sk_path": path_str(&args.sk_out),
        "pk_path": path_str(&args.pk_out),
        "sk_bytes": sk_seed.len(),
        "pk_bytes": pk_bytes.len(),
        "sk_hex": hex_encode(&sk_seed),
        "pk_hex": hex_encode(&pk_bytes),
    }))
}

fn dsa_sign(args: DsaSignArgs) -> Result<serde_json::Value, String> {
    let sk_seed = read_file(&args.sk)?;
    let message = read_file(&args.file)?;

    let (signature, variant_str) = match args.engine {
        Engine::Rustcrypto => {
            let variant = pqc_ml_dsa_rustcrypto::Variant::parse(&args.variant)?;
            (
                pqc_ml_dsa_rustcrypto::sign(variant, &sk_seed, &message)?,
                variant.as_str(),
            )
        }
        Engine::Libcrux => {
            let variant = pqc_ml_dsa_libcrux::Variant::parse(&args.variant)?;
            (
                pqc_ml_dsa_libcrux::sign(variant, &sk_seed, &message)?,
                variant.as_str(),
            )
        }
    };

    let sig_out = args
        .sig_out
        .unwrap_or_else(|| with_extra_extension(&args.file, "sig"));
    write_file(&sig_out, &signature)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "sign",
        "variant": variant_str,
        "engine": args.engine.as_str(),
        "file": path_str(&args.file),
        "signature_path": path_str(&sig_out),
        "signature_bytes": signature.len(),
        "signature_hex": hex_encode(&signature),
    }))
}

fn dsa_verify(args: DsaVerifyArgs) -> Result<serde_json::Value, String> {
    let pk_bytes = read_file(&args.pk)?;
    let message = read_file(&args.file)?;
    let signature = read_file(&args.sig)?;

    let (valid, variant_str) = match args.engine {
        Engine::Rustcrypto => {
            let variant = pqc_ml_dsa_rustcrypto::Variant::parse(&args.variant)?;
            (
                pqc_ml_dsa_rustcrypto::verify(variant, &pk_bytes, &message, &signature)?,
                variant.as_str(),
            )
        }
        Engine::Libcrux => {
            let variant = pqc_ml_dsa_libcrux::Variant::parse(&args.variant)?;
            (
                pqc_ml_dsa_libcrux::verify(variant, &pk_bytes, &message, &signature)?,
                variant.as_str(),
            )
        }
    };

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "verify",
        "variant": variant_str,
        "engine": args.engine.as_str(),
        "file": path_str(&args.file),
        "signature_path": path_str(&args.sig),
        "valid": valid,
        "pk_hex": hex_encode(&pk_bytes),
        "signature_hex": hex_encode(&signature),
    }))
}

fn parameter_set_from_generic(params: &pqc_generic::dsa_params::GenericDsaParams) -> pqc_contracts::ParameterSet {
    pqc_contracts::ParameterSet {
        scheme: pqc_contracts::Scheme::MlDsa,
        name: None,
        is_standard: false,
        n: 256,
        q: params.q as u32,
        kem: None,
        dsa: Some(pqc_contracts::DsaKnobs {
            k: params.k,
            l: params.l,
            eta: params.eta,
            gamma1: params.gamma1 as u32,
            gamma2: params.gamma2 as u32,
            tau: params.tau,
            omega: params.omega,
        }),
    }
}

fn load_custom_params(path: &Path) -> Result<pqc_generic::dsa_params::GenericDsaParams, String> {
    let bytes = read_file(path)?;
    let parameter_set: pqc_contracts::ParameterSet = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse params file '{}': {e}", path.display()))?;

    if parameter_set.scheme != pqc_contracts::Scheme::MlDsa {
        return Err("params file is not for ml-dsa".to_string());
    }
    if parameter_set.n != 256 {
        return Err(format!("params file has n={}, expected 256", parameter_set.n));
    }
    let dsa = parameter_set.dsa.ok_or("params file has no `dsa` knobs")?;
    let q = parameter_set.q as i32;

    // Defensive: re-validate even though keygen-custom already validated q, in case the file
    // was hand-edited.
    pqc_generic::dsa_params::validate_q(q)?;

    Ok(pqc_generic::dsa_params::GenericDsaParams {
        k: dsa.k,
        l: dsa.l,
        q,
        eta: dsa.eta,
        gamma1: dsa.gamma1 as i32,
        gamma2: dsa.gamma2 as i32,
        tau: dsa.tau,
        omega: dsa.omega,
    })
}

fn parse_hex32(s: &str, field_name: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!(
            "--{field_name} must be exactly 64 hex characters (32 bytes), got {} characters",
            s.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("--{field_name} is not valid hex"))?;
    }
    Ok(out)
}

fn dsa_keygen_custom(args: DsaKeygenCustomArgs) -> Result<serde_json::Value, String> {
    let params = pqc_generic::dsa_params::build_params(args.k, args.l, args.q, args.gamma1)?;

    let seed = args.seed.as_deref().map(|s| parse_hex32(s, "seed")).transpose()?;
    let overrides = pqc_generic::dilithium::KeygenOverrides {
        rho: args.rho.as_deref().map(|s| parse_hex32(s, "rho")).transpose()?,
        k_seed: args.k_seed.as_deref().map(|s| parse_hex32(s, "k-seed")).transpose()?,
        sigma: args.sigma.as_deref().map(|s| parse_hex32(s, "sigma")).transpose()?,
    };

    let kp = pqc_generic::dsa::keygen_with_overrides(&params, seed, overrides);

    write_file(&args.sk_out, &kp.sk_bytes)?;
    write_file(&args.pk_out, &kp.pk_bytes)?;

    let parameter_set = parameter_set_from_generic(&params);
    let params_json = serde_json::to_string_pretty(&parameter_set)
        .map_err(|e| format!("failed to serialize parameter set: {e}"))?;
    write_file(&args.params_out, params_json.as_bytes())?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "keygen",
        "engine": "custom",
        "k": params.k,
        "l": params.l,
        "q": params.q,
        "n": 256,
        "eta": params.eta,
        "gamma1": params.gamma1,
        "gamma2": params.gamma2,
        "tau": params.tau,
        "omega": params.omega,
        "sk_path": path_str(&args.sk_out),
        "pk_path": path_str(&args.pk_out),
        "params_path": path_str(&args.params_out),
        "sk_bytes": kp.sk_bytes.len(),
        "pk_bytes": kp.pk_bytes.len(),
        "sk_hex": hex_encode(&kp.sk_bytes),
        "pk_hex": hex_encode(&kp.pk_bytes),
        "seed_hex": hex_encode(&kp.seed),
        "rho_hex": hex_encode(&kp.rho),
        "k_seed_hex": hex_encode(&kp.k_seed),
        "sigma_hex": hex_encode(&kp.sigma),
        "seed_overridden": args.seed.is_some(),
        "rho_overridden": args.rho.is_some(),
        "k_seed_overridden": args.k_seed.is_some(),
        "sigma_overridden": args.sigma.is_some(),
    }))
}

fn dsa_sign_custom(args: DsaSignCustomArgs) -> Result<serde_json::Value, String> {
    let params = load_custom_params(&args.params)?;
    let sk_bytes = read_file(&args.sk)?;
    let message = read_file(&args.file)?;

    let signature = pqc_generic::dsa::sign(&params, &sk_bytes, &message)?;

    let sig_out = args
        .sig_out
        .unwrap_or_else(|| with_extra_extension(&args.file, "sig"));
    write_file(&sig_out, &signature)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "sign",
        "engine": "custom",
        "file": path_str(&args.file),
        "signature_path": path_str(&sig_out),
        "signature_bytes": signature.len(),
        "signature_hex": hex_encode(&signature),
    }))
}

fn dsa_verify_custom(args: DsaVerifyCustomArgs) -> Result<serde_json::Value, String> {
    let params = load_custom_params(&args.params)?;
    let pk_bytes = read_file(&args.pk)?;
    let message = read_file(&args.file)?;
    let signature = read_file(&args.sig)?;

    let valid = pqc_generic::dsa::verify(&params, &pk_bytes, &message, &signature)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "verify",
        "engine": "custom",
        "file": path_str(&args.file),
        "signature_path": path_str(&args.sig),
        "valid": valid,
        "pk_hex": hex_encode(&pk_bytes),
        "signature_hex": hex_encode(&signature),
    }))
}

fn dsa_validate_custom(args: DsaValidateCustomArgs) -> Result<serde_json::Value, String> {
    let params = pqc_generic::dsa_params::build_params(args.k, args.l, args.q, args.gamma1)?;
    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "validate-custom",
        "k": params.k,
        "l": params.l,
        "q": params.q,
        "n": 256,
        "eta": params.eta,
        "gamma1": params.gamma1,
        "gamma2": params.gamma2,
        "tau": params.tau,
        "omega": params.omega,
    }))
}

fn dsa_check_q(args: DsaCheckQArgs) -> Result<serde_json::Value, String> {
    pqc_generic::dsa_params::validate_q(args.q)?;
    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "check-q",
        "q": args.q,
        "ntt_suitable": true,
    }))
}

fn kem_keygen(args: KemKeygenArgs) -> Result<serde_json::Value, String> {
    let (sk_seed, pk_bytes, variant_str) = match args.engine {
        Engine::Rustcrypto => {
            let variant = pqc_ml_kem_rustcrypto::Variant::parse(&args.variant)?;
            let kp = pqc_ml_kem_rustcrypto::keygen(variant);
            (kp.sk_seed, kp.pk_bytes, variant.as_str())
        }
        Engine::Libcrux => {
            let variant = pqc_ml_kem_libcrux::Variant::parse(&args.variant)?;
            let kp = pqc_ml_kem_libcrux::keygen(variant);
            (kp.sk_seed, kp.pk_bytes, variant.as_str())
        }
    };

    write_file(&args.sk_out, &sk_seed)?;
    write_file(&args.pk_out, &pk_bytes)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "keygen",
        "variant": variant_str,
        "engine": args.engine.as_str(),
        "sk_path": path_str(&args.sk_out),
        "pk_path": path_str(&args.pk_out),
        "sk_bytes": sk_seed.len(),
        "pk_bytes": pk_bytes.len(),
        "sk_hex": hex_encode(&sk_seed),
        "pk_hex": hex_encode(&pk_bytes),
    }))
}

fn kem_encapsulate(args: EncapsulateArgs) -> Result<serde_json::Value, String> {
    let pk_bytes = read_file(&args.pk)?;

    let (ciphertext, shared_secret, variant_str) = match args.engine {
        Engine::Rustcrypto => {
            let variant = pqc_ml_kem_rustcrypto::Variant::parse(&args.variant)?;
            let result = pqc_ml_kem_rustcrypto::encapsulate(variant, &pk_bytes)?;
            (result.ciphertext, result.shared_secret, variant.as_str())
        }
        Engine::Libcrux => {
            let variant = pqc_ml_kem_libcrux::Variant::parse(&args.variant)?;
            let result = pqc_ml_kem_libcrux::encapsulate(variant, &pk_bytes)?;
            (result.ciphertext, result.shared_secret, variant.as_str())
        }
    };

    write_file(&args.ct_out, &ciphertext)?;
    if let Some(ss_out) = &args.ss_out {
        write_file(ss_out, &shared_secret)?;
    }

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "encapsulate",
        "variant": variant_str,
        "engine": args.engine.as_str(),
        "public_key_path": path_str(&args.pk),
        "ciphertext_path": path_str(&args.ct_out),
        "ciphertext_bytes": ciphertext.len(),
        "ciphertext_hex": hex_encode(&ciphertext),
        "shared_secret_hex": hex_encode(&shared_secret),
        "shared_secret_path": args.ss_out.as_deref().map(path_str),
    }))
}

fn kem_decapsulate(args: DecapsulateArgs) -> Result<serde_json::Value, String> {
    let sk_seed = read_file(&args.sk)?;
    let ciphertext = read_file(&args.ct)?;

    let (shared_secret, variant_str) = match args.engine {
        Engine::Rustcrypto => {
            let variant = pqc_ml_kem_rustcrypto::Variant::parse(&args.variant)?;
            (
                pqc_ml_kem_rustcrypto::decapsulate(variant, &sk_seed, &ciphertext)?,
                variant.as_str(),
            )
        }
        Engine::Libcrux => {
            let variant = pqc_ml_kem_libcrux::Variant::parse(&args.variant)?;
            (
                pqc_ml_kem_libcrux::decapsulate(variant, &sk_seed, &ciphertext)?,
                variant.as_str(),
            )
        }
    };

    if let Some(ss_out) = &args.ss_out {
        write_file(ss_out, &shared_secret)?;
    }

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "decapsulate",
        "variant": variant_str,
        "engine": args.engine.as_str(),
        "secret_key_path": path_str(&args.sk),
        "ciphertext_path": path_str(&args.ct),
        "ciphertext_hex": hex_encode(&ciphertext),
        "shared_secret_hex": hex_encode(&shared_secret),
        "shared_secret_path": args.ss_out.as_deref().map(path_str),
    }))
}

fn kem_parameter_set_from_generic(params: &pqc_generic::custom_kem_params::GenericCustomKemParams) -> pqc_contracts::ParameterSet {
    pqc_contracts::ParameterSet {
        scheme: pqc_contracts::Scheme::MlKem,
        name: None,
        is_standard: false,
        n: params.n as u32,
        q: params.q as u32,
        kem: Some(pqc_contracts::KemKnobs {
            k: params.k,
            eta1: params.eta1,
            eta2: params.eta2,
            du: params.du,
            dv: params.dv,
        }),
        dsa: None,
    }
}

fn load_custom_kem_params(path: &Path) -> Result<pqc_generic::custom_kem_params::GenericCustomKemParams, String> {
    let bytes = read_file(path)?;
    let parameter_set: pqc_contracts::ParameterSet = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse params file '{}': {e}", path.display()))?;

    if parameter_set.scheme != pqc_contracts::Scheme::MlKem {
        return Err("params file is not for ml-kem".to_string());
    }
    let kem = parameter_set.kem.ok_or("params file has no `kem` knobs")?;
    let n = parameter_set.n as usize;
    let q = parameter_set.q as i32;

    // Defensive: re-validate even though keygen-custom already validated this, in case the
    // file was hand-edited.
    pqc_generic::custom_kem_params::validate_n(n)?;
    pqc_generic::custom_kem_params::validate_q(q, n)?;

    Ok(pqc_generic::custom_kem_params::GenericCustomKemParams {
        k: kem.k,
        n,
        q,
        eta1: kem.eta1,
        eta2: kem.eta2,
        du: kem.du,
        dv: kem.dv,
    })
}

fn kem_keygen_custom(args: KemKeygenCustomArgs) -> Result<serde_json::Value, String> {
    let params = pqc_generic::custom_kem_params::build_params(args.k, args.n, args.q)?;
    let kp = pqc_generic::custom_kem::keygen(&params);

    write_file(&args.sk_out, &kp.sk_bytes)?;
    write_file(&args.pk_out, &kp.pk_bytes)?;

    let parameter_set = kem_parameter_set_from_generic(&params);
    let params_json = serde_json::to_string_pretty(&parameter_set)
        .map_err(|e| format!("failed to serialize parameter set: {e}"))?;
    write_file(&args.params_out, params_json.as_bytes())?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "keygen",
        "engine": "custom",
        "k": params.k,
        "n": params.n,
        "q": params.q,
        "eta1": params.eta1,
        "eta2": params.eta2,
        "du": params.du,
        "dv": params.dv,
        "sk_path": path_str(&args.sk_out),
        "pk_path": path_str(&args.pk_out),
        "params_path": path_str(&args.params_out),
        "sk_bytes": kp.sk_bytes.len(),
        "pk_bytes": kp.pk_bytes.len(),
        "sk_hex": hex_encode(&kp.sk_bytes),
        "pk_hex": hex_encode(&kp.pk_bytes),
    }))
}

fn kem_encapsulate_custom(args: KemEncapsulateCustomArgs) -> Result<serde_json::Value, String> {
    let params = load_custom_kem_params(&args.params)?;
    let pk_bytes = read_file(&args.pk)?;

    let (ciphertext, shared_secret) = pqc_generic::custom_kem::encapsulate(&params, &pk_bytes)?;

    write_file(&args.ct_out, &ciphertext)?;
    if let Some(ss_out) = &args.ss_out {
        write_file(ss_out, &shared_secret)?;
    }

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "encapsulate",
        "engine": "custom",
        "public_key_path": path_str(&args.pk),
        "ciphertext_path": path_str(&args.ct_out),
        "ciphertext_bytes": ciphertext.len(),
        "ciphertext_hex": hex_encode(&ciphertext),
        "shared_secret_hex": hex_encode(&shared_secret),
        "shared_secret_path": args.ss_out.as_deref().map(path_str),
    }))
}

fn kem_decapsulate_custom(args: KemDecapsulateCustomArgs) -> Result<serde_json::Value, String> {
    let params = load_custom_kem_params(&args.params)?;
    let sk_bytes = read_file(&args.sk)?;
    let ciphertext = read_file(&args.ct)?;

    let shared_secret = pqc_generic::custom_kem::decapsulate(&params, &sk_bytes, &ciphertext)?;

    if let Some(ss_out) = &args.ss_out {
        write_file(ss_out, &shared_secret)?;
    }

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "decapsulate",
        "engine": "custom",
        "secret_key_path": path_str(&args.sk),
        "ciphertext_path": path_str(&args.ct),
        "ciphertext_hex": hex_encode(&ciphertext),
        "shared_secret_hex": hex_encode(&shared_secret),
        "shared_secret_path": args.ss_out.as_deref().map(path_str),
    }))
}

fn kem_validate_custom(args: KemValidateCustomArgs) -> Result<serde_json::Value, String> {
    let params = pqc_generic::custom_kem_params::build_params(args.k, args.n, args.q)?;
    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "validate-custom",
        "k": params.k,
        "n": params.n,
        "q": params.q,
        "eta1": params.eta1,
        "eta2": params.eta2,
        "du": params.du,
        "dv": params.dv,
    }))
}

fn kem_check_q(args: KemCheckQArgs) -> Result<serde_json::Value, String> {
    pqc_generic::custom_kem_params::validate_n(args.n)?;
    pqc_generic::custom_kem_params::validate_q(args.q, args.n)?;
    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "check-q",
        "q": args.q,
        "n": args.n,
        "ntt_suitable": true,
    }))
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("failed to read '{}': {e}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| format!("failed to write '{}': {e}", path.display()))
}

fn path_str(path: &Path) -> String {
    path.display().to_string()
}

fn with_extra_extension(path: &Path, extra: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(extra);
    PathBuf::from(s)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
