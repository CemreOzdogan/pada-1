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
}

#[derive(Subcommand)]
enum MlKemOp {
    /// Generate an encapsulation keypair
    Keygen(KemKeygenArgs),
    /// Encapsulate a shared secret against a public key
    Encapsulate(EncapsulateArgs),
    /// Decapsulate a shared secret from a ciphertext
    Decapsulate(DecapsulateArgs),
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
        },
        Scheme::MlKem { op } => match op {
            MlKemOp::Keygen(args) => kem_keygen(args),
            MlKemOp::Encapsulate(args) => kem_encapsulate(args),
            MlKemOp::Decapsulate(args) => kem_decapsulate(args),
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
