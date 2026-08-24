use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use serde_json::json;

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
    #[arg(long)]
    sk_out: PathBuf,
    #[arg(long)]
    pk_out: PathBuf,
}

#[derive(Args)]
struct DsaSignArgs {
    #[arg(long)]
    variant: String,
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
    #[arg(long)]
    sk_out: PathBuf,
    #[arg(long)]
    pk_out: PathBuf,
}

#[derive(Args)]
struct EncapsulateArgs {
    #[arg(long)]
    variant: String,
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
    let variant = pqc_ml_dsa::Variant::parse(&args.variant)?;
    let kp = pqc_ml_dsa::keygen(variant);

    write_file(&args.sk_out, &kp.sk_seed)?;
    write_file(&args.pk_out, &kp.pk_bytes)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "keygen",
        "variant": variant.as_str(),
        "sk_path": path_str(&args.sk_out),
        "pk_path": path_str(&args.pk_out),
        "sk_bytes": kp.sk_seed.len(),
        "pk_bytes": kp.pk_bytes.len(),
    }))
}

fn dsa_sign(args: DsaSignArgs) -> Result<serde_json::Value, String> {
    let variant = pqc_ml_dsa::Variant::parse(&args.variant)?;
    let sk_seed = read_file(&args.sk)?;
    let message = read_file(&args.file)?;

    let signature = pqc_ml_dsa::sign(variant, &sk_seed, &message)?;

    let sig_out = args
        .sig_out
        .unwrap_or_else(|| with_extra_extension(&args.file, "sig"));
    write_file(&sig_out, &signature)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "sign",
        "variant": variant.as_str(),
        "file": path_str(&args.file),
        "signature_path": path_str(&sig_out),
        "signature_bytes": signature.len(),
    }))
}

fn dsa_verify(args: DsaVerifyArgs) -> Result<serde_json::Value, String> {
    let variant = pqc_ml_dsa::Variant::parse(&args.variant)?;
    let pk_bytes = read_file(&args.pk)?;
    let message = read_file(&args.file)?;
    let signature = read_file(&args.sig)?;

    let valid = pqc_ml_dsa::verify(variant, &pk_bytes, &message, &signature)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-dsa",
        "op": "verify",
        "variant": variant.as_str(),
        "file": path_str(&args.file),
        "signature_path": path_str(&args.sig),
        "valid": valid,
    }))
}

fn kem_keygen(args: KemKeygenArgs) -> Result<serde_json::Value, String> {
    let variant = pqc_ml_kem::Variant::parse(&args.variant)?;
    let kp = pqc_ml_kem::keygen(variant);

    write_file(&args.sk_out, &kp.sk_seed)?;
    write_file(&args.pk_out, &kp.pk_bytes)?;

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "keygen",
        "variant": variant.as_str(),
        "sk_path": path_str(&args.sk_out),
        "pk_path": path_str(&args.pk_out),
        "sk_bytes": kp.sk_seed.len(),
        "pk_bytes": kp.pk_bytes.len(),
    }))
}

fn kem_encapsulate(args: EncapsulateArgs) -> Result<serde_json::Value, String> {
    let variant = pqc_ml_kem::Variant::parse(&args.variant)?;
    let pk_bytes = read_file(&args.pk)?;

    let result = pqc_ml_kem::encapsulate(variant, &pk_bytes)?;

    write_file(&args.ct_out, &result.ciphertext)?;
    if let Some(ss_out) = &args.ss_out {
        write_file(ss_out, &result.shared_secret)?;
    }

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "encapsulate",
        "variant": variant.as_str(),
        "public_key_path": path_str(&args.pk),
        "ciphertext_path": path_str(&args.ct_out),
        "ciphertext_bytes": result.ciphertext.len(),
        "shared_secret_hex": hex_encode(&result.shared_secret),
        "shared_secret_path": args.ss_out.as_deref().map(path_str),
    }))
}

fn kem_decapsulate(args: DecapsulateArgs) -> Result<serde_json::Value, String> {
    let variant = pqc_ml_kem::Variant::parse(&args.variant)?;
    let sk_seed = read_file(&args.sk)?;
    let ciphertext = read_file(&args.ct)?;

    let shared_secret = pqc_ml_kem::decapsulate(variant, &sk_seed, &ciphertext)?;

    if let Some(ss_out) = &args.ss_out {
        write_file(ss_out, &shared_secret)?;
    }

    Ok(json!({
        "ok": true,
        "scheme": "ml-kem",
        "op": "decapsulate",
        "variant": variant.as_str(),
        "secret_key_path": path_str(&args.sk),
        "ciphertext_path": path_str(&args.ct),
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
