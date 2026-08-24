# P-KAIDO

**post kuantum algoritma işlem deney ortamı** — a post-quantum cryptography experimentation environment.

P-KAIDO is a Windows desktop app (with a matching CLI underneath) for running and observing
NIST's standardized post-quantum algorithms: **ML-KEM** (FIPS 203, key encapsulation) and
**ML-DSA** (FIPS 204, digital signatures). It's built for exploring and comparing real
implementations, not for production key management.

## Two interchangeable engines

Every operation can run against either of two independent implementations of the same
standard, selectable per-run:

- **RustCrypto** — the [`ml-kem`](https://crates.io/crates/ml-kem) and
  [`ml-dsa`](https://crates.io/crates/ml-dsa) crates. Pure Rust, portable.
- **libcrux** — Cryspen's [`libcrux-ml-kem`](https://crates.io/crates/libcrux-ml-kem) and
  [`libcrux-ml-dsa`](https://crates.io/crates/libcrux-ml-dsa). Formally verified (via
  hax/F*) with AVX2/NEON-accelerated backends selected automatically at runtime.

Both wrap their respective crate directly — no custom or placeholder crypto math sits in
that path. Public artifacts (keys, ciphertexts, signatures) are byte-compatible with the
standard wire format regardless of engine; a key or signature produced by one engine
verifies correctly against the other.

## Layout

| Path | What it is |
|---|---|
| `engines/pqc-cli` | The CLI — every operation, invoked by the GUI or directly |
| `engines/pqc-ml-kem-rustcrypto`, `pqc-ml-dsa-rustcrypto` | Thin RustCrypto-backed engine crates |
| `engines/pqc-ml-kem-libcrux`, `pqc-ml-dsa-libcrux` | Thin libcrux-backed engine crates |
| `ui/P-KAIDO` | The WinForms GUI (.NET, Windows-only) |
| `data/kat` | Reserved for known-answer-test vectors |
| `keys/`, `messages/` | Runtime output (generated keys, typed messages) — gitignored, never commit real key material here |

## Building

**CLI** (Rust, cross-platform):

```sh
cd engines
cargo build --release
# binary at engines/target/release/pqc-cli(.exe)
```

**GUI** (.NET 10, WinForms — Windows only):

```sh
cd ui/P-KAIDO
dotnet run
```

The GUI auto-detects `pqc-cli` under `engines/target/{debug,release}/`, or you can point it
at any built binary from within the app.

## CLI usage

```sh
# ML-DSA: generate a keypair, sign, verify
pqc-cli ml-dsa keygen --variant ml-dsa-65 --sk-out sk.bin --pk-out pk.bin
pqc-cli ml-dsa sign   --variant ml-dsa-65 --sk sk.bin --file message.txt
pqc-cli ml-dsa verify --variant ml-dsa-65 --pk pk.bin --file message.txt --sig message.txt.sig

# ML-KEM: generate a keypair, encapsulate, decapsulate
pqc-cli ml-kem keygen      --variant ml-kem-768 --sk-out sk.bin --pk-out pk.bin
pqc-cli ml-kem encapsulate --variant ml-kem-768 --pk pk.bin --ct-out ct.bin
pqc-cli ml-kem decapsulate --variant ml-kem-768 --sk sk.bin --ct ct.bin

# Add --engine libcrux to any of the above to use the libcrux backend instead
# of the default (rustcrypto). Every command prints a JSON result to stdout.
```

Supported variants: `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87`, `ml-kem-512` / `ml-kem-768` / `ml-kem-1024`.

## Testing

```sh
cd engines
cargo test
```

Each engine crate has round-trip tests (keygen → sign → verify / keygen → encapsulate →
decapsulate) across all three parameter sets.

## Status

Experimental. Not audited, not FIPS 140-3 validated, and not intended for production key
custody — private keys are written to disk unencrypted with no HSM/KMS integration, access
control, or key lifecycle management. Built for learning, comparing implementations, and
observing post-quantum algorithms in action.
