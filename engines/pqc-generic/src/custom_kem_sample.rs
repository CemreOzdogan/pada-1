//! XOF-backed sampling for the custom KEM path, `Vec`-based generalizations of
//! `dsa_sample.rs`'s functions (which return the fixed-size `poly::Poly`) to a runtime `n`.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::encode::bits_for_q;

/// Uniform rejection sampling in [0, q) from SHAKE128(seed||i||j) — same algorithm as
/// `dsa_sample::sample_uniform_wide`, generalized to a runtime-length output.
pub fn sample_uniform_vec(seed: &[u8; 32], i: u8, j: u8, q: i32, n: usize) -> Vec<i32> {
    let bits = bits_for_q(q);
    let bytes_per_candidate = bits.div_ceil(8) as usize;
    let mask: u32 = if bits >= 32 { u32::MAX } else { (1u32 << bits) - 1 };

    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.update(&[i, j]);
    let mut reader = hasher.finalize_xof();

    let mut out = vec![0i32; n];
    let mut count = 0;
    let mut buf = vec![0u8; bytes_per_candidate];
    while count < n {
        reader.read(&mut buf);
        let mut candidate: u32 = 0;
        for (idx, &b) in buf.iter().enumerate() {
            candidate |= (b as u32) << (8 * idx);
        }
        candidate &= mask;
        if (candidate as i64) < q as i64 {
            out[count] = candidate as i32;
            count += 1;
        }
    }
    out
}

/// Centered rejection sampling in [-eta, eta] from SHAKE256(seed||nonce) — same algorithm as
/// `dsa_sample::sample_eta`, generalized to a runtime-length output.
pub fn sample_eta_vec(seed: &[u8; 32], nonce: u16, eta: u32, n: usize) -> Vec<i32> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&nonce.to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut out = vec![0i32; n];
    let mut count = 0;
    let mut byte = [0u8; 1];
    while count < n {
        reader.read(&mut byte);
        let v = byte[0] as u32;
        if v <= 2 * eta {
            out[count] = eta as i32 - v as i32;
            count += 1;
        }
    }
    out
}
