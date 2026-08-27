//! XOF-backed sampling for the DSA path, generalized beyond what `sample.rs` supports for
//! the KEM path (whose `sample_uniform` hardcodes a 12-bit/q<4096 assumption). Kept in a
//! separate, additive file rather than modifying `sample.rs` in place, so the already-working
//! KEM sampling path carries zero regression risk from this work.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::encode::bits_for_q;
use crate::poly::{Poly, N};

/// Uniform rejection sampling in [0, q) from SHAKE128(seed||i||j), generalized to any i32 q
/// (vs. `sample::sample_uniform`'s fixed 12-bit assumption). Used for ExpandA, called k*l times.
pub fn sample_uniform_wide(seed: &[u8; 32], i: u8, j: u8, q: i32) -> Poly {
    let bits = bits_for_q(q);
    let bytes_per_candidate = bits.div_ceil(8) as usize;
    let mask: u32 = if bits >= 32 { u32::MAX } else { (1u32 << bits) - 1 };

    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.update(&[i, j]);
    let mut reader = hasher.finalize_xof();

    let mut out = Poly::zero();
    let mut count = 0;
    let mut buf = vec![0u8; bytes_per_candidate];
    while count < N {
        reader.read(&mut buf);
        let mut candidate: u32 = 0;
        for (idx, &b) in buf.iter().enumerate() {
            candidate |= (b as u32) << (8 * idx);
        }
        candidate &= mask;
        if (candidate as i64) < q as i64 {
            out.coeffs[count] = candidate as i32;
            count += 1;
        }
    }
    out
}

/// Centered rejection sampling in [-eta, eta] from SHAKE256(seed||nonce), one byte per
/// candidate (accept if byte <= 2*eta), generalized to arbitrary eta rather than the
/// nibble-packed eta-in-{2,3} the standard uses.
pub fn sample_eta(seed: &[u8; 32], nonce: u16, eta: u32) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&nonce.to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut out = Poly::zero();
    let mut count = 0;
    let mut byte = [0u8; 1];
    while count < N {
        reader.read(&mut byte);
        let v = byte[0] as u32;
        if v <= 2 * eta {
            out.coeffs[count] = eta as i32 - v as i32;
            count += 1;
        }
    }
    out
}

/// Samples the masking vector y: l polynomials, each with coefficients uniform in
/// (-gamma1, gamma1], from SHAKE256(seed||nonce). General for non-power-of-two gamma1.
pub fn expand_mask(seed: &[u8; 32], kappa: u16, l: u32, gamma1: i32) -> Vec<Poly> {
    let range = 2 * gamma1;
    let bits = bits_for_q(range);
    let bytes_per_candidate = bits.div_ceil(8) as usize;
    let mask: u32 = if bits >= 32 { u32::MAX } else { (1u32 << bits) - 1 };

    (0..l)
        .map(|idx| {
            let nonce = kappa.wrapping_add(idx as u16);
            let mut hasher = Shake256::default();
            hasher.update(seed);
            hasher.update(&nonce.to_le_bytes());
            let mut reader = hasher.finalize_xof();

            let mut out = Poly::zero();
            let mut count = 0;
            let mut buf = vec![0u8; bytes_per_candidate];
            while count < N {
                reader.read(&mut buf);
                let mut candidate: u32 = 0;
                for (i, &b) in buf.iter().enumerate() {
                    candidate |= (b as u32) << (8 * i);
                }
                candidate &= mask;
                if (candidate as i32) < range {
                    out.coeffs[count] = gamma1 - candidate as i32;
                    count += 1;
                }
            }
            out
        })
        .collect()
}

/// FIPS 204 Algorithm 29 (SampleInBall): produces a weight-tau polynomial with coefficients
/// in {-1, 0, +1}, deterministically from the challenge hash c_tilde.
pub fn sample_challenge(c_tilde: &[u8; 32], tau: u32) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(c_tilde);
    let mut reader = hasher.finalize_xof();

    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes);

    let mut c = [0i32; N];
    let tau = tau as usize;
    for i in (N - tau)..N {
        let j = loop {
            let mut b = [0u8; 1];
            reader.read(&mut b);
            let candidate = b[0] as usize;
            if candidate <= i {
                break candidate;
            }
        };
        c[i] = c[j];
        let bit_index = i - (N - tau);
        let bit = (sign_bytes[bit_index / 8] >> (bit_index % 8)) & 1;
        c[j] = if bit == 1 { -1 } else { 1 };
    }

    Poly { coeffs: c }
}
