//! XOF-backed sampling: uniform rejection sampling for matrix entries (SHAKE128, mirrors
//! Kyber's `SampleNTT`) and centered binomial sampling for noise (SHAKE256 as PRF), generalized
//! to arbitrary eta rather than only the eta in {2,3} the standard uses.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::poly::{Poly, N};

/// Sample a polynomial with coefficients uniform in [0, q) from SHAKE128(seed || i || j).
/// `q` must be < 4096 so that two candidates fit in three bytes (12 bits each); true for the
/// fixed q=3329 this engine currently supports.
pub fn sample_uniform(seed: &[u8; 32], i: u8, j: u8, q: i32) -> Poly {
    debug_assert!(q < 4096, "uniform sampler assumes 12-bit rejection sampling");

    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.update(&[i, j]);
    let mut reader = hasher.finalize_xof();

    let mut out = Poly::zero();
    let mut count = 0;
    let mut buf = [0u8; 3];
    while count < N {
        reader.read(&mut buf);
        let d1 = (buf[0] as i32) | (((buf[1] as i32) & 0x0F) << 8);
        let d2 = ((buf[1] as i32) >> 4) | ((buf[2] as i32) << 4);
        if d1 < q {
            out.coeffs[count] = d1;
            count += 1;
        }
        if count < N && d2 < q {
            out.coeffs[count] = d2;
            count += 1;
        }
    }
    out
}

/// PRF: squeeze `out_len` bytes from SHAKE256(seed || nonce).
pub fn prf(seed: &[u8; 32], nonce: u8, out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    let mut buf = vec![0u8; out_len];
    reader.read(&mut buf);
    buf
}

/// Centered binomial distribution with parameter `eta`, generalized to any eta (the standard
/// only ever uses eta in {2,3}; RustCrypto's reference crate only implements those two).
/// Consumes exactly `cbd_bytes_needed(eta)` bytes.
pub fn cbd(bytes: &[u8], eta: u32, q: i32) -> Poly {
    let mut out = Poly::zero();
    let mut bit_idx = 0usize;
    let get_bit = |idx: usize| -> i32 { ((bytes[idx / 8] >> (idx % 8)) & 1) as i32 };
    for coeff in out.coeffs.iter_mut() {
        let mut a = 0;
        for _ in 0..eta {
            a += get_bit(bit_idx);
            bit_idx += 1;
        }
        let mut b = 0;
        for _ in 0..eta {
            b += get_bit(bit_idx);
            bit_idx += 1;
        }
        *coeff = (a - b).rem_euclid(q);
    }
    out
}

/// Bytes of PRF output required for `cbd` at a given eta: 2*eta bits per coefficient, N
/// coefficients, packed to bytes. N=256 keeps this exact (no padding).
pub fn cbd_bytes_needed(eta: u32) -> usize {
    (2 * eta as usize * N) / 8
}
