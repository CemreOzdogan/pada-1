//! XOF-backed sampling for the DSA path, generalized beyond what `sample.rs` supports for
//! the KEM path (whose `sample_uniform` hardcodes a 12-bit/q<4096 assumption). Kept in a
//! separate, additive file rather than modifying `sample.rs` in place, so the already-working
//! KEM sampling path carries zero regression risk from this work.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::encode::bits_for_q;
use crate::poly::{Poly, N};

/// Uniform rejection sampling in [0, q) from SHAKE128(seed||s||r), generalized to any i32 q
/// (vs. `sample::sample_uniform`'s fixed 12-bit assumption). Used for ExpandA (FIPS 204
/// Algorithm 32), called k*l times — `r` is the matrix row, `s` the column; per spec the
/// domain-separation bytes are absorbed column-then-row (`s` before `r`), not row-then-column.
pub fn sample_uniform_wide(seed: &[u8; 32], r: u8, s: u8, q: i32) -> Poly {
    let bits = bits_for_q(q);
    let bytes_per_candidate = bits.div_ceil(8) as usize;
    let mask: u32 = if bits >= 32 { u32::MAX } else { (1u32 << bits) - 1 };

    let mut hasher = Shake128::default();
    hasher.update(seed);
    hasher.update(&[s, r]);
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

/// FIPS 204 Algorithm 31 (RejBoundedPoly): rejection-samples centered noise in [-eta, eta] from
/// SHAKE256(seed||nonce). For eta<=7, processes each byte as two 4-bit nibbles (CoeffFromHalfByte
/// in the spec), rejecting a nibble via `nibble >= largest multiple of (2*eta+1) that fits in a
/// nibble` and mapping the accepted nibble to `eta - (nibble mod (2*eta+1))`. This generalized
/// rule exactly reproduces the spec's own tables at eta=2 (reject nibble>=15, i.e. accept 15/16)
/// and eta=4 (reject nibble>=9) — the only two values the standard itself uses — verified in
/// this module's tests and by the byte-exact conformance test in `dilithium.rs`. Falls back to a
/// byte-per-candidate scheme (same shape, wider range) for eta>=8, where the spec has no defined
/// behavior anyway (it never uses eta outside {2,4}).
fn coeff_from_half_byte(nibble: u8, eta: u32) -> Option<i32> {
    let range = 2 * eta + 1;
    let usable = 16 - (16 % range);
    if (nibble as u32) < usable {
        Some(eta as i32 - (nibble as u32 % range) as i32)
    } else {
        None
    }
}

pub fn sample_eta(seed: &[u8], nonce: u16, eta: u32) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&nonce.to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut out = Poly::zero();
    let mut count = 0;

    if eta <= 7 {
        let mut byte = [0u8; 1];
        while count < N {
            reader.read(&mut byte);
            for nibble in [byte[0] & 0x0F, byte[0] >> 4] {
                if count >= N {
                    break;
                }
                if let Some(v) = coeff_from_half_byte(nibble, eta) {
                    out.coeffs[count] = v;
                    count += 1;
                }
            }
        }
    } else {
        let mut byte = [0u8; 1];
        while count < N {
            reader.read(&mut byte);
            let v = byte[0] as u32;
            if v <= 2 * eta {
                out.coeffs[count] = eta as i32 - v as i32;
                count += 1;
            }
        }
    }
    out
}

/// Samples the masking vector y: l polynomials, each with coefficients uniform in
/// (-gamma1, gamma1], from SHAKE256(seed||nonce). FIPS 204 Algorithm 34 (ExpandMask): the raw
/// squeeze output is a *dense*, bit-packed stream (`bits` bits per coefficient, back-to-back —
/// `SimpleBitPack`'s own convention, same as `encode::byte_decode`), not one byte-aligned
/// candidate block per coefficient — reading whole bytes per candidate (as an earlier version of
/// this function did) discards bits between coefficients and desyncs from every other
/// implementation from the very first coefficient onward. For the standard sets gamma1 is a
/// power of two so `range=2*gamma1` never rejects; the rejection path only ever triggers for a
/// non-power-of-two custom gamma1, which the spec itself never defines — self-consistency is all
/// that matters there, so it just continues pulling from the same dense bitstream.
pub fn expand_mask(seed: &[u8], kappa: u16, l: u32, gamma1: i32) -> Vec<Poly> {
    let range = 2 * gamma1;
    let bits = bits_for_q(range) as u64;

    (0..l)
        .map(|idx| {
            let nonce = kappa.wrapping_add(idx as u16);
            let mut hasher = Shake256::default();
            hasher.update(seed);
            hasher.update(&nonce.to_le_bytes());
            let mut reader = hasher.finalize_xof();

            let mut out = Poly::zero();
            let mut count = 0;
            let mut bit_buf: u64 = 0;
            let mut bit_len: u32 = 0;
            let mut byte = [0u8; 1];
            while count < N {
                while (bit_len as u64) < bits {
                    reader.read(&mut byte);
                    bit_buf |= (byte[0] as u64) << bit_len;
                    bit_len += 8;
                }
                let candidate = (bit_buf & ((1u64 << bits) - 1)) as i32;
                bit_buf >>= bits;
                bit_len -= bits as u32;
                if candidate < range {
                    out.coeffs[count] = gamma1 - candidate;
                    count += 1;
                }
            }
            out
        })
        .collect()
}

/// FIPS 204 Algorithm 29 (SampleInBall): produces a weight-tau polynomial with coefficients
/// in {-1, 0, +1}, deterministically from the challenge hash c_tilde. c_tilde's length is
/// `lambda` bytes (32/48/64 for the standard sets, but this accepts any length) — the spec ties
/// it to the security category, not to a fixed 32 bytes.
pub fn sample_challenge(c_tilde: &[u8], tau: u32) -> Poly {
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

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 204's own CoeffFromHalfByte tables (ml-dsa v0.1.1 src/sampling.rs, read directly
    // this session), reproduced by hand here as the ground truth to check the generalized
    // `coeff_from_half_byte` formula against, independent of the external-crate conformance
    // test in `dilithium.rs`.
    fn spec_coeff_from_half_byte_eta2(b: u8) -> Option<i32> {
        if b >= 15 {
            return None;
        }
        let m = match b {
            b if b < 5 => b,
            b if b < 10 => b - 5,
            b => b - 10,
        };
        Some(if m <= 2 { 2 - m as i32 } else { -((m - 2) as i32) })
    }

    fn spec_coeff_from_half_byte_eta4(b: u8) -> Option<i32> {
        if b >= 9 {
            return None;
        }
        Some(if b <= 4 { 4 - b as i32 } else { -((b - 4) as i32) })
    }

    #[test]
    fn coeff_from_half_byte_matches_spec_eta2() {
        for b in 0..16u8 {
            assert_eq!(coeff_from_half_byte(b, 2), spec_coeff_from_half_byte_eta2(b), "b={b}");
        }
    }

    #[test]
    fn coeff_from_half_byte_matches_spec_eta4() {
        for b in 0..16u8 {
            assert_eq!(coeff_from_half_byte(b, 4), spec_coeff_from_half_byte_eta4(b), "b={b}");
        }
    }
}
