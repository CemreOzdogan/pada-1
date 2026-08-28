//! Key/signature byte packing for the DSA path, built on the existing, unmodified
//! `encode::byte_encode/byte_decode/bits_for_q` (no new bit-packing logic invented for the
//! poly-vector parts). FIPS 204-exact: public key stores the compressed `t1` (not full `t`),
//! secret key stores `t0` (Power2Round's low bits) and a 64-byte `tr`, and the hint uses the
//! spec's compact position-list encoding (Algorithm 20/21) rather than a flat bitmap.

use crate::dsa_params::GenericDsaParams;
use crate::dsa_rounding::Hint;
use crate::encode::{bits_for_q, byte_decode, byte_encode};
use crate::poly::{Poly, N};

pub fn encode_poly_vec(v: &[Poly], bits: u32) -> Vec<u8> {
    let coeffs: Vec<i32> = v.iter().flat_map(|p| p.coeffs.iter().copied()).collect();
    byte_encode(&coeffs, bits)
}

fn decode_poly_vec(bytes: &[u8], bits: u32, count: usize) -> Vec<Poly> {
    let coeffs = byte_decode(bytes, bits, count * N);
    coeffs
        .chunks(N)
        .map(|chunk| {
            let mut p = Poly::zero();
            p.coeffs.copy_from_slice(chunk);
            p
        })
        .collect()
}

/// FIPS 204's own BitPack convention (Algorithm 17/18, used for z, s1/s2, and t0 alike) encodes
/// `b - w`, not `w + b` — subtractive, not additive. They agree at the encode step (`b-w` and
/// `w+b` land on different byte values whenever `w != 0`) but happen to *decode* identically
/// under their own matching inverse, which is why an additive convention here could silently
/// round-trip forever without ever producing spec-matching bytes — only caught by comparing
/// actual wire bytes against another implementation (see `fips204_conformance` for z; s1/s2/t0
/// aren't independently exposed by that test, but get the same fix for the same reason).
fn encode_shifted(v: &[Poly], b: i32, bits: u32) -> Vec<u8> {
    let coeffs: Vec<i32> = v.iter().flat_map(|p| p.coeffs.iter().map(|&c| b - c)).collect();
    byte_encode(&coeffs, bits)
}

fn decode_shifted(bytes: &[u8], b: i32, bits: u32, count: usize) -> Vec<Poly> {
    let coeffs = byte_decode(bytes, bits, count * N);
    coeffs
        .chunks(N)
        .map(|chunk| {
            let mut p = Poly::zero();
            for (i, &c) in chunk.iter().enumerate() {
                p.coeffs[i] = b - c;
            }
            p
        })
        .collect()
}

fn poly_vec_byte_len(bits: u32, count: usize) -> usize {
    (bits as usize * N * count).div_ceil(8)
}

/// t1 (Power2Round's high bits) coefficients are always in [0, (q-1)>>13] — non-negative, no
/// shift needed, unlike t0.
fn t1_bits(q: i32) -> u32 {
    let t1_max = (q - 1) >> 13;
    bits_for_q(t1_max + 1)
}

/// t0 (Power2Round's low bits) coefficients are in (-2^12, 2^12], i.e. the ASYMMETRIC integer
/// range [-4095, 4096] (mod_pm's edge case includes +4096 but excludes -4096) — 8192 possible
/// values, but NOT symmetric around 0. `b = 2^(d-1) = 4096` is FIPS 204's own constant for this
/// field (`encode_shifted`'s `b - w`): the min value w=4096 encodes to 0, the max magnitude
/// w=-4095 encodes to 4096-(-4095)=8191, filling [0, 8191] exactly (13 bits) with no overflow.
const T0_SHIFT: i32 = 1 << 12;
const T0_BITS: u32 = 13;

pub fn encode_pk(rho: &[u8; 32], t1: &[Poly], params: &GenericDsaParams) -> Vec<u8> {
    let mut out = rho.to_vec();
    out.extend(encode_poly_vec(t1, t1_bits(params.q)));
    out
}

pub fn decode_pk(bytes: &[u8], params: &GenericDsaParams) -> Result<([u8; 32], Vec<Poly>), String> {
    let bits = t1_bits(params.q);
    let t1_len = poly_vec_byte_len(bits, params.k as usize);
    let expected = 32 + t1_len;
    if bytes.len() != expected {
        return Err(format!(
            "public key has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[..32]);
    let t1 = decode_poly_vec(&bytes[32..], bits, params.k as usize);
    Ok((rho, t1))
}

pub fn encode_sk(
    rho: &[u8; 32],
    cap_k: &[u8; 32],
    tr: &[u8; 64],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
    params: &GenericDsaParams,
) -> Vec<u8> {
    let eta_bits = bits_for_q(2 * params.eta as i32 + 1);
    let mut out = Vec::new();
    out.extend_from_slice(rho);
    out.extend_from_slice(cap_k);
    out.extend_from_slice(tr);
    out.extend(encode_shifted(s1, params.eta as i32, eta_bits));
    out.extend(encode_shifted(s2, params.eta as i32, eta_bits));
    out.extend(encode_shifted(t0, T0_SHIFT, T0_BITS));
    out
}

pub struct DecodedSk {
    pub rho: [u8; 32],
    pub cap_k: [u8; 32],
    pub tr: [u8; 64],
    pub s1: Vec<Poly>,
    pub s2: Vec<Poly>,
    pub t0: Vec<Poly>,
}

pub fn decode_sk(bytes: &[u8], params: &GenericDsaParams) -> Result<DecodedSk, String> {
    let eta_bits = bits_for_q(2 * params.eta as i32 + 1);
    let (k, l) = (params.k as usize, params.l as usize);

    let s1_len = poly_vec_byte_len(eta_bits, l);
    let s2_len = poly_vec_byte_len(eta_bits, k);
    let t0_len = poly_vec_byte_len(T0_BITS, k);
    let expected = 32 + 32 + 64 + s1_len + s2_len + t0_len;
    if bytes.len() != expected {
        return Err(format!(
            "secret key has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[0..32]);
    let mut cap_k = [0u8; 32];
    cap_k.copy_from_slice(&bytes[32..64]);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&bytes[64..128]);

    let mut offset = 128;
    let s1 = decode_shifted(&bytes[offset..offset + s1_len], params.eta as i32, eta_bits, l);
    offset += s1_len;
    let s2 = decode_shifted(&bytes[offset..offset + s2_len], params.eta as i32, eta_bits, k);
    offset += s2_len;
    let t0 = decode_shifted(&bytes[offset..offset + t0_len], T0_SHIFT, T0_BITS, k);

    Ok(DecodedSk { rho, cap_k, tr, s1, s2, t0 })
}

/// FIPS 204 Algorithm 20 (HintBitPack): `omega + k` bytes total — the first `omega` bytes hold
/// the actual nonzero-coefficient positions (0..256) per polynomial in order, the last `k` bytes
/// hold the running cumulative count of hints after each polynomial. Ported closely from the
/// RustCrypto `ml-dsa` reference (`hint.rs::bit_pack`/`bit_unpack`, read this session).
pub fn hint_pack(h: &Hint, omega: usize) -> Vec<u8> {
    let k = h.len();
    let mut y = vec![0u8; omega + k];
    let mut index = 0usize;
    for (i, poly_hints) in h.iter().enumerate() {
        for (j, &bit) in poly_hints.iter().enumerate() {
            if bit {
                assert!(
                    index < omega,
                    "hint_pack: total hint weight exceeds omega={omega} (caller should have \
                     rejected this candidate via hint_weight(&h) > omega before encoding)"
                );
                y[index] = j as u8;
                index += 1;
            }
        }
        y[omega + i] = index as u8;
    }
    y
}

/// FIPS 204 Algorithm 21 (HintBitUnpack). Rejects malformed encodings (non-monotonic cut
/// points, non-increasing indices within a segment) rather than silently misinterpreting them.
pub fn hint_unpack(y: &[u8], k: usize, omega: usize) -> Result<Hint, String> {
    if y.len() != omega + k {
        return Err(format!(
            "hint has wrong length: expected {} bytes, got {}",
            omega + k,
            y.len()
        ));
    }

    let cuts: Vec<usize> = y[omega..omega + k].iter().map(|&b| b as usize).collect();
    if !cuts.windows(2).all(|w| w[0] <= w[1]) {
        return Err("hint cut points must be non-decreasing".to_string());
    }
    let max_cut = *cuts.iter().max().unwrap_or(&0);
    if max_cut > omega {
        return Err(format!("hint cut point {max_cut} exceeds omega={omega}"));
    }

    let mut h: Hint = vec![vec![false; N]; k];
    let mut start = 0usize;
    for (i, &end) in cuts.iter().enumerate() {
        let indices = &y[start..end];
        if !indices.windows(2).all(|w| w[0] < w[1]) {
            return Err(format!("hint indices for polynomial {i} must be strictly increasing"));
        }
        for &j in indices {
            h[i][j as usize] = true;
        }
        start = end;
    }

    Ok(h)
}

pub fn encode_sig(c_tilde: &[u8], z: &[Poly], h: &Hint, params: &GenericDsaParams) -> Vec<u8> {
    let z_bits = bits_for_q(2 * params.gamma1);
    let mut out = c_tilde.to_vec();
    out.extend(encode_shifted(z, params.gamma1, z_bits));
    out.extend(hint_pack(h, params.omega as usize));
    out
}

pub fn decode_sig(bytes: &[u8], params: &GenericDsaParams) -> Result<(Vec<u8>, Vec<Poly>, Hint), String> {
    let z_bits = bits_for_q(2 * params.gamma1);
    let (k, l) = (params.k as usize, params.l as usize);
    let lambda = params.lambda as usize;

    let z_len = poly_vec_byte_len(z_bits, l);
    let hint_len = params.omega as usize + k;
    let expected = lambda + z_len + hint_len;
    if bytes.len() != expected {
        return Err(format!(
            "signature has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }

    let c_tilde = bytes[..lambda].to_vec();
    let z = decode_shifted(&bytes[lambda..lambda + z_len], params.gamma1, z_bits, l);
    let h = hint_unpack(&bytes[lambda + z_len..], k, params.omega as usize)?;

    Ok((c_tilde, z, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_pack_round_trip() {
        let k = 3;
        let omega = 10;
        let mut h: Hint = vec![vec![false; N]; k];
        h[0][0] = true;
        h[0][10] = true;
        h[1][5] = true;
        // h[2] left empty
        let packed = hint_pack(&h, omega);
        assert_eq!(packed.len(), omega + k);
        let unpacked = hint_unpack(&packed, k, omega).unwrap();
        assert_eq!(h, unpacked);
    }

    #[test]
    fn hint_unpack_rejects_wrong_length() {
        assert!(hint_unpack(&[0u8; 3], 3, 10).is_err());
    }

    #[test]
    fn t0_encode_round_trips_full_range_including_edges() {
        // Regression test for a real bug: shifting t0's asymmetric [-4095, 4096] range by its
        // own max (4096) pushed the top value to 8192, overflowing the 13-bit field and
        // silently truncating to 0. +4095 is the correct shift (maps exactly onto [0, 8191]).
        for &edge in &[-4095i32, -1, 0, 1, 4095, 4096] {
            let mut p = Poly::zero();
            p.coeffs[0] = edge;
            let encoded = encode_shifted(&[p], T0_SHIFT, T0_BITS);
            assert_eq!(encoded.len(), poly_vec_byte_len(T0_BITS, 1), "edge={edge}");
            let decoded = decode_shifted(&encoded, T0_SHIFT, T0_BITS, 1);
            assert_eq!(decoded[0].coeffs[0], edge, "t0={edge} did not round-trip");
        }
    }
}
