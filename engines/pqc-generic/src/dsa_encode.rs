//! Key/signature byte packing for the DSA path, built entirely on the existing, unmodified
//! `encode::byte_encode`/`byte_decode`/`bits_for_q` (no new bit-packing logic invented here).
//! Not byte-exact to FIPS 204's encoding (e.g. the hint is a flat per-coefficient bitmap
//! rather than the standard's compact position-list) — consistent with this crate's existing
//! "structurally faithful, not spec-exact" posture.

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

fn encode_shifted(v: &[Poly], shift: i32, bits: u32) -> Vec<u8> {
    let coeffs: Vec<i32> = v.iter().flat_map(|p| p.coeffs.iter().map(|&c| c + shift)).collect();
    byte_encode(&coeffs, bits)
}

fn decode_shifted(bytes: &[u8], shift: i32, bits: u32, count: usize) -> Vec<Poly> {
    let coeffs = byte_decode(bytes, bits, count * N);
    coeffs
        .chunks(N)
        .map(|chunk| {
            let mut p = Poly::zero();
            for (i, &c) in chunk.iter().enumerate() {
                p.coeffs[i] = c - shift;
            }
            p
        })
        .collect()
}

fn poly_vec_byte_len(bits: u32, count: usize) -> usize {
    (bits as usize * N * count).div_ceil(8)
}

pub fn encode_pk(rho: &[u8; 32], t: &[Poly], params: &GenericDsaParams) -> Vec<u8> {
    let mut out = rho.to_vec();
    out.extend(encode_poly_vec(t, bits_for_q(params.q)));
    out
}

pub fn decode_pk(bytes: &[u8], params: &GenericDsaParams) -> Result<([u8; 32], Vec<Poly>), String> {
    let q_bits = bits_for_q(params.q);
    let t_len = poly_vec_byte_len(q_bits, params.k as usize);
    let expected = 32 + t_len;
    if bytes.len() != expected {
        return Err(format!(
            "public key has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[..32]);
    let t = decode_poly_vec(&bytes[32..], q_bits, params.k as usize);
    Ok((rho, t))
}

pub fn encode_sk(
    rho: &[u8; 32],
    cap_k: &[u8; 32],
    tr: &[u8; 32],
    s1: &[Poly],
    s2: &[Poly],
    t: &[Poly],
    params: &GenericDsaParams,
) -> Vec<u8> {
    let eta_bits = bits_for_q(2 * params.eta as i32 + 1);
    let q_bits = bits_for_q(params.q);
    let mut out = Vec::new();
    out.extend_from_slice(rho);
    out.extend_from_slice(cap_k);
    out.extend_from_slice(tr);
    out.extend(encode_shifted(s1, params.eta as i32, eta_bits));
    out.extend(encode_shifted(s2, params.eta as i32, eta_bits));
    out.extend(encode_poly_vec(t, q_bits));
    out
}

pub struct DecodedSk {
    pub rho: [u8; 32],
    pub cap_k: [u8; 32],
    pub tr: [u8; 32],
    pub s1: Vec<Poly>,
    pub s2: Vec<Poly>,
    pub t: Vec<Poly>,
}

pub fn decode_sk(bytes: &[u8], params: &GenericDsaParams) -> Result<DecodedSk, String> {
    let eta_bits = bits_for_q(2 * params.eta as i32 + 1);
    let q_bits = bits_for_q(params.q);
    let (k, l) = (params.k as usize, params.l as usize);

    let s1_len = poly_vec_byte_len(eta_bits, l);
    let s2_len = poly_vec_byte_len(eta_bits, k);
    let t_len = poly_vec_byte_len(q_bits, k);
    let expected = 96 + s1_len + s2_len + t_len;
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
    let mut tr = [0u8; 32];
    tr.copy_from_slice(&bytes[64..96]);

    let mut offset = 96;
    let s1 = decode_shifted(&bytes[offset..offset + s1_len], params.eta as i32, eta_bits, l);
    offset += s1_len;
    let s2 = decode_shifted(&bytes[offset..offset + s2_len], params.eta as i32, eta_bits, k);
    offset += s2_len;
    let t = decode_poly_vec(&bytes[offset..offset + t_len], q_bits, k);

    Ok(DecodedSk { rho, cap_k, tr, s1, s2, t })
}

pub fn encode_sig(c_tilde: &[u8; 32], z: &[Poly], h: &Hint, params: &GenericDsaParams) -> Vec<u8> {
    let z_bits = bits_for_q(2 * params.gamma1);
    let mut out = c_tilde.to_vec();
    out.extend(encode_shifted(z, params.gamma1, z_bits));

    let hint_bits: Vec<i32> = h.iter().flat_map(|p| p.iter().map(|&b| b as i32)).collect();
    out.extend(byte_encode(&hint_bits, 1));
    out
}

pub fn decode_sig(bytes: &[u8], params: &GenericDsaParams) -> Result<([u8; 32], Vec<Poly>, Hint), String> {
    let z_bits = bits_for_q(2 * params.gamma1);
    let (k, l) = (params.k as usize, params.l as usize);

    let z_len = poly_vec_byte_len(z_bits, l);
    let hint_len = (k * N).div_ceil(8);
    let expected = 32 + z_len + hint_len;
    if bytes.len() != expected {
        return Err(format!(
            "signature has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }

    let mut c_tilde = [0u8; 32];
    c_tilde.copy_from_slice(&bytes[..32]);

    let z = decode_shifted(&bytes[32..32 + z_len], params.gamma1, z_bits, l);

    let hint_flat = byte_decode(&bytes[32 + z_len..], 1, k * N);
    let h: Hint = hint_flat.chunks(N).map(|c| c.iter().map(|&x| x != 0).collect()).collect();

    Ok((c_tilde, z, h))
}
