//! Key byte packing for the custom KEM path, built entirely on the existing, unmodified
//! `encode::byte_encode/byte_decode/bits_for_q` (no new bit-packing logic invented here) —
//! same approach as `dsa_encode.rs`, just for `Vec<Vec<i32>>` polynomial vectors instead of
//! fixed-size `Poly`s.

use crate::custom_kem_params::GenericCustomKemParams;
use crate::encode::{bits_for_q, byte_decode, byte_encode};

pub fn encode_poly_vec(polys: &[Vec<i32>], bits: u32) -> Vec<u8> {
    let coeffs: Vec<i32> = polys.iter().flat_map(|p| p.iter().copied()).collect();
    byte_encode(&coeffs, bits)
}

fn decode_poly_vec(bytes: &[u8], bits: u32, count: usize, n: usize) -> Vec<Vec<i32>> {
    let coeffs = byte_decode(bytes, bits, count * n);
    coeffs.chunks(n).map(|chunk| chunk.to_vec()).collect()
}

fn encode_shifted(polys: &[Vec<i32>], shift: i32, bits: u32) -> Vec<u8> {
    let coeffs: Vec<i32> = polys.iter().flat_map(|p| p.iter().map(|&c| c + shift)).collect();
    byte_encode(&coeffs, bits)
}

fn decode_shifted(bytes: &[u8], shift: i32, bits: u32, count: usize, n: usize) -> Vec<Vec<i32>> {
    let coeffs = byte_decode(bytes, bits, count * n);
    coeffs
        .chunks(n)
        .map(|chunk| chunk.iter().map(|&c| c - shift).collect())
        .collect()
}

fn poly_vec_byte_len(bits: u32, count: usize, n: usize) -> usize {
    (bits as usize * n * count).div_ceil(8)
}

pub fn encode_pk(rho: &[u8; 32], t: &[Vec<i32>], params: &GenericCustomKemParams) -> Vec<u8> {
    let mut out = rho.to_vec();
    out.extend(encode_poly_vec(t, bits_for_q(params.q)));
    out
}

pub fn decode_pk(bytes: &[u8], params: &GenericCustomKemParams) -> Result<([u8; 32], Vec<Vec<i32>>), String> {
    let q_bits = bits_for_q(params.q);
    let t_len = poly_vec_byte_len(q_bits, params.k as usize, params.n);
    let expected = 32 + t_len;
    if bytes.len() != expected {
        return Err(format!(
            "public key has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[..32]);
    let t = decode_poly_vec(&bytes[32..], q_bits, params.k as usize, params.n);
    Ok((rho, t))
}

pub fn encode_sk(s: &[Vec<i32>], params: &GenericCustomKemParams) -> Vec<u8> {
    let eta_bits = bits_for_q(2 * params.eta1 as i32 + 1);
    encode_shifted(s, params.eta1 as i32, eta_bits)
}

pub fn decode_sk(bytes: &[u8], params: &GenericCustomKemParams) -> Result<Vec<Vec<i32>>, String> {
    let eta_bits = bits_for_q(2 * params.eta1 as i32 + 1);
    let expected = poly_vec_byte_len(eta_bits, params.k as usize, params.n);
    if bytes.len() != expected {
        return Err(format!(
            "secret key has wrong length: expected {expected} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(decode_shifted(bytes, params.eta1 as i32, eta_bits, params.k as usize, params.n))
}
