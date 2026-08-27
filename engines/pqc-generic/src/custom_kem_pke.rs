//! Kyber-like public-key encryption core for the custom KEM engine: keygen / encrypt / decrypt
//! over a runtime-chosen (k, n, q, eta1, eta2, du, dv). Same algorithm shape as `pke.rs`
//! (matrix-vector structure, CBD noise, compression before transmission), generalized to
//! runtime n via `Vec<i32>` polynomials and real NTT multiplication instead of schoolbook.
//! Same "structurally faithful, not spec-exact" posture as `pke.rs`/`dilithium.rs`.

use crate::custom_kem_ntt::{build_table, ntt_mul, NttTable};
use crate::custom_kem_params::GenericCustomKemParams;
use crate::custom_kem_sample::{sample_eta_vec, sample_uniform_vec};
use crate::encode::{byte_decode, byte_encode, compress, decompress};
use crate::sample::prf;

#[derive(Clone)]
pub struct PublicKey {
    pub t: Vec<Vec<i32>>,
    pub rho: [u8; 32],
}

#[derive(Clone)]
pub struct SecretKey {
    pub s: Vec<Vec<i32>>,
}

pub struct Ciphertext {
    pub u_bytes: Vec<u8>,
    pub v_bytes: Vec<u8>,
}

fn derive32(seed: &[u8; 32], nonce: u8) -> [u8; 32] {
    prf(seed, nonce, 32).try_into().unwrap()
}

fn expand_a(rho: &[u8; 32], k: usize, n: usize, q: i32) -> Vec<Vec<Vec<i32>>> {
    (0..k)
        .map(|i| (0..k).map(|j| sample_uniform_vec(rho, i as u8, j as u8, q, n)).collect())
        .collect()
}

fn vec_add(a: &[i32], b: &[i32], q: i32) -> Vec<i32> {
    a.iter().zip(b.iter()).map(|(&x, &y)| (x + y).rem_euclid(q)).collect()
}

fn vec_sub(a: &[i32], b: &[i32], q: i32) -> Vec<i32> {
    a.iter().zip(b.iter()).map(|(&x, &y)| (x - y).rem_euclid(q)).collect()
}

/// Dot product of two same-length vectors of polynomials, via NTT multiplication.
fn poly_vec_dot(a: &[Vec<i32>], b: &[Vec<i32>], table: &NttTable, q: i32) -> Vec<i32> {
    let mut acc = vec![0i32; table.n];
    for (ai, bi) in a.iter().zip(b.iter()) {
        acc = vec_add(&acc, &ntt_mul(ai, bi, table), q);
    }
    acc
}

fn message_to_poly(m: &[u8], n: usize, q: i32) -> Vec<i32> {
    (0..n)
        .map(|i| {
            let bit = (m[i / 8] >> (i % 8)) & 1;
            decompress(bit as i32, 1, q)
        })
        .collect()
}

fn poly_to_message(p: &[i32], n: usize, q: i32) -> Vec<u8> {
    let mut out = vec![0u8; n.div_ceil(8)];
    for (i, &c) in p.iter().enumerate() {
        let bit = compress(c, 1, q) as u8;
        out[i / 8] |= bit << (i % 8);
    }
    out
}

pub fn keygen(params: &GenericCustomKemParams, seed: [u8; 32]) -> (PublicKey, SecretKey) {
    let table = build_table(params.n, params.q).expect("params already validated by build_params");
    let k = params.k as usize;
    let rho = derive32(&seed, 0);
    let sigma = derive32(&seed, 1);
    let a = expand_a(&rho, k, params.n, params.q);

    let s: Vec<Vec<i32>> = (0..k).map(|i| sample_eta_vec(&sigma, i as u16, params.eta1, params.n)).collect();
    let e: Vec<Vec<i32>> = (0..k)
        .map(|i| sample_eta_vec(&sigma, (k + i) as u16, params.eta1, params.n))
        .collect();

    let t: Vec<Vec<i32>> = (0..k)
        .map(|i| vec_add(&poly_vec_dot(&a[i], &s, &table, params.q), &e[i], params.q))
        .collect();

    (PublicKey { t, rho }, SecretKey { s })
}

pub fn encrypt(params: &GenericCustomKemParams, pk: &PublicKey, m: &[u8], coins: &[u8; 32]) -> Ciphertext {
    let table = build_table(params.n, params.q).expect("params already validated by build_params");
    let k = params.k as usize;
    let a = expand_a(&pk.rho, k, params.n, params.q);

    let r: Vec<Vec<i32>> = (0..k).map(|i| sample_eta_vec(coins, i as u16, params.eta1, params.n)).collect();
    let e1: Vec<Vec<i32>> = (0..k)
        .map(|i| sample_eta_vec(coins, (k + i) as u16, params.eta2, params.n))
        .collect();
    let e2 = sample_eta_vec(coins, (2 * k) as u16, params.eta2, params.n);

    // u = A^T r + e1
    let u: Vec<Vec<i32>> = (0..k)
        .map(|i| {
            let column: Vec<Vec<i32>> = (0..k).map(|j| a[j][i].clone()).collect();
            vec_add(&poly_vec_dot(&column, &r, &table, params.q), &e1[i], params.q)
        })
        .collect();

    let mu = message_to_poly(m, params.n, params.q);
    let t_dot_r = poly_vec_dot(&pk.t, &r, &table, params.q);
    let v = vec_add(&vec_add(&t_dot_r, &e2, params.q), &mu, params.q);

    let u_compressed: Vec<i32> = u
        .iter()
        .flat_map(|p| p.iter().map(|&c| compress(c, params.du, params.q)))
        .collect();
    let v_compressed: Vec<i32> = v.iter().map(|&c| compress(c, params.dv, params.q)).collect();

    Ciphertext {
        u_bytes: byte_encode(&u_compressed, params.du),
        v_bytes: byte_encode(&v_compressed, params.dv),
    }
}

pub fn decrypt(params: &GenericCustomKemParams, sk: &SecretKey, ct: &Ciphertext) -> Vec<u8> {
    let table = build_table(params.n, params.q).expect("params already validated by build_params");
    let k = params.k as usize;
    let n = params.n;

    let u_vals = byte_decode(&ct.u_bytes, params.du, k * n);
    let u: Vec<Vec<i32>> = u_vals
        .chunks(n)
        .map(|chunk| chunk.iter().map(|&c| decompress(c, params.du, params.q)).collect())
        .collect();

    let v_vals = byte_decode(&ct.v_bytes, params.dv, n);
    let v: Vec<i32> = v_vals.iter().map(|&c| decompress(c, params.dv, params.q)).collect();

    let s_dot_u = poly_vec_dot(&sk.s, &u, &table, params.q);
    let mu = vec_sub(&v, &s_dot_u, params.q);
    poly_to_message(&mu, n, params.q)
}
