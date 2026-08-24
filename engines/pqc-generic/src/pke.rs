//! Kyber-like public-key encryption core: keygen / encrypt / decrypt over a runtime-chosen
//! (k, eta1, eta2, du, dv). Structurally faithful to FIPS 203's K-PKE (same matrix-vector
//! shape, CBD noise, compression before transmission) but NOT byte-exact spec compliance —
//! see the module-level TODO in `kem.rs` for what's simplified.

use crate::encode::{bits_for_q, byte_decode, byte_encode, compress, decompress};
use crate::params::{GenericKemParams, Q};
use crate::poly::{dot, Poly, N};
use crate::sample::{cbd, cbd_bytes_needed, prf, sample_uniform};

#[derive(Clone)]
pub struct PublicKey {
    pub t: Vec<Poly>,
    pub rho: [u8; 32],
}

#[derive(Clone)]
pub struct SecretKey {
    pub s: Vec<Poly>,
}

pub struct Ciphertext {
    pub u_bytes: Vec<u8>,
    pub v_bytes: Vec<u8>,
}

fn derive32(seed: &[u8; 32], nonce: u8) -> [u8; 32] {
    prf(seed, nonce, 32).try_into().unwrap()
}

fn expand_a(rho: &[u8; 32], k: usize) -> Vec<Vec<Poly>> {
    (0..k)
        .map(|i| {
            (0..k)
                .map(|j| sample_uniform(rho, i as u8, j as u8, Q))
                .collect()
        })
        .collect()
}

fn message_to_poly(m: &[u8; 32]) -> Poly {
    let mut out = Poly::zero();
    for i in 0..N {
        let bit = (m[i / 8] >> (i % 8)) & 1;
        out.coeffs[i] = decompress(bit as i32, 1, Q);
    }
    out
}

fn poly_to_message(p: &Poly) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..N {
        let bit = compress(p.coeffs[i], 1, Q) as u8;
        out[i / 8] |= bit << (i % 8);
    }
    out
}

pub fn keygen(params: &GenericKemParams, seed: [u8; 32]) -> (PublicKey, SecretKey) {
    let k = params.k as usize;
    let rho = derive32(&seed, 0);
    let sigma = derive32(&seed, 1);
    let a = expand_a(&rho, k);

    let s: Vec<Poly> = (0..k)
        .map(|i| cbd(&prf(&sigma, i as u8, cbd_bytes_needed(params.eta1)), params.eta1, Q))
        .collect();
    let e: Vec<Poly> = (0..k)
        .map(|i| {
            cbd(
                &prf(&sigma, (k + i) as u8, cbd_bytes_needed(params.eta1)),
                params.eta1,
                Q,
            )
        })
        .collect();

    let t: Vec<Poly> = (0..k).map(|i| dot(&a[i], &s, Q).add(&e[i], Q)).collect();

    (PublicKey { t, rho }, SecretKey { s })
}

pub fn encrypt(
    params: &GenericKemParams,
    pk: &PublicKey,
    m: &[u8; 32],
    coins: &[u8; 32],
) -> Ciphertext {
    let k = params.k as usize;
    let a = expand_a(&pk.rho, k);

    let r: Vec<Poly> = (0..k)
        .map(|i| cbd(&prf(coins, i as u8, cbd_bytes_needed(params.eta1)), params.eta1, Q))
        .collect();
    let e1: Vec<Poly> = (0..k)
        .map(|i| {
            cbd(
                &prf(coins, (k + i) as u8, cbd_bytes_needed(params.eta2)),
                params.eta2,
                Q,
            )
        })
        .collect();
    let e2 = cbd(
        &prf(coins, (2 * k) as u8, cbd_bytes_needed(params.eta2)),
        params.eta2,
        Q,
    );

    // u = A^T r + e1
    let u: Vec<Poly> = (0..k)
        .map(|i| {
            let column: Vec<Poly> = (0..k).map(|j| a[j][i].clone()).collect();
            dot(&column, &r, Q).add(&e1[i], Q)
        })
        .collect();

    let mu = message_to_poly(m);
    let v = dot(&pk.t, &r, Q).add(&e2, Q).add(&mu, Q);

    let qbits_du = params.du;
    let u_compressed: Vec<i32> = u
        .iter()
        .flat_map(|p| p.coeffs.iter().map(|&c| compress(c, qbits_du, Q)))
        .collect();
    let v_compressed: Vec<i32> = v.coeffs.iter().map(|&c| compress(c, params.dv, Q)).collect();

    Ciphertext {
        u_bytes: byte_encode(&u_compressed, params.du),
        v_bytes: byte_encode(&v_compressed, params.dv),
    }
}

pub fn decrypt(params: &GenericKemParams, sk: &SecretKey, ct: &Ciphertext) -> [u8; 32] {
    let k = params.k as usize;

    let u_vals = byte_decode(&ct.u_bytes, params.du, k * N);
    let u: Vec<Poly> = u_vals
        .chunks(N)
        .map(|chunk| {
            let mut p = Poly::zero();
            for (i, &c) in chunk.iter().enumerate() {
                p.coeffs[i] = decompress(c, params.du, Q);
            }
            p
        })
        .collect();

    let v_vals = byte_decode(&ct.v_bytes, params.dv, N);
    let mut v = Poly::zero();
    for (i, &c) in v_vals.iter().enumerate() {
        v.coeffs[i] = decompress(c, params.dv, Q);
    }

    let mu = v.sub(&dot(&sk.s, &u, Q), Q);
    poly_to_message(&mu)
}

pub fn encode_pk_bytes(pk: &PublicKey) -> Vec<u8> {
    let qbits = bits_for_q(Q);
    let coeffs: Vec<i32> = pk.t.iter().flat_map(|p| p.coeffs.iter().copied()).collect();
    let mut bytes = byte_encode(&coeffs, qbits);
    bytes.extend_from_slice(&pk.rho);
    bytes
}

pub fn encode_sk_bytes(sk: &SecretKey) -> Vec<u8> {
    let qbits = bits_for_q(Q);
    let coeffs: Vec<i32> = sk.s.iter().flat_map(|p| p.coeffs.iter().copied()).collect();
    byte_encode(&coeffs, qbits)
}
