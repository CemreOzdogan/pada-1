//! Bit-packing (ByteEncode/ByteDecode) and lossy rounding compression (Compress_d/Decompress_d),
//! generalized to arbitrary bit width `d` rather than the fixed widths the standard uses.

/// Pack `coeffs`, each using exactly `bits` bits, little-bit-first, into a byte vector.
pub fn byte_encode(coeffs: &[i32], bits: u32) -> Vec<u8> {
    let total_bits = bits as usize * coeffs.len();
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    let mut bit_pos = 0usize;
    for &c in coeffs {
        let c = c as u32;
        for b in 0..bits {
            let bit = (c >> b) & 1;
            out[bit_pos / 8] |= (bit as u8) << (bit_pos % 8);
            bit_pos += 1;
        }
    }
    out
}

/// Inverse of [`byte_encode`].
pub fn byte_decode(bytes: &[u8], bits: u32, count: usize) -> Vec<i32> {
    let mut out = Vec::with_capacity(count);
    let mut bit_pos = 0usize;
    for _ in 0..count {
        let mut c: u32 = 0;
        for b in 0..bits {
            let bit = (bytes[bit_pos / 8] >> (bit_pos % 8)) & 1;
            c |= (bit as u32) << b;
            bit_pos += 1;
        }
        out.push(c as i32);
    }
    out
}

/// Compress_d: round x in [0, q) to a d-bit value: round((2^d / q) * x) mod 2^d.
pub fn compress(x: i32, d: u32, q: i32) -> i32 {
    let x = x.rem_euclid(q) as i64;
    let num = x * (1i64 << d);
    let rounded = (num + (q as i64) / 2) / (q as i64);
    (rounded as i32) & ((1 << d) - 1)
}

/// Decompress_d: inverse (lossy) of [`compress`]: round((q / 2^d) * y).
pub fn decompress(y: i32, d: u32, q: i32) -> i32 {
    let y = y as i64;
    let num = y * (q as i64);
    let half = 1i64 << (d - 1);
    (((num + half) >> d) as i32).rem_euclid(q)
}

/// Number of bits needed to represent any value in [0, q).
pub fn bits_for_q(q: i32) -> u32 {
    32 - ((q - 1) as u32).leading_zeros()
}
