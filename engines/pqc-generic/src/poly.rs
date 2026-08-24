//! Polynomial ring arithmetic over Z_q[x]/(x^N + 1), N fixed at 256 for now.
//! Schoolbook (O(N^2)) multiplication — no NTT. Fine at N=256 exploration scale;
//! an NTT is a later optimization, not a correctness requirement.

pub const N: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Poly {
    pub fn zero() -> Self {
        Poly { coeffs: [0; N] }
    }

    pub fn add(&self, other: &Poly, q: i32) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = (self.coeffs[i] + other.coeffs[i]).rem_euclid(q);
        }
        out
    }

    pub fn sub(&self, other: &Poly, q: i32) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = (self.coeffs[i] - other.coeffs[i]).rem_euclid(q);
        }
        out
    }

    /// Multiplication mod (x^N + 1), reduced mod q.
    pub fn mul(&self, other: &Poly, q: i32) -> Poly {
        let mut wide = [0i64; 2 * N];
        for i in 0..N {
            if self.coeffs[i] == 0 {
                continue;
            }
            let a = self.coeffs[i] as i64;
            for j in 0..N {
                wide[i + j] += a * other.coeffs[j] as i64;
            }
        }
        let mut out = Poly::zero();
        for i in 0..N {
            // x^N == -1 (mod x^N + 1)
            let reduced = wide[i] - wide[i + N];
            out.coeffs[i] = reduced.rem_euclid(q as i64) as i32;
        }
        out
    }
}

/// Dot product of two same-length vectors of polynomials, mod q.
pub fn dot(a: &[Poly], b: &[Poly], q: i32) -> Poly {
    a.iter()
        .zip(b.iter())
        .fold(Poly::zero(), |acc, (x, y)| acc.add(&x.mul(y, q), q))
}
