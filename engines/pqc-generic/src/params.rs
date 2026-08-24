//! Generic-engine parameter knobs. n and q are fixed for now (see project constraints);
//! k/eta1/eta2/du/dv are the free knobs read from the incoming ParameterSet JSON.

/// Fixed for now — variable-n/q NTT-prime search is a future milestone.
pub const Q: i32 = 3329;

#[derive(Clone, Copy, Debug)]
pub struct GenericKemParams {
    pub k: u32,
    pub eta1: u32,
    pub eta2: u32,
    pub du: u32,
    pub dv: u32,
}
