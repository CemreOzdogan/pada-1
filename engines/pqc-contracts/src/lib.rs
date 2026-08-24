//! Rust mirror of the JSON contracts in /contracts. Keep in sync by hand for now;
//! a schema-driven codegen step is a later milestone.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    MlKem,
    MlDsa,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Engine {
    Generic,
    Reference,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KatResult {
    Pass,
    Fail,
    Na,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KemKnobs {
    pub k: u32,
    pub eta1: u32,
    pub eta2: u32,
    pub du: u32,
    pub dv: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsaKnobs {
    pub k: u32,
    pub l: u32,
    pub eta: u32,
    pub gamma1: u32,
    pub gamma2: u32,
    pub tau: u32,
    pub omega: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParameterSet {
    pub scheme: Scheme,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub is_standard: bool,
    pub n: u32,
    pub q: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kem: Option<KemKnobs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsa: Option<DsaKnobs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimingStats {
    pub median: f64,
    pub mean: f64,
    pub stddev: f64,
    pub samples: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Sizes {
    pub pk: u32,
    pub sk: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ct: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Validity {
    pub roundtrip: bool,
    pub kat: KatResult,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchResult {
    pub engine: Engine,
    pub parameter_set: ParameterSet,
    /// keygen/encaps/decaps (KEM) or keygen/sign/verify (DSA)
    pub timings_ns: std::collections::BTreeMap<String, TimingStats>,
    pub sizes_bytes: Sizes,
    pub validity: Validity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
}
