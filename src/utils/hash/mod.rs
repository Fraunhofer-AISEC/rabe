use rabe_bn::Fr;
use sha3::{
    Digest,
    Sha3_256
};
use crate::error::RabeError;
use std::ops::Mul;

/// Hash to a &String to [`rabe-bn::G1`] or [`rabe-bn::G2`] using Base g
pub fn sha3_hash<T: Mul<Fr, Output = T>>(g: T, data: &String) -> Result<T, RabeError> {
    let mut hasher = Sha3_256::new();
    hasher.update(data.as_bytes());
    match Fr::from_slice(&hasher.finalize()) {
        Ok(fr) => Ok(g * fr),
        Err(e) => Err(e.into())
    }
}

/// Hash to a &String to [`rabe-bn::Fr`]
pub fn sha3_hash_fr(data: &String) -> Result<Fr, RabeError> {
    let mut hasher = Sha3_256::new();
    hasher.update(data.as_bytes());
    match Fr::from_slice(&hasher.finalize()) {
        Ok(fr) => Ok(fr),
        Err(e) => Err(e.into())
    }
}