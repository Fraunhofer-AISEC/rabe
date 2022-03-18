use rabe_bn::Fr;
use sha3::{
    Digest,
    Sha3_512
};
use RabeError;
use std::ops::Mul;
use std::convert::TryInto;

/// hash a String to an element of G using Sha3_256 and generator g
pub fn sha3_hash<T: Mul<Fr, Output = T>>(g: T, data: &String) -> Result<T, RabeError> {
    let mut hasher = Sha3_512::new();
    hasher.update(data.as_bytes());
    let vec = hasher.finalize().to_vec();
    assert_eq!(vec.len(), 64);
    match vec.as_slice().try_into() {
        Ok(res) => Ok(g * Fr::interpret(res)),
        Err(e) => Err(e.into())
    }
}

/// hash a String to Fr using blake2b
pub fn sha3_hash_fr(data: &String) -> Result<Fr, RabeError> {
    let mut hasher = Sha3_512::new();
    hasher.update(data.as_bytes());
    let vec = hasher.finalize().to_vec();
    assert_eq!(vec.len(), 64);
    match vec.as_slice().try_into() {
        Ok(res) => Ok(Fr::interpret(res)),
        Err(e) => Err(e.into())
    }
}