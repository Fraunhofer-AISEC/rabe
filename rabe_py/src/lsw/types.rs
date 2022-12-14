//! LSW implementation of structs and types
//! ---
//!
//! This is based on the  [original paper](https://some webage) and is implented in [the aw11 source](rabe::schemes::aw11)
//!
//!
//! [`]


use rabe::schemes::lsw::{
    KpAbePublicKey,
    KpAbeMasterKey,
    KpAbeSecretKey,
    KpAbeCiphertext,
};

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use crate::serializable;


#[pyclass]
#[derive(serde::Serialize,serde::Deserialize)]
pub struct PyKpAbePublicKey {
    pub pk: KpAbePublicKey,
}

#[pyclass]
#[derive(serde::Serialize,serde::Deserialize)]
pub struct PyKpAbeMasterKey {
    pub msk: KpAbeMasterKey,
}

#[pyclass]
#[derive(serde::Serialize,serde::Deserialize)]
pub struct PyKpAbeSecretKey {
    pub sk: KpAbeSecretKey,
}

#[pyclass]
#[derive(serde::Serialize,serde::Deserialize)]
pub struct PyKpAbeCiphertext {
    pub ct: KpAbeCiphertext,
}

serializable!(PyKpAbePublicKey, PyKpAbeMasterKey, PyKpAbeSecretKey, PyKpAbeCiphertext);