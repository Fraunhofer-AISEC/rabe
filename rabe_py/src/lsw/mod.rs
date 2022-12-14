use rabe::schemes::lsw::{
    setup as lsw_setup,
    encrypt as lsw_encrypt,
    keygen as lsw_keygen,
    decrypt as lsw_decrypt
};

use rabe::utils::policy::pest::PolicyLanguage;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

mod types;
use types::*;

#[pyfunction]
pub fn setup() -> PyResult<(PyKpAbePublicKey, PyKpAbeMasterKey)> {
    let (pk, msk) = lsw_setup();
    let pk = PyKpAbePublicKey{ pk };
    let msk = PyKpAbeMasterKey{ msk };
    Ok((pk, msk))
}

#[pyfunction]
pub fn keygen(
    pk: &PyKpAbePublicKey,
    msk: &PyKpAbeMasterKey,
    policy: String
)  -> PyResult<PyKpAbeSecretKey> {
    let sk = match lsw_keygen(&pk.pk, &msk.msk, &policy, PolicyLanguage::HumanPolicy) {
        Ok(sk) => PyKpAbeSecretKey{ sk },
        Err(e) => return Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
    };
    Ok(sk)
}


#[pyfunction]
pub fn encrypt(
    pk: &PyKpAbePublicKey,
    attributes: Vec<String>,
    plaintext: String
) -> PyResult<PyKpAbeCiphertext> {
    let plaintext = plaintext.into_bytes();
    match lsw_encrypt(&pk.pk, &attributes, &plaintext) {
        Some(ct) => Ok(PyKpAbeCiphertext{ ct }),
        _ => return Err(PyErr::new::<PyValueError, _>("None")),
    }
}

#[pyfunction]
pub fn decrypt(
    sk: &PyKpAbeSecretKey,
    ct: &PyKpAbeCiphertext
) -> PyResult<Vec<u8>> {
    let plaintext: Vec<u8> = match lsw_decrypt(&sk.sk, &ct.ct) {
        Ok(plaintext) => plaintext,
        Err(e) => return Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
    };
    Ok(plaintext)
}

#[pymodule]
pub fn lsw(_py: Python, m: &PyModule) -> PyResult<()> {
    crate::add_functions!(m;setup,keygen,encrypt,decrypt);
    crate::add_types!(m;PyKpAbeCiphertext, PyKpAbeMasterKey, PyKpAbePublicKey, PyKpAbeSecretKey);
    Ok(())
}