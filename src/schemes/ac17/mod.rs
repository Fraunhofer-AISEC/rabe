//! `AC17` scheme by Shashank Agrawal, Melissa Chase.
//!
//! * Developped by Shashank Agrawal, Melissa Chase, "FAME: Fast Attribute-based Message Encryption", see Section 3
//! * Published in Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security 2017
//! * Available from <https://eprint.iacr.org/2017/807.pdf>
//! * Type: encryption (attribute-based)
//! * Setting: bilinear groups (asymmetric)
//! * Authors: Georg Bramm
//! * Date: 04/2018
//!
//! # Examples
//!
//! An AC17 KP-ABE Example:
//!
//! ```
//! use rabe::schemes::ac17::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//! let (pk, msk) = setup();
//! let plaintext = String::from("our plaintext!").into_bytes();
//! let policy = String::from(r#""A" and "B""#);
//! let ct: Ac17KpCiphertext =  kp_encrypt(&pk, &vec![
//!     "A".to_string(),
//!     "B".to_string()
//! ], &plaintext).unwrap();
//! let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
//! assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
//! ```
//!
//! An AC17 CP-ABE Example:
//!
//! ```
//! use rabe::schemes::ac17::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//! let (pk, msk) = setup();
//! let plaintext = String::from("our plaintext!").into_bytes();
//! let policy = String::from(r#""A" and "B""#);
//! let ct: Ac17CpCiphertext =  cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
//! let sk: Ac17CpSecretKey = cp_keygen(&msk, &vec![
//!     "A".to_string(),
//!     "B".to_string()
//! ]).unwrap();
//! assert_eq!(cp_decrypt(&sk, &ct).unwrap(), plaintext);
//! ```
use std::{
    string::String,
    ops::Neg
};
use rabe_bn::{Group, Gt, G1, G2, Fr, pairing};
use rand::Rng;
use utils::{
    policy::msp::AbePolicy,
    tools::*,
    secretsharing::*,
    aes::*,
    hash::sha3_hash
};
use utils::policy::pest::{PolicyLanguage, parse, PolicyType};
use crate::error::RabeError;
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// An AC17 Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17PublicKey {
    pub _g: G1,
    pub _h_a: Vec<G2>,
    pub _e_gh_ka: Vec<Gt>,
}

/// An AC17 Public Key (MK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17MasterKey {
    pub _g: G1,
    pub _h: G2,
    pub _g_k: Vec<G1>,
    pub _a: Vec<Fr>,
    pub _b: Vec<Fr>,
}

/// An AC17 Ciphertext (CT)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17Ciphertext {
    pub _c_0: Vec<G2>,
    pub _c: Vec<(String, Vec<G1>)>,
    pub _c_p: Gt,
    pub _ct: Vec<u8>,
}

/// An AC17 CP-ABE Ciphertext (CT), composed of a policy and an Ac17Ciphertext.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17CpCiphertext {
    pub _policy: (String, PolicyLanguage),
    pub _ct: Ac17Ciphertext,
}

/// An AC17 KP-ABE Ciphertext (CT), composed of a set of attributes and an Ac17Ciphertext.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17KpCiphertext {
    pub _attr: Vec<String>,
    pub _ct: Ac17Ciphertext,
}

/// An AC17 Secret Key (SK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17SecretKey {
    pub _k_0: Vec<G2>,
    pub _k: Vec<(String, Vec<G1>)>,
    pub _k_p: Vec<G1>,
}

/// An AC17 KP-ABE Secret Key (SK), composed of a policy and an Ac17Ciphertext.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17KpSecretKey {
    pub _policy: (String, PolicyLanguage),
    pub _sk: Ac17SecretKey,
}

/// An AC17 CP-ABE Secret Key (SK), composed of a set of attributes and an Ac17Ciphertext.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Ac17CpSecretKey {
    pub _attr: Vec<String>,
    pub _sk: Ac17SecretKey,
}

/// The assumption size of the pairing in the AC17 scheme.
const ASSUMPTION_SIZE: usize = 2;

/// The setup algorithm of both AC17CP and AC17KP. Generates an Ac17PublicKey and an Ac17MasterKey.
pub fn setup() -> (Ac17PublicKey, Ac17MasterKey) {
    // random number generator
    let mut _rng = rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let _g:G1 = _rng.gen();
    let _h:G2 = _rng.gen();
    //pairing
    let _e_gh = pairing(_g, _h);
    // A and B vectors
    let mut _a: Vec<Fr> = Vec::new();
    let mut _b: Vec<Fr> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _a.push(_rng.gen());
        _b.push(_rng.gen());
    }
    // k vetor
    let mut _k: Vec<Fr> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k.push(_rng.gen());
    }
    // h_A vetor
    let mut _h_a: Vec<G2> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _h_a.push(_h * _a[_i]);
    }
    _h_a.push(_h);
    // compute the e([k]_1,  [A]_2) term
    let mut _g_k: Vec<G1> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _g_k.push(_g * _k[_i]);
    }

    let mut _e_gh_ka: Vec<Gt> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _e_gh_ka.push(_e_gh.pow(_k[_i] * _a[_i] + _k[ASSUMPTION_SIZE]));
    }
    // return PK and MSK
    return (
        Ac17PublicKey {_g, _h_a, _e_gh_ka},
        Ac17MasterKey {_g, _h, _g_k, _a, _b}
    )
}

/// The key generation algorithm of AC17CP. Generates an Ac17CpSecretKey using a Ac17MasterKey and a set of attributes given as Vec<String>.
///
/// # Arguments
///
///	* `msk` - A Master Key (MSK), generated by the function setup()
///	* `attributes` - A Vector of String attributes assigned to this user key
///
pub fn cp_keygen(msk: &Ac17MasterKey, attributes: &Vec<String>) -> Result<Ac17CpSecretKey, RabeError> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if attributes.is_empty() {
        return Err(RabeError::new("empty attributes!"));
    }
    // random number generator
    let mut _rng = rand::thread_rng();
    // pick randomness
    let mut _r: Vec<Fr> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand:Fr = _rng.gen();
        _r.push(_rand);
        _sum = _sum + _rand;
    }
    // first compute Br as it will be used later
    let mut _br: Vec<Fr> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _br.push(msk._b[_i] * _r[_i])
    }
    _br.push(_sum);
    // now computer [Br]_2
    let mut _k_0: Vec<G2> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k_0.push(msk._h * _br[_i])
    }
    // compute [W_1 Br]_1, ...
    let mut _k: Vec<(String, Vec<G1>)> = Vec::new();
    let _a = msk._a.clone();
    let _g = msk._g.clone();
    for _attr in attributes {
        let mut _key: Vec<G1> = Vec::new();
        let _sigma_attr:Fr = _rng.gen();
        for _t in 0usize..ASSUMPTION_SIZE {
            let mut _prod = G1::zero();
            let _a_t = _a[_t].inverse().unwrap();
            for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                let mut _hash = String::new();
                _hash.push_str(&_attr);
                _hash.push_str(&_l.to_string());
                _hash.push_str(&_t.to_string());
                _prod = _prod + (sha3_hash(msk._g, &_hash).expect("could not hash _hash") * (_br[_l] * _a_t));
            }
            _prod = _prod + (msk._g * (_sigma_attr * _a_t));
            _key.push(_prod);
        }
        _key.push(msk._g * _sigma_attr.neg());
        _k.push((_attr.to_string(), _key));
    }
    // compute [k + VBr]_1
    let mut _k_p: Vec<G1> = Vec::new();
    let _g_k = msk._g_k.clone();
    let _sigma:Fr = _rng.gen();
    for _t in 0usize..ASSUMPTION_SIZE {
        let mut _prod = _g_k[_t];
        let _a_t = _a[_t].inverse().unwrap();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _hash = String::new();
            _hash.push_str(&String::from("01"));
            _hash.push_str(&_l.to_string());
            _hash.push_str(&_t.to_string());
            _prod = _prod + (sha3_hash(msk._g, &_hash).expect("could not hash _hash") * (_br[_l] * _a_t));
        }
        _prod = _prod + (msk._g * (_sigma * _a_t));
        _k_p.push(_prod);
    }
    _k_p.push(_g_k[ASSUMPTION_SIZE] + (msk._g * _sigma.neg()));
    let _attr = attributes.clone();
    let _sk = Ac17SecretKey {_k_0, _k, _k_p};
    Ok(Ac17CpSecretKey {_attr, _sk})
}

/// The encrypt algorithm of AC17CP. Generates an Ac17CpCiphertext using an Ac17PublicKey, an access policy given as String and some plaintext data given as [u8].
///
/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `policy` - An access policy given as JSON String
///	* `plaintext` - plaintext data given as a Vector of u8
///
pub fn cp_encrypt(
    pk: &Ac17PublicKey,
    policy: &String,
    plaintext: &[u8],
    language: PolicyLanguage,
) -> Result<Ac17CpCiphertext, RabeError> {
    // random number generator
    let mut _rng = rand::thread_rng();
    match parse(policy, language) {
        Ok(_policy) => {
            // an msp policy from the given String
            let msp: AbePolicy = AbePolicy::from_policy(&_policy).unwrap();
            let _num_cols = msp._m[0].len();
            let _num_rows = msp._m.len();
            // pick randomness
            let mut _s: Vec<Fr> = Vec::new();
            let mut _sum = Fr::zero();
            for _i in 0usize..ASSUMPTION_SIZE {
                let _rand:Fr = _rng.gen();
                _s.push(_rand);
                _sum = _sum + _rand;
            }
            // compute the [As]_2 term
            let mut _c_0: Vec<G2> = Vec::new();
            let _h_a = pk._h_a.clone();
            for _i in 0usize..ASSUMPTION_SIZE {
                _c_0.push(_h_a[_i] * _s[_i]);
            }
            _c_0.push(_h_a[ASSUMPTION_SIZE] * _sum);
            // compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms
            // pre-compute hashes
            let mut _hash_table: Vec<Vec<Vec<G1>>> = Vec::new();
            for _j in 0usize.._num_cols {
                let mut _x: Vec<Vec<G1>> = Vec::new();
                let mut _hash1 = String::new();
                _hash1.push_str(&String::from("0"));
                _hash1.push_str(&(_j + 1).to_string());
                for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                    let mut _y: Vec<G1> = Vec::new();
                    let mut _hash2 = String::new();
                    _hash2.push_str(&_hash1);
                    _hash2.push_str(&_l.to_string());
                    for _t in 0usize..ASSUMPTION_SIZE {
                        let mut _hash3 = String::new();
                        _hash3.push_str(&_hash2);
                        _hash3.push_str(&_t.to_string());
                        match sha3_hash(pk._g, &_hash3) {
                            Ok(hashed) => _y.push(hashed),
                            Err(e) => return Err(e)
                        };
                    }
                    _x.push(_y)
                }
                _hash_table.push(_x);
            }
            let mut _c: Vec<(String, Vec<G1>)> = Vec::new();
            for _i in 0usize.._num_rows {
                let mut _ct: Vec<G1> = Vec::new();
                for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                    let mut _prod = G1::zero();
                    for _t in 0usize..ASSUMPTION_SIZE {
                        let mut _hash = String::new();
                        _hash.push_str(&msp._pi[_i]);
                        _hash.push_str(&_l.to_string());
                        _hash.push_str(&_t.to_string());
                        match sha3_hash(pk._g, &_hash) {
                            Ok(mut hash) => {
                                for _j in 0usize.._num_cols {
                                    if msp._m[_i][_j] == 1 {
                                        hash = hash + _hash_table[_j][_l][_t];
                                    } else if msp._m[_i][_j] == -1 {
                                        hash = hash - _hash_table[_j][_l][_t];
                                    }
                                }
                                _prod = _prod + (hash * _s[_t]);
                            },
                            Err(e) => return Err(e)
                        }
                    }
                    _ct.push(_prod);
                }
                _c.push((msp._pi[_i].to_string(), _ct));
            }
            let mut _c_p = Gt::one();
            for _i in 0usize..ASSUMPTION_SIZE {
                _c_p = _c_p * (pk._e_gh_ka[_i].pow(_s[_i]));
            }
            // random msg
            let _msg: Gt = _rng.gen();
            let _ct = encrypt_symmetric(_msg, &plaintext.to_vec()).unwrap();
            _c_p = _c_p * _msg;
            //Encrypt plaintext using derived key from secret
            Ok(Ac17CpCiphertext {
                _policy: (policy.to_string(), language),
                _ct: Ac17Ciphertext { _c_0, _c, _c_p, _ct},
            })
        },
        Err(e) => Err(e)
    }
}

/// The decrypt algorithm of AC17CP. Reconstructs the original plaintext data as Vec<u8>, given a Ac17CpCiphertext with a matching Ac17CpSecretKey.
///
/// # Arguments
///
///	* `sk` - A Secret Key (SK), generated by the function cp_keygen()
///	* `ct` - An AC17CP Ciphertext
///
pub fn cp_decrypt(sk: &Ac17CpSecretKey, ct: &Ac17CpCiphertext) -> Result<Vec<u8>, RabeError> {
    match parse(ct._policy.0.as_ref(), ct._policy.1) {
        Ok(pol) => {
            return if traverse_policy(&sk._attr, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in cp_decrypt: attributes in SK do not match policy in CT."))
            } else {
                match calc_pruned(&sk._attr, &pol, None) {
                    Err(e) => Err(e),
                    Ok((_match, _list)) => {
                        if _match {
                            let mut _prod1_gt = Gt::one();
                            let mut _prod2_gt = Gt::one();
                            for _i in 0usize..(ASSUMPTION_SIZE + 1) {
                                let mut _prod_h = G1::zero();
                                let mut _prod_g = G1::zero();
                                for _current in _list.iter() {
                                    for _attr in ct._ct._c.iter() {
                                        if _attr.0 == _current.to_string() {
                                            _prod_g = _prod_g + _attr.1[_i];
                                        }
                                    }
                                    for _attr in sk._sk._k.iter() {
                                        if _attr.0 == _current.to_string() {
                                            _prod_h = _prod_h + _attr.1[_i];
                                        }
                                    }
                                }
                                _prod1_gt = _prod1_gt * pairing(sk._sk._k_p[_i] + _prod_h, ct._ct._c_0[_i]);
                                _prod2_gt = _prod2_gt * pairing(_prod_g, sk._sk._k_0[_i]);
                            }
                            let _msg = ct._ct._c_p * (_prod2_gt * _prod1_gt.inverse());
                            // Decrypt plaintext using derived secret from cp-abe scheme
                            decrypt_symmetric(_msg, &ct._ct._ct)
                        } else {
                            Err(RabeError::new("Error: attributes in sk do not match policy in ct."))
                        }
                    }
                }
            };
        },
        Err(e) => Err(e)
    }
}

/// The key generation algorithm of AC17KP. Generates an Ac17KpSecretKey using an Ac17MasterKey and a policy given as String.
///
/// # Arguments
///
///	* `msk` - A Master Key (MSK), generated by the function setup()
///	* `policy` - An access policy given as JSON String
///
pub fn kp_keygen(
    msk: &Ac17MasterKey,
    policy: &String,
    lang: PolicyLanguage) -> Result<Ac17KpSecretKey, RabeError> {
    // random number generator
    let mut _rng = rand::thread_rng();
    match parse(policy, lang) {
        Ok(pol) => {
            // an msp policy from the given String
            let msp: AbePolicy = AbePolicy::from_policy(&pol).unwrap();
            let _num_cols = msp._m[0].len();
            let _num_rows = msp._m.len();
            // pick randomness
            let mut _r: Vec<Fr> = Vec::new();
            let mut _sum = Fr::zero();
            for _i in 0usize..ASSUMPTION_SIZE {
                let _rand:Fr = _rng.gen();
                _r.push(_rand);
                _sum = _sum + _rand;
            }
            // first compute Br as it will be used later
            let mut _br: Vec<Fr> = Vec::new();
            for _i in 0usize..ASSUMPTION_SIZE {
                _br.push(msk._b[_i] * _r[_i])
            }
            _br.push(_sum);
            // now computer [Br]_2
            let mut _k_0: Vec<G2> = Vec::new();
            for _i in 0usize..(ASSUMPTION_SIZE + 1) {
                _k_0.push(msk._h * _br[_i])
            }
            let mut _sigma_prime: Vec<Fr> = Vec::new();
            for _i in 0usize..(_num_cols - 1) {
                _sigma_prime.push(_rng.gen())
            }
            // compute [W_1 Br]_1, ...
            let mut _k: Vec<(String, Vec<G1>)> = Vec::new();
            let _a = msk._a.clone();
            let _g = msk._g.clone();
            for _i in 0usize.._num_rows {
                let mut _key: Vec<G1> = Vec::new();
                let _sigma_attr:Fr = _rng.gen();
                // calculate _sk_i1 and _sk_i2 terms
                for _t in 0usize..ASSUMPTION_SIZE {
                    let mut _prod = G1::zero();
                    let _a_t = _a[_t].inverse().unwrap();
                    for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                        let mut _hash = String::new();
                        _hash.push_str(&msp._pi[_i]);
                        _hash.push_str(&_l.to_string());
                        _hash.push_str(&_t.to_string());
                        _prod = _prod + (sha3_hash(msk._g, &_hash).expect("could not hash _hash") * (_br[_l] * _a_t));
                    }
                    _prod = _prod + (msk._g * (_sigma_attr * _a_t));
                    if msp._m[_i][0] == 1 {
                        _prod = _prod + (msk._g_k[_t]);
                    } else if msp._m[_i][0] == -1 {
                        _prod = _prod - (msk._g_k[_t]);
                    }
                    let mut _temp = G1::zero();
                    for _j in 1usize.._num_cols {
                        // sum term of _sk_it
                        let mut _hash0 = String::new();
                        _hash0.push_str(&String::from("0"));
                        _hash0.push_str(&_j.to_string());
                        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                            let mut _hash1 = String::new();
                            _hash1.push_str(&_hash0);
                            _hash1.push_str(&_l.to_string());
                            _hash1.push_str(&_t.to_string());
                            _temp = _temp + (sha3_hash(msk._g, &_hash1).expect("could not hash _hash") * (_br[_l] * _a_t));
                        }
                        _temp = _temp + (msk._g * _sigma_prime[_j - 1].neg());
                        if msp._m[_i][_j] == 1 {
                            _prod = _prod + _temp;
                        } else if msp._m[_i][_j] == -1 {
                            _prod = _prod - _temp;
                        }
                    }
                    _key.push(_prod);
                }
                // calculate _sk_i3 term
                let mut _sk_i3 = msk._g * _sigma_attr.neg();
                if msp._m[_i][0] == 1 {
                    _sk_i3 = _sk_i3 + (msk._g_k[ASSUMPTION_SIZE]);
                } else if msp._m[_i][0] == -1 {
                    _sk_i3 = _sk_i3 - (msk._g_k[ASSUMPTION_SIZE]);
                }
                // sum term of _sk_i3
                for _j in 1usize.._num_cols {
                    if msp._m[_i][_j] == 1 {
                        _sk_i3 = _sk_i3 + (msk._g * _sigma_prime[_j - 1].neg());
                    } else if msp._m[_i][_j] == -1 {
                        _sk_i3 = _sk_i3 - (msk._g * _sigma_prime[_j - 1].neg());
                    }
                }
                _key.push(_sk_i3);
                _k.push((msp._pi[_i].to_string(), _key));
            }
            Ok(Ac17KpSecretKey {
                _policy: (policy.to_string(), lang),
                _sk: Ac17SecretKey { _k_0, _k, _k_p: Vec::new()},
            })
        },
        Err(e) => Err(e)
    }
}

/// The encrypt algorithm of AC17KP. Generates an Ac17KpCiphertext using an Ac17PublicKey, a set of attributes given as Vec<String> and some plaintext data given as [u8].
///
/// # Arguments
///
///	* `pk` - A Public Key (MSK), generated by the function setup()
///	* `attributes` - A set of attributes given as Vec<String>
///	* `_plaintext` - plaintext data given as a Vector of u8
///
pub fn kp_encrypt(
    pk: &Ac17PublicKey,
    attributes: &Vec<String>,
    _plaintext: &[u8],
) -> Result<Ac17KpCiphertext, RabeError> {
    // random number generator
    let mut _rng = rand::thread_rng();
    // pick randomness
    let mut _s: Vec<Fr> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand:Fr = _rng.gen();
        _s.push(_rand);
        _sum = _sum + _rand;
    }
    // compute the [As]_2 term
    let mut _c_0: Vec<G2> = Vec::new();
    let _h_a = pk._h_a.clone();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_0.push(_h_a[_i] * _s[_i]);
    }
    _c_0.push(_h_a[ASSUMPTION_SIZE] * _sum);
    // compute ct_y terms
    let mut _c: Vec<(String, Vec<G1>)> = Vec::new();
    for _attr in attributes {
        let mut _ct: Vec<G1> = Vec::new();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _prod = G1::zero();
            for _t in 0usize..ASSUMPTION_SIZE {
                let mut _hash = String::new();
                _hash.push_str(&_attr);
                _hash.push_str(&_l.to_string());
                _hash.push_str(&_t.to_string());
                match sha3_hash(pk._g, &_hash) {
                    Ok(hash) => {
                        _prod = _prod + (hash * _s[_t])
                    },
                    Err(e) => return Err(e)
                };
            }
            _ct.push(_prod);
        }
        _c.push((_attr.to_string(), _ct));
    }
    let mut _c_p = Gt::one();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_p = _c_p * (pk._e_gh_ka[_i].pow(_s[_i]));
    }
    // random msg
    let _msg: Gt = _rng.gen();
    let _ct = encrypt_symmetric(_msg, &_plaintext.to_vec()).unwrap();
    _c_p = _c_p * _msg;
    //Encrypt plaintext using derived key from secret
    Ok(Ac17KpCiphertext {
        _attr: attributes.clone(),
        _ct: Ac17Ciphertext {_c_0, _c, _c_p, _ct},
    })
}

/// The decrypt algorithm of AC17KP. Reconstructs the original plaintext data as Vec<u8>, given a Ac17KpCiphertext with a matching Ac17KpSecretKey.
///
/// # Arguments
///
///	* `sk` - A Secret Key (SK), generated by the function kp_keygen()
///	* `ct` - An AC17KP Ciphertext
///
pub fn kp_decrypt(sk: &Ac17KpSecretKey, ct: &Ac17KpCiphertext) -> Result<Vec<u8>, RabeError> {
    match parse(sk._policy.0.as_ref(), sk._policy.1) {
        Ok(pol) => {
            return if traverse_policy(&ct._attr, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in kp_decrypt: attributes in ct do not match policy in sk."))
            } else {
                match calc_pruned(&ct._attr, &pol, None) {
                    Err(e) => Err(e),
                    Ok(_p) => {
                        let (_match, _list) = _p;
                        if _match {
                            let mut _prod1_gt = Gt::one();
                            let mut _prod2_gt = Gt::one();
                            for _i in 0usize..(ASSUMPTION_SIZE + 1) {
                                let mut _prod_h = G1::zero();
                                let mut _prod_g = G1::zero();
                                for _current in _list.iter() {
                                    for _attr in ct._ct._c.iter() {
                                        if _attr.0 == _current.to_string() {
                                            _prod_g = _prod_g + _attr.1[_i];
                                        }
                                    }
                                    for _attr in sk._sk._k.iter() {
                                        if _attr.0 == _current.to_string() {
                                            _prod_h = _prod_h + _attr.1[_i];
                                        }
                                    }
                                }
                                // for _j in 0usize..ct._ct._c.len() {
                                //     _prod_h = _prod_h + sk._sk._k[_j].1[_i];
                                //     _prod_g = _prod_g + ct._ct._c[_j].1[_i];
                                // }
                                _prod1_gt = _prod1_gt * pairing(_prod_h, ct._ct._c_0[_i]);
                                _prod2_gt = _prod2_gt * pairing(_prod_g, sk._sk._k_0[_i]);
                            }
                            let _msg = ct._ct._c_p * (_prod2_gt * _prod1_gt.inverse());
                            // Decrypt plaintext using derived secret from cp-abe scheme
                            decrypt_symmetric(_msg, &ct._ct._ct)
                        } else {
                            Err(RabeError::new("Error in kp_decrypt: pruned attributes in sk do not match policy in ct."))
                        }
                    }
                }
            }
        },
        Err(e) => Err(e)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn kp_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext =
            kp_encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn kp_or_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name":"or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}, {"name": "and", "children": [{"name": "C"}, {"name": "D"}]}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext =
            kp_encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext =
            kp_encrypt(&pk, &vec!["C".to_string(), "D".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn kp_or() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext = kp_encrypt(&pk, &vec!["B".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn kp_not() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17KpCiphertext = kp_encrypt(&pk, &vec!["C".to_string()], &plaintext).unwrap();
        // a kp-abe SK key
        let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again
        assert_eq!(kp_decrypt(&sk, &ct).is_ok(), false);
    }

    #[test]
    fn cp_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // a kp-abe SK key
        let sk: Ac17CpSecretKey = cp_keygen(&msk, &vec!["A".to_string(), "B".to_string()]).unwrap();
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn cp_or() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}]}"#);
        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // a matching kp-abe SK key
        let sk_m1: Ac17CpSecretKey = cp_keygen(&msk, &vec!["A".to_string()]).unwrap();
        let pt = cp_decrypt(&sk_m1, &ct);
        assert_eq!(pt.is_ok(), true);
        assert_eq!(pt.unwrap(), plaintext);
    }

    #[test]
    fn cp_or_and_and() {
        // setup scheme
        let (pk, msk) = setup();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}, {"name": "and", "children": [{"name": "C"}, {"name": "D"}]}]}"#);
        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // a kp-abe SK key
        let sk: Ac17CpSecretKey = cp_keygen(
            &msk,
            &vec![
                "A".to_string(),
                "B".to_string(),
                "C".to_string(),
                "D".to_string(),
            ],
        ).unwrap();
        // and now decrypt again
        assert_eq!(cp_decrypt(&sk, &ct).unwrap(), plaintext);
    }
}
