// no serde traits until now
//#[macro_use]
//extern crate serde_derive;

extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate rustc_serialize;
extern crate num_bigint;
extern crate blake2_rfc;

use libc::*;
use blake2_rfc::blake2b::{Blake2b, blake2b};
use std::ffi::CString;
use std::ffi::CStr;
use std::mem::transmute;
use std::collections::LinkedList;
use std::string::String;
use std::convert::AsMut;
use std::ops::Add;
use std::ops::Sub;
use std::ops::Mul;
use std::ops::Div;
use std::ops::Neg;
use std::mem;
use serde_json::Value;
use num_bigint::{ToBigInt, Sign, BigInt};
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use bincode::SizeLimit::Infinite;
//use bincode::rustc_serialize::{encode, decode};
use bincode::rustc_serialize::encode;
use rustc_serialize::Encodable;
use rustc_serialize::hex::ToHex;
//use byteorder::{ByteOrder, BigEndian};
use rand::Rng;
use policy::AbePolicy;

#[macro_use]
extern crate arrayref;

mod policy;

//#[doc = /**
// * TODO
// * - Put everything in a module (?)
// * - Encrypt/Decrypt
// * - Serialization, bn::Gt is not serializable :(((
// *
// */]

//////////////////////////////////////////////////////
// BSW CP-ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbePublicKey {
    _g1: bn::G1,
    _g2: bn::G2,
    _h: bn::G2,
    _e_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeMasterKey {
    _beta: bn::Fr,
    _g1_alpha: bn::G1,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeCiphertext {
    _policy: String,
    _c_0: bn::G2,
    _c: Vec<(bn::G2, bn::G1)>,
    _c_m: bn::Gt,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

pub struct CpAbeSecretKey {
    _attr: Vec<(String)>,
    _k_0: bn::G1,
    _k: Vec<(bn::G1, bn::G2)>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeContext {
    _msk: CpAbeMasterKey,
    _pk: CpAbePublicKey,
}

//////////////////////////////////////////////////////
// AC17 KP-ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17PublicKey {
    _g: bn::G1,
    _h_a: Vec<bn::G2>,
    _e_gh_ka: Vec<bn::Gt>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17MasterKey {
    _g: bn::G1,
    _h: bn::G2,
    _g_k: Vec<bn::G1>,
    _a: Vec<bn::Fr>,
    _b: Vec<bn::Fr>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17CpCiphertext {
    _policy: String,
    _c_0: Vec<bn::G2>,
    _c: Vec<(String, Vec<bn::G1>)>,
    _c_p: bn::Gt,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

pub struct Ac17CpSecretKey {
    _attr: Vec<(String)>,
    _k_0: Vec<bn::G2>,
    _k: Vec<(String, Vec<(bn::G1)>)>,
    _k_p: Vec<bn::G1>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Ac17Context {
    _msk: Ac17MasterKey,
    _pk: Ac17PublicKey,
}

//////////////////////////////////////////////////////
// LSE KP-ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbePublicKey {
    _g_g1: bn::G1,
    _g_g2: bn::G2,
    _g_g1_b: bn::G1,
    _g_g1_b2: bn::G1,
    _h_g1_b: bn::G1,
    _e_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbeMasterKey {
    _alpha1: bn::Fr,
    _alpha2: bn::Fr,
    _b: bn::Fr,
    _h_g1: bn::G1,
    _h_g2: bn::G2,
}

pub struct KpAbeSecretKey {
    _policy: String,
    _d_i: Vec<(bn::G1, bn::G2, bn::G1, bn::G1, bn::G1)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbeCiphertext {
    _attr: Vec<(String)>,
    _e1: bn::Gt,
    _e2: bn::G2,
    _e3: Vec<(bn::G1)>,
    _e4: Vec<(bn::G1)>,
    _e5: Vec<(bn::G1)>,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

impl AbePolicy {
    pub fn from_string(policy: &String) -> Option<AbePolicy> {
        policy::string_to_msp(policy)
    }
    pub fn from_json(json: &serde_json::Value) -> Option<AbePolicy> {
        policy::json_to_msp(json)
    }
}

/////////////////////////////////////////////
// BSW CP-ABE algorithms on type-3 pairing
/////////////////////////////////////////////

pub fn cpabe_setup() -> (CpAbePublicKey, CpAbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g1 and generator of group G2: g2
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    // random
    let _beta = Fr::random(_rng);
    let _alpha = Fr::random(_rng);
    // vectors
    // calulate h and f
    let _h = _g2 * _beta;
    let _g1_alpha = _g1 * _alpha;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g1_alpha, _g2);
    // set values of PK
    let _pk = CpAbePublicKey {
        _g1: _g1,
        _g2: _g2,
        _h: _h,
        _e_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = CpAbeMasterKey {
        _beta: _beta,
        _g1_alpha: _g1_alpha,
    };
    // return PK and MSK
    return (_pk, _msk);
}

pub fn cpabe_keygen(
    pk: &CpAbePublicKey,
    msk: &CpAbeMasterKey,
    attributes: &Vec<String>,
) -> Option<CpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if attributes.is_empty() || attributes.len() == 0 {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate random r1 and r2 and sum of both
    // compute Br as well because it will be used later too
    let _r = Fr::random(_rng);
    let _g1_r = pk._g1 * _r;
    let _beta_inverse = msk._beta.inverse().unwrap();
    let _k_0 = (msk._g1_alpha + _g1_r) * _beta_inverse;
    let mut _k: Vec<(bn::G1, bn::G2)> = Vec::new();
    let mut _attr_vec: Vec<(String)> = Vec::new();
    for _attr in attributes {
        let _r_attr = Fr::random(_rng);
        _attr_vec.push(_attr.clone());
        _k.push((
            _g1_r + (blake2b_hash_g1(pk._g1, &_attr) * _r_attr),
            pk._g2 * _r_attr,
        ));
    }
    return Some(CpAbeSecretKey {
        _attr: _attr_vec,
        _k_0: _k_0,
        _k: _k,
    });
}

// ENCRYPT

pub fn cpabe_encrypt(
    pk: &CpAbePublicKey,
    policy: &String,
    plaintext: &Vec<u8>,
) -> Option<CpAbeCiphertext> {
    if plaintext.is_empty() {
        return None;
    }
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    // random number generator
    let _rng = &mut rand::thread_rng();
    // msp matrix M with size n1xn2
    let _rows = msp._m.len();
    let _cols = msp._m[0].len();
    // pick randomness
    let mut _u: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize.._cols {
        _u.push(Fr::random(_rng));
    }
    // the shared root secret
    let _s = _u[0];
    let _c_0 = pk._h * _s;

    let mut _c: Vec<(bn::G2, bn::G1)> = Vec::new();
    for _i in 0usize.._rows {
        let mut _sum = Fr::zero();
        for _j in 0usize.._cols {
            if msp._m[_i][_j] == 0 {
                // do nothing
            } else if msp._m[_i][_j] == 1 {
                _sum = _sum + _u[_j];
            } else {
                _sum = _sum - _u[_j];
            }
        }
        _c.push((
            pk._g2 * _sum,
            blake2b_hash_g1(pk._g1, &msp._pi[_i]) * _sum,
        ));
    }
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    let _c_m = pk._e_gg_alpha.pow(_s) * _msg;
    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&_msg, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            _rng.fill_bytes(&mut iv);
            let ct = CpAbeCiphertext {
                _policy: policy.clone(),
                _c_0: _c_0,
                _c: _c,
                _c_m: _c_m,
                _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

// DECRYPT

pub fn cpabe_decrypt(sk: &CpAbeSecretKey, ct: &CpAbeCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&sk._attr, &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let mut _prod = Gt::one();
        for _i in 0usize..ct._c.len() {
            let (c_attr1, c_attr2) = ct._c[_i];
            let (k_attr1, k_attr2) = sk._k[_i];
            _prod = _prod * (pairing(k_attr1, c_attr1) * pairing(c_attr2, k_attr2).inverse());
        }
        let _msg = (ct._c_m * _prod) * pairing(sk._k_0, ct._c_0).inverse();
        // Decrypt plaintext using derived secret from cp-abe scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}

//////////////////////////////////////////
// AC17 KP-ABE on type-3
//////////////////////////////////////////

const ASSUMPTION_SIZE: usize = 2;

pub fn ac17_setup() -> (Ac17PublicKey, Ac17MasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let _g = G1::random(_rng);
    let _h = G2::random(_rng);
    //pairing
    let _e_gh = pairing(_g, _h);
    // A and B vectors
    let mut _a: Vec<(bn::Fr)> = Vec::new();
    let mut _b: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _a.push(Fr::random(_rng));
        _b.push(Fr::random(_rng));
    }
    // k vetor
    let mut _k: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k.push(Fr::random(_rng));
    }
    // h_A vetor
    let mut _h_a: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _h_a.push(_h * _a[_i]);
    }
    _h_a.push(_h);
    // compute the e([k]_1,  [A]_2) term
    let mut _g_k: Vec<(bn::G1)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _g_k.push(_g * _k[_i]);
    }

    let mut _e_gh_ka: Vec<(bn::Gt)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _e_gh_ka.push(_e_gh.pow(_k[_i] * _a[_i] + _k[ASSUMPTION_SIZE]));
    }

    let _pk = Ac17PublicKey {
        _g: _g,
        _h_a: _h_a,
        _e_gh_ka: _e_gh_ka,
    };
    let _msk = Ac17MasterKey {
        _g: _g,
        _h: _h,
        _g_k: _g_k,
        _a: _a,
        _b: _b,
    };
    // return PK and MSK
    return (_pk, _msk);
}


pub fn ac17cp_keygen(msk: &Ac17MasterKey, attributes: &Vec<String>) -> Option<Ac17CpSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if attributes.is_empty() {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // pick randomness
    let mut _r: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand = Fr::random(_rng);
        _r.push(_rand);
        _sum = _sum + _rand;
    }
    // first compute Br as it will be used later
    let mut _br: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _br.push(msk._b[_i] * _r[_i])
    }
    _br.push(_sum);
    // now computer [Br]_2
    let mut _k_0: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _k_0.push(msk._h * _br[_i])
    }
    // compute [W_1 Br]_1, ...
    let mut _k: Vec<(String, Vec<(bn::G1)>)> = Vec::new();
    let _a = msk._a.clone();
    let _g = msk._g.clone();
    for _attr in attributes {
        let mut _key: Vec<(bn::G1)> = Vec::new();
        let _sigma_attr = Fr::random(_rng);
        for _t in 0usize..ASSUMPTION_SIZE {
            let mut _prod = G1::zero();
            let _a_t = _a[_t].inverse().unwrap();
            for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                let _hash = combine_three_strings(_attr, _l, _t);
                _prod = _prod + (blake2b_hash_g1(msk._g, &_hash) * (_br[_l] * _a_t));
            }
            _prod = _prod + (msk._g * (_sigma_attr * _a_t));
            _key.push(_prod);
        }
        _key.push(msk._g * _sigma_attr.neg());
        _k.push((_attr.to_string(), _key));
    }
    // compute [k + VBr]_1
    let mut _k_p: Vec<(bn::G1)> = Vec::new();
    let _g_k = msk._g_k.clone();
    let _sigma = Fr::random(_rng);
    for _t in 0usize..ASSUMPTION_SIZE {
        let mut _prod = _g_k[_t];
        let _a_t = _a[_t].inverse().unwrap();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let _hash = combine_three_strings(&String::from("01"), _l, _t);
            _prod = _prod + (blake2b_hash_g1(msk._g, &_hash) * (_br[_l] * _a_t));
        }
        _prod = _prod + (msk._g * (_sigma * _a_t));
        _k_p.push(_prod);
    }
    _k_p.push(_g_k[ASSUMPTION_SIZE] + (msk._g * _sigma.neg()));
    return Some(Ac17CpSecretKey {
        _attr: attributes.clone(),
        _k_0: _k_0,
        _k: _k,
        _k_p: _k_p,
    });
}

pub fn ac17cp_encrypt(
    pk: &Ac17PublicKey,
    policy: &String,
    plaintext: &[u8],
) -> Option<Ac17CpCiphertext> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _num_cols = msp._m[0].len();
    let _num_rows = msp._m.len();
    // pick randomness
    let mut _s: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        let _rand = Fr::random(_rng);
        _s.push(_rand);
        _sum = _sum + _rand;
    }
    // compute the [As]_2 term
    let mut _c_0: Vec<(bn::G2)> = Vec::new();
    let _h_a = pk._h_a.clone();
    for _i in 0usize..ASSUMPTION_SIZE {
        _c_0.push(_h_a[_i] * _s[_i]);
    }
    _c_0.push(_h_a[ASSUMPTION_SIZE] * _sum);
    // compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms
    // pre-compute hashes
    let mut _hash_table: Vec<Vec<Vec<(bn::G1)>>> = Vec::new();
    for _j in 0usize.._num_cols {
        let mut _x: Vec<Vec<(bn::G1)>> = Vec::new();
        let _hash1 = combine_two_strings(&String::from("0"), (_j + 1));
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _y: Vec<(bn::G1)> = Vec::new();
            let _hash2 = combine_two_strings(&_hash1, _l);
            for _t in 0usize..ASSUMPTION_SIZE {
                let _hash3 = combine_two_strings(&_hash2, _t);
                let _hashed_value = blake2b_hash_g1(pk._g, &_hash3);
                _y.push(_hashed_value);
            }
            _x.push(_y)
        }
        _hash_table.push(_x);
    }
    let mut _c: Vec<(String, Vec<bn::G1>)> = Vec::new();
    for _i in 0usize.._num_rows {
        let mut _ct: Vec<bn::G1> = Vec::new();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _prod = G1::zero();
            for _t in 0usize..ASSUMPTION_SIZE {
                let _hash = combine_three_strings(&msp._pi[_i], _l, _t);
                let mut _prod1 = blake2b_hash_g1(pk._g, &_hash);
                for _j in 0usize.._num_cols {
                    if msp._m[_i][_j] == 1 {
                        _prod1 = _prod1 + _hash_table[_j][_l][_t];
                    } else if msp._m[_i][_j] == -1 {
                        _prod1 = _prod1 - _hash_table[_j][_l][_t];
                    }
                }
                _prod = _prod + (_prod1 * _s[_t]);
            }
            _ct.push(_prod);
        }
        _c.push((msp._pi[_i].to_string(), _ct));
    }
    let mut _c_p = Gt::one();
    for _i in 0usize..ASSUMPTION_SIZE {
        // TODO CHECK HERE * in GT
        _c_p = _c_p * (pk._e_gh_ka[_i].pow(_s[_i]));
    }
    // random msg
    //let _msg = pairing(G1::ranom(_rng), G2::ranom(_rng));
    let _msg = Gt::one();
    _c_p = _c_p * _msg;

    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&_msg, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            _rng.fill_bytes(&mut iv);
            return Some(Ac17CpCiphertext {
                _policy: policy.clone(),
                _c_0: _c_0,
                _c: _c,
                _c_p: _c_p,
                _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            });
        }
    }
}

pub fn ac17cp_decrypt(sk: &Ac17CpSecretKey, ct: &Ac17CpCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&sk._attr, &ct._policy) == false {
        println!("Error: attributes in ct do not match policy in sk.");
        return None;
    } else {
        let mut _prod1_gt = Gt::one();
        let mut _prod2_gt = Gt::one();
        for _i in 0usize..(ASSUMPTION_SIZE + 1) {
            let mut _prod_h = G1::zero();
            let mut _prod_g = G1::zero();
            for _j in 0usize..ct._c.len() {
                _prod_h = _prod_h + sk._k[_j].1[_i];
                _prod_g = _prod_g + ct._c[_j].1[_i];
            }
            _prod1_gt = _prod1_gt * pairing(sk._k_p[_i] + _prod_h, ct._c_0[_i]);
            _prod2_gt = _prod2_gt * pairing(_prod_g, sk._k_0[_i]);
        }
        let _msg = ct._c_p * (_prod2_gt * _prod1_gt.inverse());
        println!("_pt: {:?}", into_dec(_msg).unwrap());
        // Decrypt plaintext using derived secret from cp-abe scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}


//////////////////////////////////////////
// LSW KP-ABE on type-3
//////////////////////////////////////////

// SETUP

pub fn kpabe_setup() -> (KpAbePublicKey, KpAbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate random alpha1, alpha2 and b
    let _alpha1 = Fr::random(_rng);
    let _alpha2 = Fr::random(_rng);
    let _alpha = _alpha1 * _alpha2;
    let _b = Fr::random(_rng);
    let _g_g1 = G1::random(_rng);
    let _g_g2 = G2::random(_rng);
    let _h_g1 = G1::random(_rng);
    let _h_g2 = G2::random(_rng);
    let _g1_b = _g_g1 * _b;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g_g1, _g_g2).pow(_alpha);
    // set values of PK
    let _pk = KpAbePublicKey {
        _g_g1: _g_g1,
        _g_g2: _g_g2,
        _g_g1_b: _g1_b,
        _g_g1_b2: _g1_b * _b,
        _h_g1_b: _h_g1 * _b,
        _e_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = KpAbeMasterKey {
        _alpha1: _alpha1,
        _alpha2: _alpha2,
        _b: _b,
        _h_g1: _h_g1,
        _h_g2: _h_g2,
    };
    // return PK and MSK
    return (_pk, _msk);
}

// KEYGEN

pub fn kpabe_keygen(
    pk: &KpAbePublicKey,
    msk: &KpAbeMasterKey,
    policy: &String,
) -> Option<KpAbeSecretKey> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _secret = msk._alpha1;
    let _shares = gen_shares_str(_secret, policy).unwrap();
    let mut _d: Vec<(bn::G1, bn::G2, bn::G1, bn::G1, bn::G1)> = Vec::new();
    let mut _d_i: (bn::G1, bn::G2, bn::G1, bn::G1, bn::G1) =
        (G1::zero(), G2::zero(), G1::zero(), G1::zero(), G1::zero());
    for _x in 0usize..msp._pi.len() {
        let _r = Fr::random(_rng);
        let mut _sum = Fr::zero();
        if is_negative(&msp._pi[_x]) {
            _d_i.2 = (pk._g_g1 * (msk._alpha2 * _shares[_x].1)) + (pk._g_g1_b2 * _r);
            _d_i.3 = pk._g_g1_b * (blake2b_hash_fr(&_shares[_x].0) * _r) + (msk._h_g1 * _r);
            _d_i.4 = pk._g_g1 * _r.neg();
        } else {
            _d_i.0 = (pk._g_g1 * (msk._alpha2 * _shares[_x].1)) +
                (blake2b_hash_g1(pk._g_g1, &_shares[_x].0) * _r);
            _d_i.1 = pk._g_g2 * _r;
        }
        _d.push(_d_i);
    }
    return Some(KpAbeSecretKey {
        _policy: policy.clone(),
        _d_i: _d,
    });
}

pub fn kpabe_encrypt(
    pk: &KpAbePublicKey,
    attributes: &Vec<String>,
    plaintext: &[u8],
) -> Option<KpAbeCiphertext> {
    if attributes.is_empty() || plaintext.is_empty() {
        return None;
    } else {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // e3,4,5 vectors
        let mut _e3: Vec<(bn::G1)> = Vec::new();
        let mut _e4: Vec<(bn::G1)> = Vec::new();
        let mut _e5: Vec<(bn::G1)> = Vec::new();
        // random message
        let _msg = Gt::one();
        println!("_pt: {:?}", into_dec(_msg).unwrap());
        // random secret
        let _s = Fr::random(_rng);
        // sx vector
        let mut _sx: Vec<(bn::Fr)> = Vec::new();
        _sx.push(_s);
        for _i in 0usize..attributes.len() {
            _sx.push(Fr::random(_rng));
            _sx[0] = _sx[0] - _sx[_i];
        }
        for _i in 0usize..attributes.len() {
            _e3.push(blake2b_hash_g1(pk._g_g1, &attributes[_i]) * _s);
            _e4.push(pk._g_g1_b * _sx[_i]);
            _e5.push(
                (pk._g_g1_b2 * (_sx[_i] * blake2b_hash_fr(&attributes[_i]))) +
                    (pk._h_g1_b * _sx[_i]),
            );
        }
        let _e1 = (pk._e_gg_alpha.pow(_s)) * _msg;
        let _e2 = pk._g_g2 * _s;
        //Encrypt plaintext using derived key from secret
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let mut iv: [u8; 16] = [0; 16];
                _rng.fill_bytes(&mut iv);
                let _ct = KpAbeCiphertext {
                    _attr: attributes.clone(),
                    _e1: _e1,
                    _e2: _e2,
                    _e3: _e3,
                    _e4: _e4,
                    _e5: _e5,
                    _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                    _iv: iv,
                };
                return Some(_ct);
            }
        }
    }
}

pub fn kpabe_decrypt(sk: &KpAbeSecretKey, ct: &KpAbeCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&ct._attr, &sk._policy) == false {
        println!("Error: attributes in ct do not match policy in sk.");
        return None;
    } else {
        let mut _prod_t = Gt::one();
        let mut _coeff: Vec<(String, bn::Fr)> = calc_coefficients_str(&sk._policy).unwrap();
        for _i in 0usize.._coeff.len() {
            let mut _z = Gt::one();
            if is_negative(&_coeff[_i].0) {
                let _sum_e4 = G2::zero();
                let _sum_e5 = G2::zero();

            //_z = pairing(sk._d_i[_i].2, ct._e2) *
            //    (pairing(sk._d_i[_i].3, _sum_e4) * pairing(sk._d_i[_i].4, _sum_e5)).inverse();
            } else {
                _z = pairing(sk._d_i[_i].0, ct._e2) * pairing(ct._e3[_i], sk._d_i[_i].1).inverse();
            }
            println!(
                "DEC_coeff[{:?}]: {:?}",
                _coeff[_i].0,
                into_dec(_coeff[_i].1).unwrap()
            );
            _prod_t = _prod_t * _z.pow(_coeff[_i].1);
        }
        let _msg = ct._e1 * _prod_t.inverse();
        println!("_pt: {:?}", into_dec(_msg).unwrap());
        // Decrypt plaintext using derived secret from cp-abe scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}


#[no_mangle]
pub extern "C" fn abe_context_create() -> *mut CpAbeContext {
    let (pk, msk) = cpabe_setup();
    let _ctx = unsafe { transmute(Box::new(CpAbeContext { _msk: msk, _pk: pk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn abe_context_destroy(ctx: *mut CpAbeContext) {
    let _ctx: Box<CpAbeContext> = unsafe { transmute(ctx) };
    // Drop reference for GC
}

/*
#[no_mangle]
pub extern "C" fn kpabe_secret_key_create(
    ctx: *mut CpAbeContext,
    policy: *mut c_char,
) -> *mut KpCpAbeSecretKey {
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _msp = AbePolicy::from_string(&pol).unwrap();
    let _ctx = unsafe { &mut *ctx };
    let sk = kpabe_keygen(&_ctx._msk, &_msp).unwrap();
    let _sk = unsafe {
        transmute(Box::new(KpCpAbeSecretKey {
            _sk_0: sk._sk_0.clone(),
            _sk_y: sk._sk_y.clone(),
        }))
    };
    _sk
}
*/
#[no_mangle]
pub extern "C" fn abe_secret_key_destroy(sk: *mut CpAbeSecretKey) {
    let _sk: Box<CpAbeSecretKey> = unsafe { transmute(sk) };
    // Drop reference for GC
}

#[no_mangle]
pub extern "C" fn kpabe_decrypt_native(sk: *mut CpAbeSecretKey, ct: *mut c_char) -> i32 {
    //TODO: Deserialize ct
    //TODO: Call abe_decrypt
    //TODO: serialize returned pt and store under pt
    return 1;
}


pub fn is_negative(_attr: &String) -> bool {
    let first_char = &_attr[..1];
    return first_char == '!'.to_string();
}

pub fn calc_coefficients_str(_policy: &String) -> Option<Vec<(String, bn::Fr)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            let mut _coeff: Vec<(String, bn::Fr)> = Vec::new();
            calc_coefficients(&pol, &mut _coeff, Fr::one());
            return Some(_coeff);
        }
    }
}

pub fn calc_coefficients(
    _json: &serde_json::Value,
    _coeff_vec: &mut Vec<(String, bn::Fr)>,
    _coeff: bn::Fr,
) {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
    } else {
        // leaf node
        if _json["ATT"] != serde_json::Value::Null {
            _coeff_vec.push((_json["ATT"].to_string(), _coeff));
        }
        // inner node
        else if _json["AND"].is_array() {
            let _this_coeff = recover_coefficients(vec![Fr::one(), (Fr::one() + Fr::one())]);
            calc_coefficients(&_json["AND"][0], _coeff_vec, _coeff * _this_coeff[0]);
            calc_coefficients(&_json["AND"][1], _coeff_vec, _coeff * _this_coeff[1]);
        }
        // inner node
        else if _json["OR"].is_array() {
            let _this_coeff = recover_coefficients(vec![Fr::one()]);
            calc_coefficients(&_json["OR"][0], _coeff_vec, _coeff * _this_coeff[0]);
            calc_coefficients(&_json["OR"][0], _coeff_vec, _coeff * _this_coeff[0]);
        }
    }
}

// lagrange interpolation
pub fn recover_coefficients(_list: Vec<bn::Fr>) -> Vec<bn::Fr> {
    let mut _coeff: Vec<bn::Fr> = Vec::new();
    for _i in _list.clone() {
        let mut _result = Fr::one();
        for _j in _list.clone() {
            if _i != _j {
                _result = _result * ((Fr::zero() - _j) * (_i - _j).inverse().unwrap());
                println!(
                    "lagrange_coeff : {:?} {:?}",
                    into_dec(_i).unwrap(),
                    into_dec(_result).unwrap()
                );
            }
        }
        _coeff.push(_result);
    }
    return _coeff;
}

pub fn usize_to_fr(_i: usize) -> bn::Fr {
    let _i = _i.to_bigint().unwrap();
    return Fr::from_str(&_i.to_str_radix(10)).unwrap();
}

pub fn gen_shares_str(_secret: bn::Fr, _policy: &String) -> Option<Vec<(String, bn::Fr)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            return gen_shares_json(_secret, &pol);
        }
    }
}

pub fn gen_shares_json(
    _secret: bn::Fr,
    _json: &serde_json::Value,
) -> Option<Vec<(String, bn::Fr)>> {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return None;
    } else {
        let mut _k = 0;
        let mut _type = "";
        let mut _result: Vec<(String, bn::Fr)> = Vec::new();
        // leaf node
        if _json["ATT"] != serde_json::Value::Null {
            match _json["ATT"].as_str() {
                Some(_s) => {
                    _result.push((_s.to_string(), _secret));
                    return Some(_result);
                }
                None => {
                    println!("ERROR attribute value");
                    return None;
                }
            }
        }
        // inner node
        else if _json["OR"].is_array() {
            _k = 1;
            _type = "OR";
        }
        // inner node
        else if _json["AND"].is_array() {
            _k = 2;
            _type = "AND";
        }
        let shares = gen_shares(_secret, _k, 2);
        let left = gen_shares_json(shares[0], &_json[_type][0]).unwrap();
        _result.extend(left);
        let right = gen_shares_json(shares[1], &_json[_type][1]).unwrap();
        _result.extend(right);
        return Some(_result);
    }
}

pub fn gen_shares(_secret: bn::Fr, _k: usize, _n: usize) -> Vec<bn::Fr> {
    let mut _shares: Vec<bn::Fr> = Vec::new();
    if _k <= _n {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // polynomial coefficients
        let mut _a: Vec<bn::Fr> = Vec::new();
        for _i in 0.._k {
            if _i == 0 {
                _a.push(_secret);
            } else {
                _a.push(Fr::random(_rng))
            }
            println!("KEY_coeff[{:?}]: {:?}", _i, into_dec(_a[_i]).unwrap());
        }
        for _i in 0..(_n + 1) {
            let _polynom = polynomial(_a.clone(), usize_to_fr(_i));
            _shares.push(_polynom);
            println!("KEY_polynom[{:?}]: {:?}", _i, into_dec(_polynom).unwrap());
        }
    }
    return _shares;
}

pub fn recover_secret(_shares: Vec<bn::Fr>, _policy: &String) -> bn::Fr {
    let _coeff = calc_coefficients_str(_policy).unwrap();
    let mut _secret = Fr::zero();
    for _i in 0usize.._shares.len() {
        _secret = _secret + (_coeff[_i].1 * _shares[_i]);
    }
    return _secret;
}

pub fn polynomial(_coeff: Vec<bn::Fr>, _x: bn::Fr) -> bn::Fr {
    let mut _share = Fr::zero();
    for _i in 0usize.._coeff.len() {
        _share = _share + (_coeff[_i] * _x.pow(usize_to_fr(_i)));
    }
    return _share;
}


pub fn traverse_str(_attr: &Vec<(String)>, _policy: &String) -> bool {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return false;
        }
        Ok(pol) => {
            return traverse_json(_attr, &pol);
        }
    }
}
// used to traverse / check policy tree
pub fn traverse_json(_attr: &Vec<(String)>, _json: &serde_json::Value) -> bool {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return false;
    }
    if _attr.len() == 0 {
        println!("Error: No attributes in List!");
        return false;
    }
    // inner node or
    if _json["OR"].is_array() {
        let _num_terms = _json["OR"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = false;
            for _i in 0usize.._num_terms {
                ret = ret || traverse_json(_attr, &_json["OR"][_i]);
            }
            return ret;
        } else {
            println!("Invalid policy.");
            return false;
        }
    }
    // inner node and
    else if _json["AND"].is_array() {
        let _num_terms = _json["AND"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = true;
            for _i in 0usize.._num_terms {
                ret = ret && traverse_json(_attr, &_json["AND"][_i]);
            }
            return ret;
        } else {
            println!("Invalid policy.");
            return false;
        }
    }
    // leaf node
    else if _json["ATT"] != serde_json::Value::Null {
        match _json["ATT"].as_str() {
            Some(s) => {
                // check if ATT in _attr list
                return (&_attr).into_iter().any(|v| v == &s);
            }
            None => {
                println!("ERROR attribute not in list");
                return false;
            }
        }
    }
    // error
    else {
        println!("Policy invalid. No AND or OR found");
        return false;
    }
}
// used to hash to G1
pub fn blake2b_hash_g1(g: bn::G1, data: &String) -> bn::G1 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to G1
pub fn blake2b_hash_g2(g: bn::G2, data: &String) -> bn::G2 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}


// used to hash to Fr
pub fn blake2b_hash_fr(data: &String) -> bn::Fr {
    let hash = blake2b(64, &[], data.as_bytes());
    return Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// Helper functions from here on used by CP and KP
pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| e.to_hex())
}

pub fn into_dec<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| {
        BigInt::parse_bytes(e.to_hex().as_bytes(), 16)
            .unwrap()
            .to_str_radix(10)
    })
}

pub fn combine_two_strings(text: &String, j: usize) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    return _combined.to_string();
}

pub fn combine_three_strings(text: &String, j: usize, t: usize) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    _combined.push_str(&t.to_string());
    return _combined.to_string();
}


// AES functions from here on

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
fn decrypt_aes(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    return Ok(final_result);
}

fn encrypt_aes(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

#[cfg(test)]
mod tests {
    use cpabe_setup;
    use cpabe_keygen;
    use cpabe_encrypt;
    use cpabe_decrypt;
    use ac17_setup;
    use ac17cp_keygen;
    use ac17cp_encrypt;
    use ac17cp_decrypt;
    use kpabe_setup;
    use kpabe_keygen;
    use kpabe_encrypt;
    use kpabe_decrypt;
    use traverse_str;
    use traverse_json;
    use gen_shares;
    use recover_secret;
    use blake2b_hash_g1;
    use blake2b_hash_fr;
    use AbePolicy;
    use CpAbeCiphertext;
    use CpAbeSecretKey;
    use KpAbeCiphertext;
    use KpAbeSecretKey;
    use Ac17CpCiphertext;
    use Ac17CpSecretKey;
    //use KpCpAbeSecretKey;
    //use Fr;
    use std::collections::LinkedList;
    use std::string::String;
    use std::ops::Add;
    use std::ops::Sub;
    use bn::*;
    use num_bigint::BigInt;
    use bincode::SizeLimit::Infinite;
    use bincode::rustc_serialize::{encode, decode};
    use rustc_serialize::{Encodable, Decodable};
    use rustc_serialize::hex::{FromHex, ToHex};
    use rand;

    pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
        encode(&obj, Infinite).ok().map(|e| e.to_hex())
    }

    pub fn into_dec<S: Encodable>(obj: S) -> Option<String> {
        encode(&obj, Infinite).ok().map(|e| {
            BigInt::parse_bytes(e.to_hex().as_bytes(), 16)
                .unwrap()
                .to_str_radix(10)
        })
    }

    pub fn from_hex<S: Decodable>(s: &str) -> Option<S> {
        let s = s.from_hex().unwrap();
        decode(&s).ok()
    }

    #[test]
    fn test_traverse() {
        let policyfalse = String::from(r#"joking-around?"#);
        let policy1 = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy2 = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy3 = String::from(
            r#"{"AND": [{"OR": [{"ATT": "C"}, {"ATT": "D"}]}, {"ATT": "B"}]}"#,
        );

        let mut _set0: Vec<String> = Vec::new();
        _set0.push(String::from("X"));
        _set0.push(String::from("Y"));

        let mut _set1: Vec<String> = Vec::new();
        _set1.push(String::from("A"));
        _set1.push(String::from("B"));

        let mut _set2: Vec<String> = Vec::new();
        _set2.push(String::from("C"));
        _set2.push(String::from("D"));

        let mut _set3: Vec<String> = Vec::new();
        _set3.push(String::from("A"));
        _set3.push(String::from("B"));
        _set3.push(String::from("C"));
        _set3.push(String::from("D"));

        assert_eq!(traverse_str(&_set1, &policyfalse), false);

        assert_eq!(traverse_str(&_set0, &policy1), false);
        assert_eq!(traverse_str(&_set1, &policy1), true);
        assert_eq!(traverse_str(&_set2, &policy1), false);
        assert_eq!(traverse_str(&_set3, &policy1), true);

        assert_eq!(traverse_str(&_set1, &policy2), true);
        assert_eq!(traverse_str(&_set2, &policy2), false);
        assert_eq!(traverse_str(&_set3, &policy2), true);

        assert_eq!(traverse_str(&_set1, &policy3), false);
        assert_eq!(traverse_str(&_set2, &policy3), false);
        assert_eq!(traverse_str(&_set3, &policy3), true);
    }

    #[test]
    fn test_ac17_and() {
        // setup scheme
        let (pk, msk) = ac17_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "C"}, {"ATT": "B"}]}"#);

        // kp-abe ciphertext
        let ct: Ac17CpCiphertext = ac17cp_encrypt(&pk, &policy, &plaintext).unwrap();

        // kp-abe ciphertext
        //let ct_kp_not_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_not_matching, &plaintext)
        //    .unwrap();

        // a kp-abe SK key
        let sk: Ac17CpSecretKey = ac17cp_keygen(&msk, &att_matching).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = ac17cp_decrypt(&sk, &ct);
        match _matching {
            None => println!("AC17-CP-ABE: Cannot decrypt"),
            Some(x) => println!("AC17-CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        //let _not_matching = kpabe_decrypt(&sk, &ct_kp_not_matching);
        //match _not_matching {
        //    None => println!("KP-ABE: Cannot decrypt"),
        //    Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        //}
    }


    /*
    #[test]
    fn test_cp_abe_and() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();

        // a cp-abe SK key matching
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_not_matching).unwrap();


        // and now decrypt again with mathcing sk
        let _matching = cpabe_decrypt(&sk_matching, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }
  
    #[test]
    fn test_kp_abe_and() {
        // setup scheme
        let (pk, msk) = kpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_matching, &plaintext)
            .unwrap();

        // kp-abe ciphertext
        //let ct_kp_not_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_not_matching, &plaintext)
        //    .unwrap();

        // a kp-abe SK key
        let sk: KpAbeSecretKey = kpabe_keygen(&pk, &msk, &policy).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = kpabe_decrypt(&sk, &ct_kp_matching);
        match _matching {
            None => println!("KP-ABE: Cannot decrypt"),
            Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        //let _not_matching = kpabe_decrypt(&sk, &ct_kp_not_matching);
        //match _not_matching {
        //    None => println!("KP-ABE: Cannot decrypt"),
        //    Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        //}
    }

    #[test]
    fn test_secret_sharing_and() {
        // AND
        let _rng = &mut rand::thread_rng();
        let _secret = Fr::random(_rng);
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 2, 2);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(K).unwrap());
        let mut _input: Vec<Fr> = Vec::new();
        _input.push(_shares[1]);
        _input.push(_shares[2]);
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        );
        assert!(_k == _reconstruct);
    }

    #[test]
    fn test_secret_sharing_or() {
        // OR
        let _rng = &mut rand::thread_rng();
        let _secret = Fr::random(_rng);
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 1, 2);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(K).unwrap());
        let mut _input: Vec<Fr> = Vec::new();
        _input.push(_shares[1]);
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        );
        assert!(_k == _reconstruct);
    }

    #[test]
    fn test_to_msp() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let _zero = 0;
        let _plus = 1;
        let _minus = -1;
        let p1 = vec![_zero, _zero, _minus];
        let p2 = vec![_plus, _zero, _plus];
        let p3 = vec![_zero, _minus, _zero];
        let p4 = vec![_plus, _plus, _zero];
        let mut _msp_static = AbePolicy {
            _m: vec![p1, p2, p3, p4],
            _pi: vec![
                String::from("A"),
                String::from("B"),
                String::from("C"),
                String::from("D"),
            ],
            _deg: 3,
        };
        match AbePolicy::from_string(&policy) {
            None => assert!(false),
            Some(_msp) => {
                for i in 0..4 {
                    let p = &_msp._m[i];
                    let p_test = &_msp_static._m[i];
                    for j in 0..3 {
                        //println!("_mspg[{:?}][{:?}]: {:?}", i, j, p[j]);
                        //println!("_msps[{:?}][{:?}]: {:?}", i, j, p_test[j]);
                        assert!(p[j] == p_test[j]);
                    }
                    //println!("_pi[{:?}]{:?} _pi[{:?}]{:?}",i,_msp_static._pi[i],i,_msp._pi[i]);
                    assert!(_msp_static._pi[i] == _msp._pi[i]);
                }
                assert!(_msp_static._deg == _msp._deg);
            }
        }
    }
    */
}
