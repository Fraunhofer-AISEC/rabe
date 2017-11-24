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

use std::string::String;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use rustc_serialize::hex::ToHex;
use rand::Rng;
use policy::AbePolicy;
use tools::*;

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

/////////////////////////////////////////////
// BSW CP-ABE type-3
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
