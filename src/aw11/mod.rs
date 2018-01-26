extern crate bn;
extern crate rand;
extern crate serde;
extern crate serde_json;

use std::string::String;
use std::ops::Neg;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use rustc_serialize::hex::ToHex;
use rand::Rng;
use policy::AbePolicy;
use secretsharing::{gen_shares_str, calc_coefficients_str, calc_pruned_str};
use tools::*;
use std::ascii::AsciiExt;

//////////////////////////////////////////////////////
// AW11 ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11GlobalKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11PublicKey {
    pub _attr: Vec<(String, bn::Gt, bn::G1, bn::G2)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11MasterKey {
    pub _attr: Vec<(String, bn::Fr, bn::Fr, bn::Fr)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11Ciphertext {
    pub _policy: String,
    pub _c_0: bn::Gt,
    pub _c: Vec<(String, bn::Gt, bn::G1, bn::G1, bn::G2, bn::G2)>,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11SecretKey {
    pub _gid: String,
    pub _attr: Vec<(String, bn::G1, bn::G2)>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11GlobalContext {
    pub _gk: Aw11GlobalKey,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Aw11Context {
    pub _msk: Aw11MasterKey,
    pub _pk: Aw11PublicKey,
}

//////////////////////////////////////////
// AW11 D-ABE on type-3
//////////////////////////////////////////

const ASSUMPTION_SIZE: usize = 2;

// BOTH SCHEMES SHARE

// global setup
pub fn aw11_global() -> Aw11GlobalKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g1 and generator of group G2: g2
    let _gk = Aw11GlobalKey {
        _g1: G1::random(_rng),
        _g2: G2::random(_rng),
    };
    // return PK and MSK
    return _gk;
}
// authority setup for a given set of attributes
pub fn aw11_setup(
    gk: &Aw11GlobalKey,
    attributes: &Vec<String>,
) -> Option<(Aw11PublicKey, Aw11MasterKey)> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if attributes.is_empty() {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let mut _msk: Vec<(String, bn::Fr, bn::Fr, bn::Fr)> = Vec::new();
    let mut _pk: Vec<(String, bn::Gt, bn::G1, bn::G2)> = Vec::new();
    // now calculate attribute values
    for _attr in attributes {
        // calculate randomness
        let _alpha_i = Fr::random(_rng);
        let _y1_i = Fr::random(_rng);
        let _y2_i = Fr::random(_rng);
        let mut _key: (String, bn::Fr, bn::Fr, bn::Fr) =
            (_attr.clone().to_uppercase(), _alpha_i, _y1_i, _y2_i);
        let mut _value: (String, bn::Gt, bn::G1, bn::G2) = (
            _attr.clone().to_uppercase(),
            pairing(gk._g1, gk._g2).pow(_alpha_i),
            gk._g1 * _y1_i,
            gk._g2 * _y2_i,
        );
        _msk.push(_key);
        _pk.push(_value);
    }
    // return PK and MSK
    return Some((
        Aw11PublicKey { _attr: _pk },
        Aw11MasterKey { _attr: _msk },
    ));
}

/*
 * user key setup
 * Create a key for GID on attributes belonging to authority msk
 * msk is the private key for the releveant authority
 * the attributes are appended to the secret key sk
 */
pub fn aw11_keygen(
    gk: &Aw11GlobalKey,
    msk: &Aw11MasterKey,
    attribute: &String,
    sk: &Aw11SecretKey,
) -> Option<Aw11SecretKey> {
    // if no attibutes or no gid
    if attribute.is_empty() || sk._gid.is_empty() {
        return None;
    }
    let mut _values: Vec<(String, bn::G1, bn::G2)> = sk._attr.clone();
    let _h_g1 = blake2b_hash_g1(gk._g1, &sk._gid);
    let _h_g2 = blake2b_hash_g2(gk._g2, &sk._gid);

    let _sk_attr = aw11_attr_from_msk(msk, attribute);
    match _sk_attr {
        None => return None,
        Some(_current) => {
            let _attribute = msk._attr[_current.1].clone();
            _values.push((
                _attribute.0.clone().to_uppercase(),
                (gk._g1 * _attribute.1) + (_h_g1 * _attribute.2),
                (gk._g2 * _attribute.1) + (_h_g2 * _attribute.3),
            ));
        }
    }

    return Some(Aw11SecretKey {
        _attr: _values,
        _gid: sk._gid.clone(),
    });
}

/* encrypt
 * M is a group element
 * pk is a dictionary with all the attributes of all authorities put together.
 * This is legal because no attribute can be shared by more than one authority
 * {i: {'e(gg)^alpha_i: , 'g^y_i'}
 */
pub fn aw11_encrypt(
    gk: &Aw11GlobalKey,
    pk: &Aw11PublicKey,
    policy: &String,
    plaintext: &[u8],
) -> Option<Aw11Ciphertext> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _num_cols = msp._m[0].len();
    let _num_rows = msp._m.len();
    // pick randomness
    let _s = Fr::random(_rng);
    let _zero = Fr::zero();
    let _e_gg_s = pairing(gk._g1, gk._g2).pow(_s);
    // random msg
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    let _c_0 = _msg * _e_gg_s;
    let _s_shares = gen_shares_str(_s, policy).unwrap();
    let _w_shares = gen_shares_str(_zero, policy).unwrap();

    let mut _c: Vec<(String, bn::Gt, bn::G1, bn::G1, bn::G2, bn::G2)> = Vec::new();
    for (_i, _tuple) in _s_shares.iter().enumerate() {
        let _r = Fr::random(_rng);
        let _current_attr = aw11_attr_from_pk(pk, &_tuple.0);
        match _current_attr {
            None => return None,
            Some(_current) => {
                let _attribute = pk._attr[_current.1].clone();
                _c.push((
                    _tuple.0.clone(),
                    pairing(gk._g1, gk._g2).pow(_tuple.1) * _attribute.1.pow(_r),
                    gk._g1 * _r,
                    (_attribute.2 * _r) + (gk._g1 * _w_shares[_i].1),
                    gk._g2 * _r,
                    (_attribute.3 * _r) + (gk._g2 * _w_shares[_i].1),
                ));
            }
        }
    }
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
            return Some(Aw11Ciphertext {
                _policy: policy.clone(),
                _c_0: _c_0,
                _c: _c,
                _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            });
        }
    }
}

/*
 * decrypt
 * Decrypt a ciphertext
 * SK is the user's private key dictionary sk.attr: { xxx , xxx }
 */

pub fn aw11_decrypt(
    gk: &Aw11GlobalKey,
    sk: &Aw11SecretKey,
    ct: &Aw11Ciphertext,
) -> Option<Vec<u8>> {
    if traverse_str(&flatten(&sk._attr), &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let _coeffs = calc_coefficients_str(&ct._policy).unwrap();
        let _pruned = calc_pruned_str(&ct._policy, &sk._attr);
        match _pruned {
            None => return None,
            Some(_p) => {
                let _h_g1 = blake2b_hash_g1(gk._g1, &sk._gid);
                let _h_g2 = blake2b_hash_g2(gk._g2, &sk._gid);
                let mut _egg_s = Gt::one();
                for (_i, _coeff) in _coeffs.iter().enumerate() {
                    /*
            let _current_sk_attr = aw11_get_sk_attribute(sk, &_coeff.0);
            let _current_ct_attr = aw11_get_ct_attribute(ct, &_coeff.0);
            */
                    //let num = ct. ['C1'][x] * pair(h_gid, ct['C3'][x]);
                    //let dem = pair(sk[y]['k'], ct['C2'][x]);
                    //egg_s = _egg_s * ( (num * dem.inverse()) ** coeffs[x] );

                }
                let _msg = ct._c_0 * _egg_s.inverse();
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


    }
}
