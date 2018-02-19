extern crate bn;
extern crate rand;
extern crate serde;
extern crate serde_json;

use std::string::String;
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

//////////////////////////////////////////////////////
// MSK08 ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08PublicKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _p1: bn::G1,
    pub _p2: bn::G2,
    pub _e_gg_y: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08MasterKey {
    pub _g1_y: bn::G1,
    pub _g2_y: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08PublicUserKey {
    pub _u: String,
    pub _pk_g1: bn::G1,
    pub _pk_g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08SecretUserKey {
    pub _sk_g1: bn::G1,
    pub _sk_g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08SecretAuthorityKey {
    pub _a: String,
    pub _h: bn::Fr,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08PublicAttributeKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _gt: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08SecretAttributeKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08Ciphertext {
    pub _policy: String,
    pub _c: Vec<(String, bn::Gt, bn::G1, bn::G1, bn::G2, bn::G2)>,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08GlobalContext {
    pub _gk: Msk08PublicKey,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Msk08Context {
    pub _msk: Msk08MasterKey,
    pub _pk: Msk08PublicKey,
}

//////////////////////////////////////////
// MSK08 DABE on type-3
//////////////////////////////////////////

const ASSUMPTION_SIZE: usize = 2;

// global setup
pub fn msk08_setup() -> (Msk08PublicKey, Msk08MasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    let _y = Fr::random(_rng);
    let _z = Fr::random(_rng);
    // generator of group G1: g1 and generator of group G2: g2
    let _pk = Msk08PublicKey {
        _g1: _g1,
        _g2: _g2,
        _p1: _g1 * _z,
        _p2: _g2 * _z,
        _e_gg_y: pairing(_g1, _g2).pow(_y),
    };
    // generator of group G1: g1 and generator of group G2: g2
    let _mk = Msk08MasterKey {
        _g1: _g1 * _y,
        _g2: _g2 * _y,
    };
    // return PK and MSK
    return (_pk, _mk);
}

// user setup
pub fn msk08_create_user(
    pk: &Msk08PublicKey,
    mk: &Msk08MasterKey,
    u: &String,
) -> (Msk08PublicUserKey, Msk08SecretUserKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _mk_u = Fr::random(_rng);
    // return PK and MSK
    return (
        Msk08PublicUserKey {
            _u: u.clone(),
            _pk_g1: pk._g1 * _mk_u,
            _pk_g2: pk._g2 * _mk_u,
        },
        Msk08SecretUserKey {
            _pk_g1: mk._g1_y + (pk._p1 * _mk_u),
            _pk_g2: mk._g2_y + (pk._p2 * _mk_u),
        },
    );
}

// authority setup
pub fn msk08_create_authority(pk: &Msk08PublicKey, a: &String) -> Msk08SecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // return PK and MSK
    return Msk08SecretAuthorityKey {
        _a: a.clone(),
        _h: Fr::random(_rng),
    };
}

// request an attribute PK from an authority
pub fn msk08_request_authority_pk(
    pk: &Msk08PublicKey,
    a: &String,
    sk_a: &Msk08SecretAuthorityKey,
) -> Option<Msk08PublicAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(a, sk_a._a) {
        let exponent = blake2b_hash_fr(a) * sk_a._h;
        // return PK and MSK
        return Msk08PublicAttributeKey {
            _g1: pk._g1 * exponent,
            _g2: pk._g2 * exponent,
            _gt: pk._e_gg_y.pow(exponent),
        };
    } else {
        return None;
    }
}

// request an attribute PK from an authority
pub fn msk08_request_authority_sk(
    pk: &Msk08PublicKey,
    a: &String,
    sk_a: &Msk08SecretAuthorityKey,
    pk_u: &Msk08PublicUserKey,
) -> Option<Msk08SecretAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(a, sk_a._a) && is_eligible(a, pk_u._u) {
        let exponent = blake2b_hash_fr(a) * sk_a._h;
        // return PK and MSK
        return Msk08SecretAttributeKey {
            _g1: pk_u._pk_g1 * exponent,
            _g2: pk_u._pk_g2 * exponent,
        };
    } else {
        return None;
    }
}
/* encrypt
 * M is a group element
 * pk is a dictionary with all the attributes of all authorities put together.
 * This is legal because no attribute can be shared by more than one authority
 * {i: {'e(gg)^alpha_i: , 'g^y_i'}
 */
pub fn msk08_encrypt(
    pk: &Msk08PublicKey,
    attr_pks: &Vec<Msk08PublicAttributeKey>,
    policy: &String,
    plaintext: &[u8],
) -> Option<Msk08Ciphertext> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _num_cols = msp._m[0].len();
    let _num_rows = msp._m.len();
    // random Gt msg
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    // CT result vector
    let mut _c: Vec<(String, bn::Gt, bn::G1, bn::G1, bn::G2, bn::G2)> = Vec::new();

    // TODO

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
            return Some(Msk08Ciphertext {
                _policy: policy.clone(),
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

pub fn msk08_decrypt(
    gk: &Aw11GlobalKey,
    sk: &Aw11SecretKey,
    ct: &Aw11Ciphertext,
) -> Option<Vec<u8>> {
    if traverse_str(&flatten(&sk._attr), &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        // TODO
    }
}
