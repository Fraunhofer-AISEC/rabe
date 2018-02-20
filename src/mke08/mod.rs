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
use policy::DnfPolicy;
use tools::*;

//////////////////////////////////////////////////////
// MKE08 ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08PublicKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _p1: bn::G1,
    pub _p2: bn::G2,
    pub _e_gg_y: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08MasterKey {
    pub _g1_y: bn::G1,
    pub _g2_y: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08PublicUserKey {
    pub _u: String,
    pub _pk_g1: bn::G1,
    pub _pk_g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretUserKey {
    pub _sk_g1: bn::G1,
    pub _sk_g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretAuthorityKey {
    pub _a: String,
    pub _h: bn::Fr,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08PublicAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _gt: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08Ciphertext {
    pub _policy: String,
    pub _c: Vec<(String, bn::Gt, bn::G1, bn::G1, bn::G2, bn::G2)>,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08GlobalContext {
    pub _gk: Mke08PublicKey,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08Context {
    pub _mke: Mke08MasterKey,
    pub _pk: Mke08PublicKey,
}

//////////////////////////////////////////
// MKE08 DABE on type-3
//////////////////////////////////////////

// global setup
pub fn mke08_setup() -> (Mke08PublicKey, Mke08MasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    let _y = Fr::random(_rng);
    let _z = Fr::random(_rng);
    // generator of group G1: g1 and generator of group G2: g2
    let _pk = Mke08PublicKey {
        _g1: _g1,
        _g2: _g2,
        _p1: _g1 * _z,
        _p2: _g2 * _z,
        _e_gg_y: pairing(_g1, _g2).pow(_y),
    };
    // generator of group G1: g1 and generator of group G2: g2
    let _mk = Mke08MasterKey {
        _g1_y: _g1 * _y,
        _g2_y: _g2 * _y,
    };
    // return PK and mke
    return (_pk, _mk);
}

// user setup
pub fn mke08_create_user(
    pk: &Mke08PublicKey,
    mk: &Mke08MasterKey,
    u: &String,
) -> (Mke08PublicUserKey, Mke08SecretUserKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _mk_u = Fr::random(_rng);
    // return PK and mke
    return (
        Mke08PublicUserKey {
            _u: u.clone(),
            _pk_g1: pk._g1 * _mk_u,
            _pk_g2: pk._g2 * _mk_u,
        },
        Mke08SecretUserKey {
            _sk_g1: mk._g1_y + (pk._p1 * _mk_u),
            _sk_g2: mk._g2_y + (pk._p2 * _mk_u),
        },
    );
}

// authority setup
pub fn mke08_create_authority(pk: &Mke08PublicKey, a: &String) -> Mke08SecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // return PK and mke
    return Mke08SecretAuthorityKey {
        _a: a.clone(),
        _h: Fr::random(_rng),
    };
}

// request an attribute PK from an authority
pub fn mke08_request_authority_pk(
    pk: &Mke08PublicKey,
    a: &String,
    sk_a: &Mke08SecretAuthorityKey,
) -> Option<Mke08PublicAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(a, &sk_a._a) {
        let exponent = blake2b_hash_fr(a) * sk_a._h;
        // return PK and mke
        return Some(Mke08PublicAttributeKey {
            _str: a.clone(),
            _g1: pk._g1 * exponent,
            _g2: pk._g2 * exponent,
            _gt: pk._e_gg_y.pow(exponent),
        });
    } else {
        return None;
    }
}

// request an attribute PK from an authority
pub fn mke08_request_authority_sk(
    pk: &Mke08PublicKey,
    a: &String,
    sk_a: &Mke08SecretAuthorityKey,
    pk_u: &Mke08PublicUserKey,
) -> Option<Mke08SecretAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(a, &sk_a._a) && is_eligible(a, &pk_u._u) {
        let exponent = blake2b_hash_fr(a) * sk_a._h;
        // return PK and mke
        return Some(Mke08SecretAttributeKey {
            _str: a.clone(),
            _g1: pk_u._pk_g1 * exponent,
            _g2: pk_u._pk_g2 * exponent,
        });
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
pub fn mke08_encrypt(
    pk: &Mke08PublicKey,
    attr_pks: &Vec<Mke08PublicAttributeKey>,
    policy: &String,
    plaintext: &[u8],
) -> Option<Mke08Ciphertext> {
    // if policy is in DNF
    if DnfPolicy::is_in_dnf(&policy) {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // an DNF policy from the given String
        let dnf: DnfPolicy = DnfPolicy::from_string(&policy, attr_pks).unwrap();
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
                return Some(Mke08Ciphertext {
                    _policy: policy.clone(),
                    _c: _c,
                    _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                    _iv: iv,
                });
            }
        }
    } else {
        return None;
    }
}

/*
 * decrypt
 * Decrypt a ciphertext
 * SK is the user's private key dictionary sk.attr: { xxx , xxx }


pub fn mke08_decrypt() -> Option<Vec<u8>> {
    if traverse_str(&flatten(&sk._attr), &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        // TODO
    }
}
 */
