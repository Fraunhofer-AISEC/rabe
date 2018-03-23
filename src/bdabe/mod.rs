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
use policydnf::*;
use tools::*;

//////////////////////////////////////////////////////
// BDABE ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabePublicKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _p1: bn::G1,
    pub _p2: bn::G2,
    pub _e_gg_y: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeMasterKey {
    pub _y: bn::Fr,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeUserKey {
    pub _sk: BdabeSecretUserKey,
    pub _pk: BdabePublicUserKey,
    pub _ska: Vec<BdabeSecretAttributeKey>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabePublicUserKey {
    pub _u: String,
    pub _u1: bn::G1,
    pub _u2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeSecretUserKey {
    pub _u1: bn::G1,
    pub _u2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeSecretAuthorityKey {
    pub _a1: bn::G1,
    pub _a2: bn::G2,
    pub _a3: bn::Fr,
    pub _a: String,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabePublicAttributeKey {
    pub _str: String,
    pub _a1: bn::G1,
    pub _a2: bn::G2,
    pub _a3: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeSecretAttributeKey {
    pub _au1: bn::G1,
    pub _au2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeCiphertextTuple {
    pub _str: Vec<String>,
    pub _e1: bn::Gt,
    pub _e2: bn::G1,
    pub _e3: bn::G2,
    pub _e4: bn::G1,
    pub _e5: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeCiphertext {
    pub _j: Vec<BdabeCiphertextTuple>,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeGlobalContext {
    pub _gk: BdabePublicKey,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct BdabeContext {
    pub _mk: BdabeMasterKey,
    pub _pk: BdabePublicKey,
}

//////////////////////////////////////////
// BDABE on type-3
//////////////////////////////////////////

// global key generation
pub fn setup() -> (BdabePublicKey, BdabeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    let _p1 = G1::random(_rng);
    let _p2 = G2::random(_rng);
    let _y = Fr::random(_rng);
    // return pk and mk
    return (
        BdabePublicKey {
            _g1: _g1,
            _g2: _g2,
            _p1: _p1,
            _p2: _p2,
            _e_gg_y: pairing(_g1, _g2).pow(_y),
        },
        BdabeMasterKey { _y: _y },
    );
}

// user key generation
pub fn create_user(
    _pk: &BdabePublicKey,
    _ska: &BdabeSecretAuthorityKey,
    _u: &String,
) -> BdabeUserKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _r_u = Fr::random(_rng);
    // return pk_u and sk_u
    return BdabeUserKey {
        _sk: BdabeSecretUserKey {
            _u1: _ska._a1 + (_pk._p1 * _r_u),
            _u2: _ska._a2 + (_pk._p2 * _r_u),
        },
        _pk: BdabePublicUserKey {
            _u: _u.clone(),
            _u1: _pk._g1 * _r_u,
            _u2: _pk._g2 * _r_u,
        },
        _ska: Vec::new(),
    };
}

// authority setup
pub fn create_authority(
    _pk: &BdabePublicKey,
    _mk: &BdabeMasterKey,
    _a: &String,
) -> BdabeSecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _alpha = Fr::random(_rng);
    let _beta = _mk._y - _alpha;
    // return secret authority key
    return BdabeSecretAuthorityKey {
        _a1: _pk._g1 * _alpha,
        _a2: _pk._g2 * _beta,
        _a3: Fr::random(_rng),
        _a: _a.clone(),
    };
}

// request an attribute PK from an authority
pub fn request_attribute_pk(
    _pk: &BdabePublicKey,
    _sk_a: &BdabeSecretAuthorityKey,
    _a: &String,
) -> Option<BdabePublicAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(_a, &_sk_a._a) {
        let exponent = blake2b_hash_fr(_a) * blake2b_hash_fr(&_sk_a._a) * _sk_a._a3;
        // return PK and mke
        return Some(BdabePublicAttributeKey {
            _str: _a.clone(),
            _a1: _pk._g1 * exponent,
            _a2: _pk._g2 * exponent,
            _a3: _pk._e_gg_y.pow(exponent),
        });
    } else {
        return None;
    }
}

// request an attribute PK from an authority
pub fn request_attribute_sk(
    _a: &String,
    _sk_a: &BdabeSecretAuthorityKey,
    _pk_u: &BdabePublicUserKey,
) -> Option<BdabeSecretAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(_a, &_sk_a._a) && is_eligible(_a, &_pk_u._u) {
        let exponent = blake2b_hash_fr(_a) * blake2b_hash_fr(&_sk_a._a) * _sk_a._a3;
        // return PK and mke
        return Some(BdabeSecretAttributeKey {
            _au1: _pk_u._u1 * exponent,
            _au2: _pk_u._u2 * exponent,
        });
    } else {
        return None;
    }
}
/* encrypt
 * _attr_pks is a vector of all public attribute keys
 */
pub fn encrypt(
    _pk: &BdabePublicKey,
    _attr_pks: &Vec<BdabePublicAttributeKey>,
    _policy: &String,
    _plaintext: &[u8],
) -> Option<BdabeCiphertext> {
    // if policy is in DNF
    if DnfPolicy::is_in_dnf(&_policy) {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // an DNF policy from the given String
        let dnf: DnfPolicy = DnfPolicy::from_string(&_policy, _attr_pks).unwrap();
        // random Gt msg
        let _msg = pairing(G1::random(_rng), G2::random(_rng));
        // CT result vectors
        let mut _j: Vec<BdabeCiphertextTuple> = Vec::new();
        // now add randomness using _r_j
        for _term in dnf._terms {
            let _r_j = Fr::random(_rng);
            _j.push(BdabeCiphertextTuple {
                _str: _term.0,
                _e1: _term.1.pow(_r_j) * _msg,
                _e2: _pk._p1 * _r_j,
                _e3: _pk._p2 * _r_j,
                _e4: _term.3 * _r_j,
                _e5: _term.4 * _r_j,
            });
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
                return Some(BdabeCiphertext {
                    _j: _j,
                    _ct: encrypt_aes(&_plaintext, &key, &iv).ok().unwrap(),
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

pub fn decrypt(
    _pk: &BdabePublicKey,
    _ct: &BdabeCiphertext,
    _sk: &BdabeUserKey,
    _policy: &String,
) -> Option<Vec<u8>> {
    if traverse_str(&flatten_mke08(&_sk._sk_a), &_policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let mut _msg = Gt::zero();
        for _i in 0usize.._ct._str.len() {
            if is_satisfiable(&_ct._str[_i], &_sk._sk_a) {
                let _sk_sum = calc_satisfiable(&_ct._str[_i], &_sk._sk_a);
                _msg = _ct._e_j1[_i] * _ct._e_j2[_i] * pairing(_ct._e_j3[_i], _sk_sum.1) *
                    pairing(_sk_sum.0, _ct._e_j4[_i]) *
                    (pairing(_ct._e_j5[_i], _sk._sk_u._sk_g2) *
                         pairing(_sk._sk_u._sk_g1, _ct._e_j6[_i])).inverse();
                break;
            }
        }
        // Decrypt plaintext using derived secret from Bdabe scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&_ct._ct[..], &key, &_ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}
*/
#[cfg(test)]
mod tests {

    use super::*;


    #[test]
    fn test_and() {
        // setup scheme
        let (_pk, _msk) = setup();
        // authority1
        let _a1_key = create_authority(&_pk, &_msk, &String::from("aa1"));
        // authority2
        let _a2_key = create_authority(&_pk, &_msk, &String::from("aa2"));
        // our attributes
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = create_user(&_pk, &_a1_key, &String::from("u1"));
        let _att1 = String::from("A");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        _u_key._ska.push(
            request_attribute_sk(
                &_att1,
                &_a1_key,
                &_u_key._pk,
            ).unwrap(),
        );
        _u_key._ska.push(
            request_attribute_sk(
                &_att2,
                &_a2_key,
                &_u_key._pk,
            ).unwrap(),
        );
        // our plaintext
        let _plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let _policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        //et _match = decrypt(&_pk, &_ct, &_u_key, &_policy);
        //assert_eq!(_match.is_some(), true);
        //assert_eq!(_match.unwrap(), _plaintext);
    }


    #[test]
    fn test_or() {
        // setup scheme
        let (_pk, _msk) = setup();
        // authority1
        let _a1_key = create_authority(&_pk, &_msk, &String::from("aa1"));
        // authority2
        let _a2_key = create_authority(&_pk, &_msk, &String::from("aa2"));
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = create_user(&_pk, &_a2_key, &String::from("u1"));
        // our attributes
        let _att1 = String::from("C");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        _u_key._ska.push(
            request_attribute_sk(
                &_att1,
                &_a1_key,
                &_u_key._pk,
            ).unwrap(),
        );
        _u_key._ska.push(
            request_attribute_sk(
                &_att2,
                &_a2_key,
                &_u_key._pk,
            ).unwrap(),
        );
        // our plaintext
        let _plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let _policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        //let _match = decrypt(&_pk, &_ct, &_u_key, &_policy);
        //assert_eq!(_match.is_some(), true);
        //assert_eq!(_match.unwrap(), _plaintext);
    }
}
