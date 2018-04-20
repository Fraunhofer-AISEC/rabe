//! This is the documentation for the `MKE08` scheme:
//!
//! Developped by:	S Müller, S Katzenbeisser, C Eckert , "Distributed Attribute-based Encryption"
//! Published in:	International Conference on Information Security and Cryptology, Heidelberg, 2008
//! Available from:	http://www2.seceng.informatik.tu-darmstadt.de/assets/mueller/icisc08.pdf
//! * type:			encryption (attribute-based)
//! * setting:		bilinear groups (asymmetric)
//! :Authors:		Georg Bramm
//! :Date:			04/2018
//!
//! # Examples
//!
//! ```
//!
//! ```
extern crate bn;
extern crate rand;
extern crate serde;
extern crate serde_json;

use std::string::String;
use bn::*;
use utils::policy::dnf::DnfPolicy;
use utils::tools::*;
use utils::aes::*;

//////////////////////////////////////////////////////
// MKE08 ABE structs
//////////////////////////////////////////////////////
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08PublicKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _p1: bn::G1,
    pub _p2: bn::G2,
    pub _e_gg_y1: bn::Gt,
    pub _e_gg_y2: bn::Gt,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08MasterKey {
    pub _g1_y: bn::G1,
    pub _g2_y: bn::G2,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08UserKey {
    pub _sk_u: Mke08SecretUserKey,
    pub _pk_u: Mke08PublicUserKey,
    pub _sk_a: Vec<Mke08SecretAttributeKey>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08PublicUserKey {
    pub _u: String,
    pub _pk_g1: bn::G1,
    pub _pk_g2: bn::G2,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08SecretUserKey {
    pub _sk_g1: bn::G1,
    pub _sk_g2: bn::G2,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08SecretAuthorityKey {
    pub _a: String,
    pub _r: bn::Fr,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08PublicAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _gt1: bn::Gt,
    pub _gt2: bn::Gt,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08SecretAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08Ciphertext {
    pub _e: Vec<Mke08CTConjunction>,
    pub _ct: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08CTConjunction {
    pub _str: Vec<String>,
    pub _j1: bn::Gt,
    pub _j2: bn::Gt,
    pub _j3: bn::G1,
    pub _j4: bn::G2,
    pub _j5: bn::G1,
    pub _j6: bn::G2,
}

//For C
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08GlobalContext {
    pub _gk: Mke08PublicKey,
}

//For C
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08Context {
    pub _mk: Mke08MasterKey,
    pub _pk: Mke08PublicKey,
}

//////////////////////////////////////////
// MKE08 DABE on type-3
//////////////////////////////////////////

// global key generation
pub fn setup() -> (Mke08PublicKey, Mke08MasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    let _p1 = G1::random(_rng);
    let _p2 = G2::random(_rng);
    let _y1 = Fr::random(_rng);
    let _y2 = Fr::random(_rng);
    // return PK and MK
    return (
        Mke08PublicKey {
            _g1: _g1,
            _g2: _g2,
            _p1: _p1,
            _p2: _p2,
            _e_gg_y1: pairing(_g1, _g2).pow(_y1),
            _e_gg_y2: pairing(_g1, _g2).pow(_y2),
        },
        Mke08MasterKey {
            _g1_y: _g1 * _y1,
            _g2_y: _g2 * _y2,
        },
    );
}

// user key generation
pub fn keygen(_pk: &Mke08PublicKey, _mk: &Mke08MasterKey, _u: &String) -> Mke08UserKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _mk_u = Fr::random(_rng);
    // return pk_u and sk_u
    return Mke08UserKey {
        _sk_u: Mke08SecretUserKey {
            _sk_g1: _mk._g1_y + (_pk._p1 * _mk_u),
            _sk_g2: _mk._g2_y + (_pk._p2 * _mk_u),
        },
        _pk_u: Mke08PublicUserKey {
            _u: _u.clone(),
            _pk_g1: _pk._g1 * _mk_u,
            _pk_g2: _pk._g2 * _mk_u,
        },
        _sk_a: Vec::new(),
    };
}

// authority setup
pub fn authgen(_a: &String) -> Mke08SecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // return secret authority key
    return Mke08SecretAuthorityKey {
        _a: _a.clone(),
        _r: Fr::random(_rng),
    };
}

// request an attribute PK from an authority
pub fn request_authority_pk(
    _pk: &Mke08PublicKey,
    _a: &String,
    _sk_a: &Mke08SecretAuthorityKey,
) -> Option<Mke08PublicAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(_a, &_sk_a._a) {
        let exponent = blake2b_hash_fr(_a) * blake2b_hash_fr(&_sk_a._a) * _sk_a._r;
        // return PK and mke
        return Some(Mke08PublicAttributeKey {
            _str: _a.clone(),
            _g1: _pk._g1 * exponent,
            _g2: _pk._g2 * exponent,
            _gt1: _pk._e_gg_y1.pow(exponent),
            _gt2: _pk._e_gg_y2.pow(exponent),
        });
    } else {
        return None;
    }
}

// request an attribute PK from an authority
pub fn request_authority_sk(
    _a: &String,
    _sk_a: &Mke08SecretAuthorityKey,
    _pk_u: &Mke08PublicUserKey,
) -> Option<Mke08SecretAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(_a, &_sk_a._a) && is_eligible(_a, &_pk_u._u) {
        let exponent = blake2b_hash_fr(_a) * blake2b_hash_fr(&_sk_a._a) * _sk_a._r;
        // return PK and mke
        return Some(Mke08SecretAttributeKey {
            _str: _a.clone(),
            _g1: _pk_u._pk_g1 * exponent,
            _g2: _pk_u._pk_g2 * exponent,
        });
    } else {
        return None;
    }
}
/* encrypt
 * _attr_pks is a vector of all public attribute keys
 */
pub fn encrypt(
    _pk: &Mke08PublicKey,
    _attr_pks: &Vec<Mke08PublicAttributeKey>,
    _policy: &String,
    _plaintext: &[u8],
) -> Option<Mke08Ciphertext> {
    // if policy is in DNF
    if DnfPolicy::is_in_dnf(&_policy) {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // an DNF policy from the given String
        let dnf: DnfPolicy = DnfPolicy::from_string(&_policy, _attr_pks).unwrap();
        // random Gt msgs
        let _msg1 = pairing(G1::random(_rng), G2::random(_rng));
        let _msg2 = _msg1.pow(Fr::random(_rng));
        let _msg = _msg1 * _msg2;
        // CT result vectors
        let mut _e: Vec<Mke08CTConjunction> = Vec::new();
        // now add randomness using _r_j
        for _term in dnf._terms.into_iter() {
            let _r_j = Fr::random(_rng);
            _e.push(Mke08CTConjunction {
                _str: _term.0,
                _j1: _term.1.pow(_r_j) * _msg1,
                _j2: _term.2.pow(_r_j) * _msg2,
                _j3: _pk._p1 * _r_j,
                _j4: _pk._p2 * _r_j,
                _j5: _term.3 * _r_j,
                _j6: _term.4 * _r_j,
            });
        }
        //Encrypt plaintext using derived key from secret
        return Some(Mke08Ciphertext {
            _e: _e,
            _ct: encrypt_symmetric(&_msg, &_plaintext.to_vec()).unwrap(),
        });
    } else {
        return None;
    }
}

/*
 * decrypt
 * Decrypt a ciphertext
 * SK is the user's private key dictionary sk.attr: { xxx , xxx }
*/
pub fn decrypt(
    _pk: &Mke08PublicKey,
    _sk: &Mke08UserKey,
    _ct: &Mke08Ciphertext,
    _policy: &String,
) -> Option<Vec<u8>> {
    let _attr = _sk._sk_a
        .iter()
        .map(|triple| {
            let _a = triple.clone();
            _a._str.to_string()
        })
        .collect::<Vec<_>>();
    if traverse_str(&_attr, &_policy) == false {
        //println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let mut _msg = Gt::one();
        for (_i, _e_j) in _ct._e.iter().enumerate() {
            if is_satisfiable(&_e_j._str, &_sk._sk_a) {
                let _sk_sum = calc_satisfiable(&_e_j._str, &_sk._sk_a);
                _msg = _e_j._j1 * _e_j._j2 * pairing(_e_j._j3, _sk_sum.1) *
                    pairing(_sk_sum.0, _e_j._j4) *
                    (pairing(_e_j._j5, _sk._sk_u._sk_g2) * pairing(_sk._sk_u._sk_g1, _e_j._j6))
                        .inverse();
                break;
            }
        }
        // Decrypt plaintext using derived secret from mke08 scheme
        return decrypt_symmetric(&_msg, &_ct._ct);
    }
}

// MKE08 Scheme helper functions

fn is_satisfiable(_conjunction: &Vec<String>, _sk: &Vec<Mke08SecretAttributeKey>) -> bool {
    let mut _ret: bool = true;
    for _attr in _conjunction {
        match _sk.into_iter().find(|&x| x._str == *_attr) {
            None => {
                _ret = false;
                break;
            }
            Some(_attr_sk) => {}
        }
    }
    _ret
}

fn calc_satisfiable(
    _conjunction: &Vec<String>,
    _sk: &Vec<Mke08SecretAttributeKey>,
) -> (bn::G1, bn::G2) {
    let mut ret: (bn::G1, bn::G2) = (G1::one(), G2::one());
    for _i in 0usize.._conjunction.len() {
        match _sk.into_iter().find(
            |&x| x._str == _conjunction[_i].to_string(),
        ) {
            None => {}
            Some(_found) => {
                if _i == 0 {
                    ret = (_found._g1, _found._g2);
                } else {
                    ret = (ret.0 + _found._g1, ret.1 + _found._g2);
                }
            }
        }
    }
    ret
}

fn from_authority(_attr: &String, _authority: &String) -> bool {
    // TODO !!!!
    // Implement blockchain logic to determine which attribute belongs to authority
    return true;
}

fn is_eligible(_attr: &String, _user: &String) -> bool {
    // TODO !!!!
    // Implement blockchain logic to determine which user is able to own which attribute
    return true;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_and() {
        // setup scheme
        let (_pk, _msk) = setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = keygen(&_pk, &_msk, &String::from("user1"));
        // authority1
        let _a1_key = authgen(&String::from("authority1"));
        // authority2
        let _a2_key = authgen(&String::from("authority2"));
        // our attributes
        let _att1 = String::from("A");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        // add attribute sk's to user key
        _u_key._sk_a.push(
            request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap(),
        );
        _u_key._sk_a.push(
            request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap(),
        );
        // our plaintext
        let _plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let _policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct, &_policy);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }


    #[test]
    fn test_or() {
        // setup scheme
        let (_pk, _msk) = setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = keygen(&_pk, &_msk, &String::from("user1"));
        // authority1
        let _a1_key = authgen(&String::from("authority1"));
        // authority2
        let _a2_key = authgen(&String::from("authority2"));
        // our attributes
        let _att1 = String::from("C");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        // add attribute sk's to user key
        _u_key._sk_a.push(
            request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap(),
        );
        _u_key._sk_a.push(
            request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap(),
        );
        // our plaintext
        let _plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let _policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct, &_policy);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn test_is_satisfiable() {
        // A && B && C
        let mut _conjunction: Vec<String> = Vec::new();
        _conjunction.push(String::from("A"));
        _conjunction.push(String::from("B"));
        _conjunction.push(String::from("C"));
        // a sk_a
        let mut _sk_as: Vec<Mke08SecretAttributeKey> = Vec::new();
        _sk_as.push(Mke08SecretAttributeKey {
            _str: String::from("A"),
            _g1: G1::one(),
            _g2: G2::one(),
        });
        assert!(!is_satisfiable(&_conjunction, &_sk_as));
        _sk_as.push(Mke08SecretAttributeKey {
            _str: String::from("B"),
            _g1: G1::one(),
            _g2: G2::one(),
        });
        assert!(!is_satisfiable(&_conjunction, &_sk_as));
        _sk_as.push(Mke08SecretAttributeKey {
            _str: String::from("C"),
            _g1: G1::one(),
            _g2: G2::one(),
        });
        assert!(is_satisfiable(&_conjunction, &_sk_as));
    }
}
