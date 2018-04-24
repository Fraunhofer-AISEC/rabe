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
//!use rabe::schemes::mke08::*;
//!let (_pk, _msk) = setup();
//!let mut _u_key = keygen(&_pk, &_msk, &String::from("user1"));
//!let _att1 = String::from("aa1::A");
//!let _att2 = String::from("aa2::B");
//!let _a1_key = authgen(&String::from("aa1"));
//!let _a2_key = authgen(&String::from("aa2"));
//!let _att1_pk = request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
//!let _att2_pk = request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
//!_u_key._sk_a.push(request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap());
//!_u_key._sk_a.push(request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap());
//!let _plaintext = String::from("our plaintext!").into_bytes();
//!let _policy = String::from(r#"{"AND": [{"ATT": "aa1::A"}, {"ATT": "aa2::B"}]}"#);
//!let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext).unwrap();
//!assert_eq!(decrypt(&_pk, &_u_key, &_ct, &_policy).unwrap(), _plaintext);
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
use utils::hash::{blake2b_hash_fr, blake2b_hash_g1, blake2b_hash_g2};

/// A MKE08 Public Key (PK)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08PublicKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _p1: bn::G1,
    pub _p2: bn::G2,
    pub _e_gg_y1: bn::Gt,
    pub _e_gg_y2: bn::Gt,
}

/// A MKE08 Master Key (MK)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08MasterKey {
    pub _g1_y: bn::G1,
    pub _g2_y: bn::G2,
}

/// A MKE08 User Key (SK), consisting of a Secret User Key (SKu), a Public User Key (PKu) and a Vector of Secret Attribute Keys (SKau)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08UserKey {
    pub _sk_u: Mke08SecretUserKey,
    pub _pk_u: Mke08PublicUserKey,
    pub _sk_a: Vec<Mke08SecretAttributeKey>,
}

/// A MKE08 Public User Key (PKu)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08PublicUserKey {
    pub _u: String,
    pub _pk_g1: bn::G1,
    pub _pk_g2: bn::G2,
}

/// A MKE08 Secret User Key (SKu)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08SecretUserKey {
    pub _sk_g1: bn::G1,
    pub _sk_g2: bn::G2,
}

/// A MKE08 Secret Authrotiy Key (SKauth)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08SecretAuthorityKey {
    pub _a: String,
    pub _r: bn::Fr,
}

/// A MKE08 Public Attribute Key (PKa)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08PublicAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _gt1: bn::Gt,
    pub _gt2: bn::Gt,
}

/// A MKE08 Secret Attribute Key (SKa)
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08SecretAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

/// A MKE08 Ciphertext (CT) consisting of the AES encrypted data as well as a Vector of all Conjunctions of the access policy
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08Ciphertext {
    pub _e: Vec<Mke08CTConjunction>,
    pub _ct: Vec<u8>,
}

/// A MKE08 Ciphertext Conjunction (CTcon)
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

/// A MKE08 Global Context
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08GlobalContext {
    pub _gk: Mke08PublicKey,
}

/// A MKE08 Context
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Mke08Context {
    pub _mk: Mke08MasterKey,
    pub _pk: Mke08PublicKey,
}

/// The setup algorithm of MKE08. Generates a Mke08PublicKey and a Mke08PublicKey.
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

/// The key generation algorithm of MKE08 CP-ABE. Generates a Mke08UserKey using a Mke08PublicKey, a Mke08MasterKey and a username given as String.
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_mk` - A Master Key (MSK), generated by the function setup()
///	* `_u` - A username given as String. Must be unique.
///
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

/// Sets up and generates a new Authority by creating a secret authority key (SKauth).
/// The key is created for an authority with a given "name".
///
/// # Arguments
///
///	* `_a` - The name of the authority the key is associated with. Must be unique.
///
pub fn authgen(_a: &String) -> Mke08SecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // return secret authority key
    return Mke08SecretAuthorityKey {
        _a: _a.clone(),
        _r: Fr::random(_rng),
    };
}

/// Sets up and generates a public Attribute Key for an Authority, if the attribute belongs to this auhtority
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_a` - The name of the attribute given as String.
///	* `_ska` - A Secret Authority Key (SKauth), generated by the function authgen()
///
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

/// Sets up and generates a secret Attribute Key for a given user by an authorized authority, if the attribute belongs to this auhtority and the user is eligible to own the attribute.
///
/// # Arguments
///
///	* `_pk_u` - A Public User Key (PKu), generated by the function keygen()
///	* `_a` - The name of the attribute given as String.
///	* `_ska` - A Secret Authority Key (SKauth), generated by the function authgen()
///
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

/// The encrypt algorithm of MKE08. Generates an Mke08Ciphertext using an Mke08PublicKey,
/// a Vector of Mke08PublicAttributeKeys, an access policy given as String as well as some plaintext data given as [u8].
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_attr_pks` - A Vector of all Mke08PublicAttributeKey that are involded in the policy
///	* `_policy` - An access policy given as JSON String
///	* `_plaintext` - plaintext data given as a Vector of u8
///
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

/// The decrypt algorithm of MKE08. Reconstructs the original plaintext data as Vec<u8>, given a Mke08PublicKey, a Mke08Ciphertext and a matching Mke08UserKey.
///
/// # Arguments
///
///	* `_pk` - A Mke08PublicKey (PK), generated by the function setup()
///	* `_sk` - A Mke08UserKey (SK), generated by the function keygen()
///	* `_ct` - A Mke08Ciphertext
///	* `_policy` - An access policy given as JSON String
///
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

/// MKE08 Scheme helper function: is_satisfiable
/// Checks if a Conjunction of Attributes (a part of an access policy in DNF) is satisfied by the vector of secret attribute keys
/// Returns true if satisfiable.
///
/// # Arguments
///
///	* `_conjunction` - A Conjunction of attributes given as String Vector
///	* `_sk` - A Vector of Mke08SecretAttributeKeys
///
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

/// MKE08 Scheme helper function: calc_satisfiable
/// Calculates the Conjunction of Attributes (a part of an access policy in DNF) using a Vector of Mke08SecretAttributeKeys
///
/// # Arguments
///
///	* `_conjunction` - A Conjunction of attributes given as String Vector
///	* `_sk` - A Vector of Mke08SecretAttributeKeys
///
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

/// MKE08 Scheme helper function: from_authority
/// Returns true if a specific attribute is handled by a given authority.
/// Please adopt or implement you own logic. Right now the algorithm checks if the first part
/// of an attribute up to "::" is equal with the authority name.
/// i.e. Attribute: "Fraunhofer::User" is handled by Fraunhofer = true
///      Attribute: "BWM::User" is handled by Fraunhofer = false
///
/// # Arguments
///
///	* `_attr` - Name of the attribute given as String
///	* `_sk` - Name of the auhtority given as String
///
fn from_authority(_attr: &String, _authority: &String) -> bool {
    let v: Vec<_> = _attr.match_indices("::").collect();
    if v.len() == 1 {
        return _attr.get(0..v[0].0).unwrap().to_string() == _authority.to_string();
    }
    return false;
}

/// MKE08 Scheme helper function: is_eligible
/// Returns true if a specific user is eligible to own a attribute given by _attr
/// Please adopt and implement you own logic.
///
/// # Arguments
///
///	* `_attr` - Name of the attribute given as String
///	* `_user` - Name of the user given as String
///
fn is_eligible(_attr: &String, _user: &String) -> bool {
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
        let _a1_key = authgen(&String::from("aa1"));
        // authority2
        let _a2_key = authgen(&String::from("aa2"));
        // our attributes
        let _att1 = String::from("aa1::A");
        let _att2 = String::from("aa2::B");
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
        let _policy = String::from(r#"{"AND": [{"ATT": "aa1::A"}, {"ATT": "aa2::B"}]}"#);
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
        let _a1_key = authgen(&String::from("aa1"));
        // authority2
        let _a2_key = authgen(&String::from("aa2"));
        // our attributes
        let _att1 = String::from("aa1::C");
        let _att2 = String::from("aa2::B");
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
        let _policy = String::from(r#"{"OR": [{"ATT": "aa1::A"}, {"ATT": "aa2::B"}]}"#);
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
