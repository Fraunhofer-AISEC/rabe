//! `MKE08` scheme Müller, Katzenbeisser, Eckert.
//!
//! * Developped by S Müller, S Katzenbeisser, C Eckert , "Distributed Attribute-based Encryption"
//! * Published in International Conference on Information Security and Cryptology, Heidelberg, 2008
//! * Available from <http://www2.seceng.informatik.tu-darmstadt.de/assets/mueller/icisc08.pdf>
//! * Type encryption (attribute-based)
//! * Setting bilinear groups (asymmetric)
//! * Authors Georg Bramm
//! * Date: 04/2018
//!
//! # Examples
//!
//! ```
//!use rabe::schemes::mke08::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
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
//!let _policy = String::from(r#""aa1::A" and "aa2::B""#);
//!let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, PolicyLanguage::HumanPolicy, &_plaintext).unwrap();
//!assert_eq!(decrypt(&_pk, &_u_key, &_ct).unwrap(), _plaintext);
//! ```
use rabe_bn::{Group, Fr, G1, G2, Gt, pairing};
use rand::Rng;
use std::string::String;
use utils::{
    aes::*,
    hash::sha3_hash_fr,
    policy::dnf::DnfPolicy,
    tools::*
};
use utils::policy::pest::{PolicyLanguage, parse, PolicyType};
use utils::policy::dnf::policy_in_dnf;
use crate::error::RabeError;
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// A MKE08 Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08PublicKey {
    pub _g1: G1,
    pub _g2: G2,
    pub _p1: G1,
    pub _p2: G2,
    pub _e_gg_y1: Gt,
    pub _e_gg_y2: Gt,
}

/// A MKE08 Master Key (MK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08MasterKey {
    pub _g1_y: G1,
    pub _g2_y: G2,
}

/// A MKE08 User Key (SK), consisting of a Secret User Key (SKu), a Public User Key (PKu) and a Vector of Secret Attribute Keys (SKau)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08UserKey {
    pub _sk_u: Mke08SecretUserKey,
    pub _pk_u: Mke08PublicUserKey,
    pub _sk_a: Vec<Mke08SecretAttributeKey>,
}

/// A MKE08 Public User Key (PKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08PublicUserKey {
    pub _u: String,
    pub _pk_g1: G1,
    pub _pk_g2: G2,
}

/// A MKE08 Secret User Key (SKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08SecretUserKey {
    pub _sk_g1: G1,
    pub _sk_g2: G2,
}

/// A MKE08 Secret Authrotiy Key (SKauth)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08SecretAuthorityKey {
    pub _a: String,
    pub _r: Fr,
}

/// A MKE08 Public Attribute Key (PKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08PublicAttributeKey {
    pub _str: String,
    pub _g1: G1,
    pub _g2: G2,
    pub _gt1: Gt,
    pub _gt2: Gt,
}

/// A MKE08 Secret Attribute Key (SKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08SecretAttributeKey {
    pub _str: String,
    pub _g1: G1,
    pub _g2: G2,
}

/// A MKE08 Ciphertext (CT) consisting of the AES encrypted data as well as a Vector of all Conjunctions of the access policy
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08Ciphertext {
    pub _policy: (String, PolicyLanguage),
    pub _e: Vec<Mke08CTConjunction>,
    pub _ct: Vec<u8>,
}

/// A MKE08 Ciphertext Conjunction (CTcon)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Mke08CTConjunction {
    pub _str: Vec<String>,
    pub _j1: Gt,
    pub _j2: Gt,
    pub _j3: G1,
    pub _j4: G2,
    pub _j5: G1,
    pub _j6: G2,
}

/// The setup algorithm of MKE08. Generates a Mke08PublicKey and a Mke08PublicKey.
pub fn setup() -> (Mke08PublicKey, Mke08MasterKey) {
    // random number generator
    let mut _rng = rand::thread_rng();
    let _g1:G1 = _rng.gen();
    let _g2:G2 = _rng.gen();
    let _p1:G1 = _rng.gen();
    let _p2:G2 = _rng.gen();
    let _y1:Fr = _rng.gen();
    let _y2:Fr = _rng.gen();
    let _e_gg_y1 = pairing(_g1, _g2).pow(_y1);
    let _e_gg_y2 = pairing(_g1, _g2).pow(_y2);
    let _g1_y = _g1 * _y1;
    let _g2_y = _g2 * _y2;
    // return PK and MK
    (
        Mke08PublicKey {_g1, _g2, _p1, _p2, _e_gg_y1, _e_gg_y2},
        Mke08MasterKey {_g1_y, _g2_y }
    )
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
    let mut _rng = rand::thread_rng();
    let _mk_u:Fr = _rng.gen();
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
    let mut _rng = rand::thread_rng();
    // return secret authority key
    return Mke08SecretAuthorityKey {
        _a: _a.clone(),
        _r: _rng.gen(),
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
    _attribute: &String,
    _ska: &Mke08SecretAuthorityKey,
) -> Result<Mke08PublicAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(_attribute, &_ska._a) {
        match sha3_hash_fr(_attribute) {
            Ok(hash_1) => {
                match sha3_hash_fr(&_ska._a) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * _ska._r;
                        // return PK and mke
                        Ok(Mke08PublicAttributeKey {
                            _str: _attribute.to_string(),
                            _g1: _pk._g1 * exp,
                            _g2: _pk._g2 * exp,
                            _gt1: _pk._e_gg_y1.pow(exp),
                            _gt2: _pk._e_gg_y2.pow(exp),
                        })
                    },
                    Err(e) => Err(e)
                }
            },
            Err(e) => Err(e)
        }
    } else {
        Err(RabeError::new(&format!("attribute {} is not from_authority() or !is_eligible()", _attribute.to_string())))
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
) -> Result<Mke08SecretAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(_a, &_sk_a._a) && is_eligible(_a, &_pk_u._u) {
        match sha3_hash_fr(_a) {
            Ok(hash_1) => {
                match sha3_hash_fr(&_sk_a._a) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * _sk_a._r;
                        // return PK and mke
                        Ok(Mke08SecretAttributeKey {
                            _str: _a.clone(),
                            _g1: _pk_u._pk_g1 * exp,
                            _g2: _pk_u._pk_g2 * exp,
                        })
                    },
                    Err(e) => Err(e)
                }
            },
            Err(e) => Err(e)
        }
    } else {
        Err(RabeError::new(&format!("attribute {} is not from_authority() or !is_eligible()", _a.to_string())))
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
    _language: PolicyLanguage,
    _plaintext: &[u8],
) -> Result<Mke08Ciphertext, RabeError> {
    match parse(_policy, _language) {
        Ok(pol) => {
            // if policy is in DNF
            return if policy_in_dnf(&pol, false, None) {
                // random number generator
                let mut _rng = rand::thread_rng();
                // an DNF policy from the given String
                let policy = DnfPolicy::from_string(&_policy, _attr_pks, _language).unwrap();
                // random Gt msgs
                let _msg1 = pairing(_rng.gen(), _rng.gen());
                let _msg2 = _msg1.pow(_rng.gen());
                let _msg = _msg1 * _msg2;
                // CT result vectors
                let mut _e: Vec<Mke08CTConjunction> = Vec::new();
                // now add randomness using _r_j
                for _term in policy._terms.into_iter() {
                    let _r_j: Fr = _rng.gen();
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
                let _policy = _policy.to_string();
                let _ct = encrypt_symmetric(_msg, &_plaintext.to_vec()).unwrap();
                Ok(Mke08Ciphertext { _policy: (_policy, _language), _e, _ct})
            } else {
                Err(RabeError::new("Error in mke08/encrypt: policy is not in dnf"))
            }
        },
        Err(e) => Err(e)
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
    _ct: &Mke08Ciphertext) -> Result<Vec<u8>, RabeError> {
    let _attr = _sk._sk_a
        .iter()
        .map(|triple| {
            let _a = triple.clone();
            _a._str.to_string()
        })
        .collect::<Vec<_>>();
    match parse(_ct._policy.0.as_ref(), _ct._policy.1) {
        Ok(pol) => {
            return if traverse_policy(&_attr, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in mke08/decrypt: attributes in sk do not match policy in ct."))
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
                decrypt_symmetric(_msg, &_ct._ct)
            }
        },
        Err(e) => Err(e)
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
) -> (G1, G2) {
    let mut ret: (G1, G2) = (G1::one(), G2::one());
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn is_eligible(_attr: &String, _user: &String) -> bool {
    return true;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn and() {
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
        let _policy = String::from(r#"{"name": "and", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy,PolicyLanguage::JsonPolicy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn or() {
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
        let _policy = String::from(r#"{"name": "or", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, PolicyLanguage::JsonPolicy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn or_and() {
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
        let _att3 = String::from("aa2::X");
        // authority1 owns A
        let _att1_pk = request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        let _att3_pk = request_authority_pk(&_pk, &_att3, &_a2_key).unwrap();
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
        let _policy = String::from(
            r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}, {"name": "aa2::X"}]}"#,
        );
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(
            &_pk,
            &vec![_att1_pk, _att2_pk, _att3_pk],
            &_policy,
            PolicyLanguage::JsonPolicy,
            &_plaintext,
        ).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn issatisfiable() {
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

    #[test]
    fn not() {
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
        let _policy = String::from(r#"{"name": "or", "children": [{"name": "aa2::A"}, {"name": "aa1::B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, PolicyLanguage::JsonPolicy, &_plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), false);
    }
}
