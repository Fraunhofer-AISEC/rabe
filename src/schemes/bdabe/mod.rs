//! `BDABE` scheme by Bramm, Gall, Schuette.
//!
//! * Developped by Bramm, Gall, Schuette, "Blockchain based Distributed Attribute-based Encryption"
//! * Published in ICETE 2018
//! * Available from <https://www.semanticscholar.org/paper/BDABE-Blockchain-based-Distributed-Attribute-based-Bramm-Gall/3451ea120d5eac9a3ec09b24123add69150fa0fd>
//! * Type:	encryption (attribute-based)
//! * Setting: bilinear groups (asymmetric)
//! * Authors: Georg Bramm
//! * Date: 04/2018
//!
//! # Examples
//!
//! ```
//!use rabe::schemes::bdabe::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//!let (_pk, _msk) = setup();
//!let _a1_key = authgen(&_pk, &_msk, &String::from("aa1"));
//!let mut _u_key = keygen(&_pk, &_a1_key, &String::from("u1"));
//!let _att1 = String::from("aa1::A");
//!let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
//!_u_key._ska.push(request_attribute_sk(&_u_key._pk, &_a1_key, &_att1).unwrap());
//!let _plaintext = String::from("our plaintext!").into_bytes();
//!let _policy = String::from(r#""aa1::A" or "aa1::B""#);
//!let _ct: BdabeCiphertext = encrypt(&_pk, &vec![_att1_pk], &_policy, &_plaintext, PolicyLanguage::HumanPolicy).unwrap();
//!let _match = decrypt(&_pk, &_u_key, &_ct);
//!assert_eq!(_match.is_ok(), true);
//!assert_eq!(_match.unwrap(), _plaintext);
//! ```
use std::string::String;
use rand::Rng;
use rabe_bn::{Group, Fr, G1, G2, Gt, pairing};
use utils::{
    policy::*,
    tools::*,
    aes::*,
    hash::sha3_hash_fr
};
use utils::policy::pest::{PolicyLanguage, parse, PolicyType};
use crate::error::RabeError;
use utils::policy::dnf::policy_in_dnf;
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// A BDABE Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabePublicKey {
    pub _g1: G1,
    pub _g2: G2,
    pub _p1: G1,
    pub _p2: G2,
    pub _e_gg_y: Gt,
}

/// A BDABE Master Key (MK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeMasterKey {
    pub _y: Fr,
}

/// A BDABE User Key (PKu, SKu and SKa's)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeUserKey {
    pub _sk: BdabeSecretUserKey,
    pub _pk: BdabePublicUserKey,
    pub _ska: Vec<BdabeSecretAttributeKey>,
}

/// A BDABE Public User Key (PKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabePublicUserKey {
    pub _u: String,
    pub _u1: G1,
    pub _u2: G2,
}

/// A BDABE Secret User Key (SKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeSecretUserKey {
    pub _u1: G1,
    pub _u2: G2,
}

/// A BDABE Secret Attribute Key (SKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeSecretAttributeKey {
    pub _str: String,
    pub _au1: G1,
    pub _au2: G2,
}

/// A BDABE Public Attribute Key (PKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabePublicAttributeKey {
    pub _str: String,
    pub _a1: G1,
    pub _a2: G2,
    pub _a3: Gt,
}

/// A BDABE Secret Authority Key (SKauth)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeSecretAuthorityKey {
    pub _a1: G1,
    pub _a2: G2,
    pub _a3: Fr,
    pub _a: String,
}

/// A Ciphertext Tuple representing a conjunction in a CT
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeCiphertextTuple {
    pub _str: Vec<String>,
    pub _e1: Gt,
    pub _e2: G1,
    pub _e3: G2,
    pub _e4: G1,
    pub _e5: G2,
}

/// A BDABE Ciphertext (CT)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct BdabeCiphertext {
    pub _policy: (String, PolicyLanguage),
    pub _j: Vec<BdabeCiphertextTuple>,
    pub _ct: Vec<u8>,
}

/// The setup algorithm of BDABE. Generates a BdabePublicKey and a BdabeMasterKey.
pub fn setup() -> (BdabePublicKey, BdabeMasterKey) {
    // random number generator
    let mut _rng = rand::thread_rng();
    let _g1:G1 = _rng.gen();
    let _g2:G2 = _rng.gen();
    let _p1:G1 = _rng.gen();
    let _p2:G2 = _rng.gen();
    let _y:Fr = _rng.gen();
    // return pk and mk
    (
        BdabePublicKey {_g1, _g2, _p1, _p2, _e_gg_y: pairing(_g1, _g2).pow(_y) },
        BdabeMasterKey { _y }
    )
}

/// Sets up and generates a new Authority by creating a secret authority key (SKauth).
/// The key is created for an authority with a given "name".
///
/// # Arguments
///
///	* `_pk` - A BdabePublicKey (PK), generated by setup()
///	* `_mk` - A BdabeMasterKey (MK), generated by setup()
///	* `_name` - The name of the authority the key is associated with. Must be unique.
///
pub fn authgen(
    _pk: &BdabePublicKey,
    _mk: &BdabeMasterKey,
    _name: &String,
) -> BdabeSecretAuthorityKey {
    // random number generator
    let mut _rng = rand::thread_rng();
    let _alpha: Fr = _rng.gen();
    let _beta = _mk._y - _alpha;
    let _a1 = _pk._g1 * _alpha;
    let _a2 = _pk._g2 * _beta;
    let _a3:Fr = _rng.gen();
    // return secret authority key
    BdabeSecretAuthorityKey {_a1, _a2, _a3, _a: _name.clone()}
}

/// Sets up and generates a new User by creating a secret user key (SK).
/// The key is created for an user with a given "name".
/// It consists of a BdabeSecretUserKey and a BdabePublicUserKey as well as
/// an empty vector of BdabeSecretAttributeKeys.
///
/// # Arguments
///
///	* `_pk` - A BdabePublicKey (PK), generated by setup()
///	* `_ska` - A BdabeSecretAuthorityKey (SKauth), associated with an authority and generated by authgen()
///	* `_name` - The name of the user the key is associated with. Must be unique.
///
pub fn keygen(
    _pk: &BdabePublicKey,
    _ska: &BdabeSecretAuthorityKey,
    _name: &String,
) -> BdabeUserKey {
    // random number generator
    let mut _rng = rand::thread_rng();
    let _r_u: Fr = _rng.gen();
    // return pk_u and sk_u
    BdabeUserKey {
        _sk: BdabeSecretUserKey {
            _u1: _ska._a1 + (_pk._p1 * _r_u),
            _u2: _ska._a2 + (_pk._p2 * _r_u),
        },
        _pk: BdabePublicUserKey {
            _u: _name.clone(),
            _u1: _pk._g1 * _r_u,
            _u2: _pk._g2 * _r_u,
        },
        _ska: Vec::new(),
    }
}

/// Generates a new BdabePublicAttributeKey for a requested attribute, if it is handled by the authority _ska.
///
/// # Arguments
///
///	* `_pk` - A BdabePublicKey (PK), generated by setup()
///	* `_ska` - A BdabeSecretAuthorityKey (SKauth), associated with an authority and generated by authgen()
///	* `_attribute` - The attribute value as String
///
pub fn request_attribute_pk(
    _pk: &BdabePublicKey,
    _ska: &BdabeSecretAuthorityKey,
    _attribute: &String,
) -> Result<BdabePublicAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(_attribute, &_ska._a) {
        match sha3_hash_fr(_attribute) {
            Ok(hash_1) => {
                match sha3_hash_fr(&_ska._a) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * _ska._a3;
                        // return PK and mke
                        Ok(BdabePublicAttributeKey {
                            _str: _attribute.clone(),
                            _a1: _pk._g1 * exp,
                            _a2: _pk._g2 * exp,
                            _a3: _pk._e_gg_y.pow(exp),
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

/// Generates a new BdabeSecretAttributeKey for a requested attribute, if it is handled by the authority _ska and user _pk_u is eligible to recieve it.
///
/// # Arguments
///
///	* `_pku` - A BdabePublicUserKey (PK), generated by keygen()
///	* `_ska` - A BdabeSecretAuthorityKey (SKauth), associated with an authority and generated by authgen()
///	* `_attribute` - The attribute value as String
///
pub fn request_attribute_sk(
    _pku: &BdabePublicUserKey,
    _ska: &BdabeSecretAuthorityKey,
    _attribute: &String,
) -> Result<BdabeSecretAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(_attribute, &_ska._a) && is_eligible(_attribute, &_pku._u) {
        match sha3_hash_fr(_attribute) {
            Ok(hash_1) => {
                match sha3_hash_fr(&_ska._a) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * _ska._a3;
                        // return PK and mke
                        Ok(BdabeSecretAttributeKey {
                            _str: _attribute.to_string(),
                            _au1: _pku._u1 * exp,
                            _au2: _pku._u2 * exp,
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

/// The encrypt algorithm of BDABE. Generates an BdabeCiphertext using an BdabePublicKey,
/// a Vector of BdabePublicAttributeKeys, an access policy given as String as well as some plaintext data given as [u8].
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_attr_pks` - A Vector of all BdabePublicAttributeKeys that are involded in the policy
///	* `_policy` - An access policy given as JSON String
///	* `_plaintext` - plaintext data given as a Vector of u8
///
pub fn encrypt(
    _pk: &BdabePublicKey,
    _attr_pks: &Vec<BdabePublicAttributeKey>,
    _policy: &String,
    _plaintext: &[u8],
    _language: PolicyLanguage,
) -> Result<BdabeCiphertext, RabeError> {
    match parse(_policy, _language) {
        Ok(pol) => {
            // if policy is in DNF
            if policy_in_dnf(&pol, false, None) {
                // random number generator
                let mut _rng = rand::thread_rng();
                let _policy = _policy.to_string();
                // an DNF policy from the given String
                let dnf: dnf::DnfPolicy = dnf::DnfPolicy::from_string(&_policy, _attr_pks, _language).unwrap();
                // random Gt msg
                let _msg = pairing(_rng.gen(), _rng.gen());
                // CT result vector
                let _ct = encrypt_symmetric(_msg, &_plaintext.to_vec()).unwrap();
                let mut _j: Vec<BdabeCiphertextTuple> = Vec::new();
                // now add randomness using _r_j
                for _term in dnf._terms {
                    let _r_j: Fr = _rng.gen();
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
                Ok(BdabeCiphertext {_policy: (_policy, _language), _j, _ct })
            } else {
                Err(RabeError::new("Error in bdabe/encrypt: Policy not in DNF."))
            }
        },
        Err(e) => Err(e)
    }
}

/// The decrypt algorithm of BDABE. Reconstructs the original plaintext data as Vec<u8>, given a BdabeCiphertext with a matching BdabeUserKey.
///
/// # Arguments
///
///	* `_pk` - A BdabePublicKey (PK), generated by the function setup()
///	* `_sk` - A BdabeUserKey (SK), generated by the function keygen()
///	* `_ct` - A BdabeCiphertext Ciphertext
///
pub fn decrypt(
    _pk: &BdabePublicKey,
    _sk: &BdabeUserKey,
    _ct: &BdabeCiphertext) -> Result<Vec<u8>, RabeError> {
    let _str_attr = _sk
        ._ska
        .iter()
        .map(|_values| _values._str.to_string())
        .collect::<Vec<_>>();
    match parse(_ct._policy.0.as_ref(), _ct._policy.1) {
        Ok(pol) => {
            if traverse_policy(&_str_attr, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in bdabe/decrypt: attributes in sk do not match policy in ct."))
            } else {
                let mut _msg = Gt::one();
                for (_i, _ct_j) in _ct._j.iter().enumerate() {
                    if is_satisfiable(&_ct_j._str, &_sk._ska) {
                        let _sk_sum = calc_satisfiable(&_ct_j._str, &_sk._ska);
                        _msg = _ct_j._e1
                            * pairing(_ct_j._e2, _sk_sum.1)
                            * pairing(_sk_sum.0, _ct_j._e3)
                            * (pairing(_ct_j._e4, _sk._sk._u2) * pairing(_sk._sk._u1, _ct_j._e5)).inverse();
                        break;
                    }
                }
                // Decrypt plaintext using derived secret from Bdabe scheme
                decrypt_symmetric(_msg, &_ct._ct)
            }
        },
        Err(e) => Err(e)
    }


}

/// BDABE Scheme helper function: is_satisfiable
/// Checks if a Conjunction of Attributes (a part of an access policy in DNF) is satisfied by the vector of secret attribute keys
/// Returns true if satisfiable.
///
/// # Arguments
///
///	* `_conjunction` - A Conjunction of attributes given as String Vector
///	* `_sk` - A Vector of Mke08SecretAttributeKeys
///
fn is_satisfiable(_conjunction: &Vec<String>, _sk: &Vec<BdabeSecretAttributeKey>) -> bool {
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
    _sk: &Vec<BdabeSecretAttributeKey>,
) -> (G1, G2) {
    let mut ret: (G1, G2) = (G1::one(), G2::one());
    for _i in 0usize.._conjunction.len() {
        match _sk
            .into_iter()
            .find(|&x| x._str == _conjunction[_i].to_string())
        {
            None => {}
            Some(_found) => {
                if _i == 0 {
                    ret = (_found._au1, _found._au2);
                } else {
                    ret = (ret.0 + _found._au1, ret.1 + _found._au2);
                }
            }
        }
    }
    ret
}

/// BDABE Scheme helper function: from_authority
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
    fn and() {
        // setup scheme
        let (_pk, _msk) = setup();
        // authority1
        let _a1_key = authgen(&_pk, &_msk, &String::from("aa1"));
        // authority2
        let _a2_key = authgen(&_pk, &_msk, &String::from("aa2"));
        // our attributes
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = keygen(&_pk, &_a1_key, &String::from("u1"));
        let _att1 = String::from("aa1::A");
        let _att2 = String::from("aa2::B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a1_key, &_att1).unwrap());
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a2_key, &_att2).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(r#"{"name": "and", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}"#);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn or() {
        // setup scheme
        let (_pk, _msk) = setup();
        // authority1
        let _a1_key = authgen(&_pk, &_msk, &String::from("aa1"));
        // authority2
        let _a2_key = authgen(&_pk, &_msk, &String::from("aa2"));
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = keygen(&_pk, &_a2_key, &String::from("u1"));
        // our attributes
        let _att1 = String::from("aa1::C");
        let _att2 = String::from("aa2::B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a1_key, &_att1).unwrap());
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a2_key, &_att2).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(r#"{"name": "or", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}"#);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn or_and() {
        // setup scheme
        let (_pk, _msk) = setup();
        // authority1
        let _a1_key = authgen(&_pk, &_msk, &String::from("aa1"));
        // authority2
        let _a2_key = authgen(&_pk, &_msk, &String::from("aa2"));
        // authority2
        let _a3_key = authgen(&_pk, &_msk, &String::from("aa3"));
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = keygen(&_pk, &_a2_key, &String::from("u1"));
        // our attributes
        let _att1 = String::from("aa1::A");
        let _att2 = String::from("aa2::B");
        let _att3 = String::from("aa3::C");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // authority3 owns C
        let _att2_pk = request_attribute_pk(&_pk, &_a3_key, &_att3).unwrap();
        // add attribute sk's to user key
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a1_key, &_att1).unwrap());
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a2_key, &_att2).unwrap());
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a3_key, &_att3).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(
            r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "aa3::C"}, {"name": "aa2::B"}]}, {"name": "aa1::X"}]}"#,
        );
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }

    #[test]
    fn not() {
        // setup scheme
        let (_pk, _msk) = setup();
        // authority1
        let _a1_key = authgen(&_pk, &_msk, &String::from("aa1"));
        // authority2
        let _a2_key = authgen(&_pk, &_msk, &String::from("aa2"));
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = keygen(&_pk, &_a2_key, &String::from("u1"));
        // our attributes
        let _att1 = String::from("aa1::A");
        let _att2 = String::from("aa2::B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a1_key, &_att1).unwrap());
        _u_key
            ._ska
            .push(request_attribute_sk(&_u_key._pk, &_a2_key, &_att2).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(r#"{"name": "or", "children": [{"name": "aa1::B"}, {"name": "aa2::A"}]}"#);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&_pk, &_u_key, &_ct);
        assert_eq!(_match.is_ok(), false);
    }

}
