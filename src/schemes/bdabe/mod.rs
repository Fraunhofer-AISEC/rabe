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
//! use rabe::schemes::bdabe::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//! let (pk, msk) = setup();
//! let auth1 = authgen(&pk, &msk, &String::from("auth1"));
//! let mut sk = keygen(&pk, &auth1, &String::from("u1"));
//! let attr_a_pk = request_attribute_pk(&pk, &auth1, "auth1::A").unwrap();
//! sk.sk_a.push(request_attribute_sk(&sk.pk, &auth1, "auth1::A").unwrap());
//! let plaintext = String::from("our plaintext!").into_bytes();
//! let policy = String::from(r#""auth1::A" or "auth1::B""#);
//! let ct: BdabeCiphertext = encrypt(&pk, &vec![&attr_a_pk], &policy, PolicyLanguage::HumanPolicy, &plaintext).unwrap();
//! let ct_decrypted = decrypt(&sk, &ct);
//! assert_eq!(ct_decrypted.is_ok(), true);
//! assert_eq!(ct_decrypted.unwrap(), plaintext);
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
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// A BDABE Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabePublicKey {
    pub g1: G1,
    pub g2: G2,
    pub p1: G1,
    pub p2: G2,
    pub e_gg_y: Gt,
}

/// A BDABE Master Key (MK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeMasterKey {
    pub y: Fr,
}

/// A BDABE User Key (PKu, SKu and SKa's)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeUserKey {
    pub sk: BdabeSecretUserKey,
    pub pk: BdabePublicUserKey,
    pub sk_a: Vec<BdabeSecretAttributeKey>,
}

/// A BDABE Public User Key (PKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabePublicUserKey {
    pub u: String,
    pub u1: G1,
    pub u2: G2,
}

/// A BDABE Secret User Key (SKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeSecretUserKey {
    pub u1: G1,
    pub u2: G2,
}

/// A BDABE Secret Attribute Key (SKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeSecretAttributeKey {
    pub attr: String,
    pub au1: G1,
    pub au2: G2,
}

/// A BDABE Public Attribute Key (PKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabePublicAttributeKey {
    pub attr: String,
    pub a1: G1,
    pub a2: G2,
    pub a3: Gt,
}

/// A BDABE Secret Authority Key (SKauth)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeSecretAuthorityKey {
    pub name: String,
    pub a1: G1,
    pub a2: G2,
    pub a3: Fr,
}

/// A Ciphertext Tuple representing a conjunction in a CT
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeCiphertextTuple {
    pub attr: Vec<String>,
    pub e1: Gt,
    pub e2: G1,
    pub e3: G2,
    pub e4: G1,
    pub e5: G2,
}

/// A BDABE Ciphertext (CT)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BdabeCiphertext {
    pub policy: (String, PolicyLanguage),
    pub j: Vec<BdabeCiphertextTuple>,
    pub ct: Vec<u8>,
}

/// The setup algorithm of BDABE. Generates a BdabePublicKey and a BdabeMasterKey.
pub fn setup() -> (BdabePublicKey, BdabeMasterKey) {
    // random number generator
    let mut rng = rand::thread_rng();
    let g1:G1 = rng.gen();
    let g2:G2 = rng.gen();
    let p1:G1 = rng.gen();
    let p2:G2 = rng.gen();
    let y:Fr = rng.gen();
    // return pk and mk
    (
        BdabePublicKey { g1, g2, p1, p2, e_gg_y: pairing(g1, g2).pow(y) },
        BdabeMasterKey { y }
    )
}

/// Sets up and generates a new Authority by creating a secret authority key (SKauth).
/// The key is created for an authority with a given "name".
///
/// # Arguments
///
///	* `pk` - A BdabePublicKey (PK), generated by setup()
///	* `mk` - A BdabeMasterKey (MK), generated by setup()
///	* `name` - The name of the authority the key is associated with. Must be unique.
///
pub fn authgen(
    pk: &BdabePublicKey,
    msk: &BdabeMasterKey,
    name: &str,
) -> BdabeSecretAuthorityKey {
    // random number generator
    let mut rng = rand::thread_rng();
    let _alpha: Fr = rng.gen();
    let _beta = msk.y - _alpha;
    let a1 = pk.g1 * _alpha;
    let a2 = pk.g2 * _beta;
    let a3:Fr = rng.gen();
    // return secret authority key
    BdabeSecretAuthorityKey { a1, a2, a3, name: name.to_string()}
}

/// Sets up and generates a new User by creating a secret user key (SK).
/// The key is created for an user with a given "name".
/// It consists of a BdabeSecretUserKey and a BdabePublicUserKey as well as
/// an empty vector of BdabeSecretAttributeKeys.
///
/// # Arguments
///
///	* `pk` - A BdabePublicKey (PK), generated by setup()
///	* `sk_a` - A BdabeSecretAuthorityKey (SKauth), associated with an authority and generated by authgen()
///	* `name` - The name of the user the key is associated with. Must be unique.
///
pub fn keygen(
    pk: &BdabePublicKey,
    sk_a: &BdabeSecretAuthorityKey,
    name: &str,
) -> BdabeUserKey {
    // random number generator
    let mut rng = rand::thread_rng();
    let r_u: Fr = rng.gen();
    // return pk_u and sk_u
    BdabeUserKey {
        sk: BdabeSecretUserKey {
            u1: sk_a.a1 + (pk.p1 * r_u),
            u2: sk_a.a2 + (pk.p2 * r_u),
        },
        pk: BdabePublicUserKey {
            u: name.to_string(),
            u1: pk.g1 * r_u,
            u2: pk.g2 * r_u,
        },
        sk_a: Vec::new(),
    }
}

/// Generates a new BdabePublicAttributeKey for a requested attribute, if it is handled by the authority _ska.
///
/// # Arguments
///
///	* `pk` - A BdabePublicKey (PK), generated by setup()
///	* `sk_a` - A BdabeSecretAuthorityKey (SKauth), associated with an authority and generated by authgen()
///	* `attribute` - The attribute value as String
///
pub fn request_attribute_pk(
    pk: &BdabePublicKey,
    sk_a: &BdabeSecretAuthorityKey,
    attribute: &str,
) -> Result<BdabePublicAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(attribute, &sk_a.name) {
        match sha3_hash_fr(attribute) {
            Ok(hash_1) => {
                match sha3_hash_fr(&sk_a.name) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * sk_a.a3;
                        // return PK and mke
                        Ok(BdabePublicAttributeKey {
                            attr: attribute.to_string(),
                            a1: pk.g1 * exp,
                            a2: pk.g2 * exp,
                            a3: pk.e_gg_y.pow(exp),
                        })
                    },
                    Err(e) => Err(e)
                }
            },
            Err(e) => Err(e)
        }
    } else {
        Err(RabeError::new(&format!("attribute {} is not from_authority() or !is_eligible()", attribute.to_string())))
    }
}

/// Generates a new BdabeSecretAttributeKey for a requested attribute, if it is handled by the authority _ska and user _pk_u is eligible to recieve it.
///
/// # Arguments
///
///	* `pk_u` - A BdabePublicUserKey (PK), generated by keygen()
///	* `sk_a` - A BdabeSecretAuthorityKey (SKauth), associated with an authority and generated by authgen()
///	* `attribute` - The attribute value as String
///
pub fn request_attribute_sk(
    pk_u: &BdabePublicUserKey,
    sk_a: &BdabeSecretAuthorityKey,
    attribute: &str,
) -> Result<BdabeSecretAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(attribute, &sk_a.name) && is_eligible(attribute, &pk_u.u) {
        match sha3_hash_fr(attribute) {
            Ok(hash_1) => {
                match sha3_hash_fr(&sk_a.name) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * sk_a.a3;
                        // return PK and mke
                        Ok(BdabeSecretAttributeKey {
                            attr: attribute.to_string(),
                            au1: pk_u.u1 * exp,
                            au2: pk_u.u2 * exp,
                        })
                    },
                    Err(e) => Err(e)
                }
            },
            Err(e) => Err(e)
        }
    } else {
        Err(RabeError::new(&format!("attribute {} is not from_authority() or !is_eligible()", attribute.to_string())))
    }
}

/// The encrypt algorithm of BDABE. Generates an BdabeCiphertext using an BdabePublicKey,
/// a Vector of BdabePublicAttributeKeys, an access policy given as String as well as some plaintext data given as [u8].
///
/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `attr_pks` - A Vector of all BdabePublicAttributeKeys that are involded in the policy
///	* `policy` - An access policy given as JSON String
///	* `plaintext` - plaintext data given as a Vector of u8
///
pub fn encrypt(
    pk: &BdabePublicKey,
    attr_pks: &[&BdabePublicAttributeKey],
    policy: &str,
    language: PolicyLanguage,
    plaintext: &[u8],
) -> Result<BdabeCiphertext, RabeError> {
    match parse(policy, language) {
        Ok(pol) => {
            // if policy is in DNF
            if policy_in_dnf(&pol, false, None) {
                // random number generator
                let mut rng = rand::thread_rng();
                // an DNF policy from the given String
                let dnf: dnf::DnfPolicy = dnf::DnfPolicy::from_string(policy, attr_pks, language).unwrap();
                // random Gt msg
                let _msg = pairing(rng.gen(), rng.gen());
                let mut j: Vec<BdabeCiphertextTuple> = Vec::new();
                // now add randomness using _r_j
                for _term in dnf.terms {
                    let _r_j: Fr = rng.gen();
                    j.push(BdabeCiphertextTuple {
                        attr: _term.0,
                        e1: _term.1.pow(_r_j) * _msg,
                        e2: pk.p1 * _r_j,
                        e3: pk.p2 * _r_j,
                        e4: _term.3 * _r_j,
                        e5: _term.4 * _r_j,
                    });
                }
                //Encrypt plaintext using derived key from secret
                match encrypt_symmetric(_msg, &plaintext.to_vec()) {
                    Ok(ct) => Ok(BdabeCiphertext { policy: (policy.to_string(), language), j, ct }),
                    Err(e) => Err(e)
                }
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
///	* `sk` - A BdabeUserKey (SK), generated by the function keygen()
///	* `ct` - A BdabeCiphertext Ciphertext
///
pub fn decrypt(
    sk: &BdabeUserKey,
    ct: &BdabeCiphertext
) -> Result<Vec<u8>, RabeError> {
    let str_attr = sk
        .sk_a
        .iter()
        .map(|v| v.attr.to_string())
        .collect::<Vec<_>>();
    match parse(ct.policy.0.as_ref(), ct.policy.1) {
        Ok(pol) => {
            if traverse_policy(&str_attr, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in bdabe/decrypt: attributes in sk do not match policy in ct."))
            } else {
                let mut msg = Gt::one();
                for (_i, _ct_j) in ct.j.iter().enumerate() {
                    if is_satisfiable(&_ct_j.attr, &sk.sk_a) {
                        let _sk_sum = calc_satisfiable(&_ct_j.attr, &sk.sk_a);
                        msg = _ct_j.e1
                            * pairing(_ct_j.e2, _sk_sum.1)
                            * pairing(_sk_sum.0, _ct_j.e3)
                            * (pairing(_ct_j.e4, sk.sk.u2) * pairing(sk.sk.u1, _ct_j.e5)).inverse();
                        break;
                    }
                }
                // Decrypt plaintext using derived secret from Bdabe scheme
                decrypt_symmetric(msg, &ct.ct)
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
///	* `conjunction` - A Conjunction of attributes given as String Vector
///	* `sk` - A Vector of Mke08SecretAttributeKeys
///
fn is_satisfiable(
    conjunction: &Vec<String>,
    sk: &Vec<BdabeSecretAttributeKey>
) -> bool {
    let mut _ret: bool = true;
    for _attr in conjunction {
        match sk.into_iter().find(|&x| x.attr == *_attr) {
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
///	* `conjunction` - A Conjunction of attributes given as String Vector
///	* `sk` - A Vector of Mke08SecretAttributeKeys
///
fn calc_satisfiable(
    conjunction: &Vec<String>,
    sk: &Vec<BdabeSecretAttributeKey>,
) -> (G1, G2) {
    let mut ret: (G1, G2) = (G1::one(), G2::one());
    for _i in 0usize..conjunction.len() {
        match sk
            .into_iter()
            .find(|&x| x.attr == conjunction[_i].to_string())
        {
            None => {}
            Some(_found) => {
                if _i == 0 {
                    ret = (_found.au1, _found.au2);
                } else {
                    ret = (ret.0 + _found.au1, ret.1 + _found.au2);
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
///	* `attr` - Name of the attribute given as String
///	* `authority` - Name of the auhtority given as String
///
fn from_authority(
    attr: &str,
    authority: &str
) -> bool {
    let v: Vec<_> = attr.match_indices("::").collect();
    if v.len() == 1 {
        return attr.get(0..v[0].0).unwrap().to_string() == authority.to_string();
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
fn is_eligible(
    _attr: &str,
    _user: &str
) -> bool {
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
        let mut sk = keygen(&_pk, &_a1_key, &String::from("u1"));
        let _att1 = String::from("aa1::A");
        let _att2 = String::from("aa2::B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a1_key, &_att1).unwrap());
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a2_key, &_att2).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}"#);
        let attr_pks: Vec<&BdabePublicAttributeKey> = vec!(&_att1_pk, &_att2_pk);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(
                &_pk,
                &attr_pks.as_slice(),
                &policy,
                PolicyLanguage::JsonPolicy,
                &_plaintext
            ).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&sk, &_ct);
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
        let mut sk = keygen(&_pk, &_a2_key, &String::from("u1"));
        // our attributes
        let _att1 = String::from("aa1::C");
        let _att2 = String::from("aa2::B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a1_key, &_att1).unwrap());
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a2_key, &_att2).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(r#"{"name": "or", "children": [{"name": "aa1::A"}, {"name": "aa2::B"}]}"#);
        let attr_pks: Vec<&BdabePublicAttributeKey> = vec!(&_att1_pk, &_att2_pk);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &attr_pks.as_slice(), &_policy, PolicyLanguage::JsonPolicy, &_plaintext).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&sk, &_ct);
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
        let mut sk = keygen(&_pk, &_a2_key, &String::from("u1"));
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
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a1_key, &_att1).unwrap());
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a2_key, &_att2).unwrap());
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a3_key, &_att3).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(
            r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "aa3::C"}, {"name": "aa2::B"}]}, {"name": "aa1::X"}]}"#,
        );
        let attr_pks: Vec<&BdabePublicAttributeKey> = vec!(&_att1_pk, &_att2_pk);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &attr_pks.as_slice(), &_policy,PolicyLanguage::JsonPolicy, &_plaintext).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&sk, &_ct);
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
        let mut sk = keygen(&_pk, &_a2_key, &String::from("u1"));
        // our attributes
        let _att1 = String::from("aa1::A");
        let _att2 = String::from("aa2::B");
        // authority1 owns A
        let _att1_pk = request_attribute_pk(&_pk, &_a1_key, &_att1).unwrap();
        // authority2 owns B
        let _att2_pk = request_attribute_pk(&_pk, &_a2_key, &_att2).unwrap();
        // add attribute sk's to user key
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a1_key, &_att1).unwrap());
        sk
            .sk_a
            .push(request_attribute_sk(&sk.pk, &_a2_key, &_att2).unwrap());
        // our plaintext
        let _plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let _policy = String::from(r#"{"name": "or", "children": [{"name": "aa1::B"}, {"name": "aa2::A"}]}"#);
        let attr_pks: Vec<&BdabePublicAttributeKey> = vec!(&_att1_pk, &_att2_pk);
        // cp-abe ciphertext
        let _ct: BdabeCiphertext =
            encrypt(&_pk, &attr_pks.as_slice(), &_policy, PolicyLanguage::JsonPolicy, &_plaintext).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&sk, &_ct);
        assert_eq!(_match.is_ok(), false);
    }

}
