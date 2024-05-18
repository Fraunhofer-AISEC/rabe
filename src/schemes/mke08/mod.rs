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
//! use rabe::schemes::bdabe::BdabePublicAttributeKey;
//! use rabe::schemes::mke08::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//! let (_pk, _msk) = setup();
//! let mut sk = keygen(&_pk, &_msk, "user1");
//! let _att1 = "aa1::A";
//! let _att2 = "aa2::B";
//! let _a1_key = authgen("aa1");
//! let _a2_key = authgen("aa2");
//! let _att1_pk = request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
//! let _att2_pk = request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
//! sk.sk_a.push(request_authority_sk(&sk.pk, &_att1, &_a1_key).unwrap());
//! sk.sk_a.push(request_authority_sk(&sk.pk, &_att2, &_a2_key).unwrap());
//! let plaintext = String::from("our plaintext!").into_bytes();
//! let policy = String::from(r#""aa1::A" and "aa2::B""#);
//! let attr_vec: Vec<&Mke08PublicAttributeKey> = vec!(&_att1_pk, &_att2_pk);
//! let _ct: Mke08Ciphertext = encrypt(&_pk, &attr_vec.as_slice(), &policy, PolicyLanguage::HumanPolicy, &plaintext).unwrap();
//! assert_eq!(decrypt(&sk, &_ct).unwrap(), plaintext);
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
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// A MKE08 Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08PublicKey {
    pub g1: G1,
    pub g2: G2,
    pub p1: G1,
    pub p2: G2,
    pub e_gg_y1: Gt,
    pub e_gg_y2: Gt,
}

/// A MKE08 Master Key (MK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08MasterKey {
    pub g1: G1,
    pub g2: G2,
}

/// A MKE08 User Key (SK), consisting of a Secret User Key (SKu), a Public User Key (PKu) and a Vector of Secret Attribute Keys (SKau)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08UserKey {
    pub sk: Mke08SecretUserKey,
    pub pk: Mke08PublicUserKey,
    pub sk_a: Vec<Mke08SecretAttributeKey>,
}

/// A MKE08 Public User Key (PKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08PublicUserKey {
    pub name: String,
    pub g1: G1,
    pub g2: G2,
}

/// A MKE08 Secret User Key (SKu)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08SecretUserKey {
    pub g1: G1,
    pub g2: G2,
}

/// A MKE08 Secret Authrotiy Key (SKauth)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08SecretAuthorityKey {
    pub name: String,
    pub r: Fr,
}

/// A MKE08 Public Attribute Key (PKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08PublicAttributeKey {
    pub attr: String,
    pub g1: G1,
    pub g2: G2,
    pub gt1: Gt,
    pub gt2: Gt,
}

/// A MKE08 Secret Attribute Key (SKa)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08SecretAttributeKey {
    pub attr: String,
    pub g1: G1,
    pub g2: G2,
}

/// A MKE08 Ciphertext (CT) consisting of the AES encrypted data as well as a Vector of all Conjunctions of the access policy
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08Ciphertext {
    pub policy: (String, PolicyLanguage),
    pub e: Vec<Mke08CTConjunction>,
    pub ct: Vec<u8>,
}

/// A MKE08 Ciphertext Conjunction (CTcon)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mke08CTConjunction {
    pub str: Vec<String>,
    pub j1: Gt,
    pub j2: Gt,
    pub j3: G1,
    pub j4: G2,
    pub j5: G1,
    pub j6: G2,
}

/// The setup algorithm of MKE08. Generates a Mke08PublicKey and a Mke08PublicKey.
pub fn setup() -> (Mke08PublicKey, Mke08MasterKey) {
    // random number generator
    let mut rng = rand::thread_rng();
    let g1:G1 = rng.gen();
    let g2:G2 = rng.gen();
    let p1:G1 = rng.gen();
    let p2:G2 = rng.gen();
    let y1:Fr = rng.gen();
    let y2:Fr = rng.gen();
    let e_gg_y1 = pairing(g1, g2).pow(y1);
    let e_gg_y2 = pairing(g1, g2).pow(y2);
    let msk_g1 = g1 * y1;
    let msk_g2 = g2 * y2;
    // return PK and MK
    (
        Mke08PublicKey { g1, g2, p1, p2, e_gg_y1, e_gg_y2 },
        Mke08MasterKey { g1: msk_g1, g2: msk_g2 }
    )
}

/// The key generation algorithm of MKE08 CP-ABE. Generates a Mke08UserKey using a Mke08PublicKey, a Mke08MasterKey and a username given as String.
///
/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `msk` - A Master Key (MSK), generated by the function setup()
///	* `name` - A username given as String. Must be unique.
///
pub fn keygen(
    pk: &Mke08PublicKey,
    msk: &Mke08MasterKey,
    name: &str
) -> Mke08UserKey {
    // random number generator
    let mut rng = rand::thread_rng();
    let mk_u:Fr = rng.gen();
    // return pk_u and sk_u
    return Mke08UserKey {
        sk: Mke08SecretUserKey {
            g1: msk.g1 + (pk.p1 * mk_u),
            g2: msk.g2 + (pk.p2 * mk_u),
        },
        pk: Mke08PublicUserKey {
            name: name.to_string(),
            g1: pk.g1 * mk_u,
            g2: pk.g2 * mk_u,
        },
        sk_a: Vec::new(),
    };
}

/// Sets up and generates a new Authority by creating a secret authority key (SKauth).
/// The key is created for an authority with a given "name".
///
/// # Arguments
///
///	* `name` - The name of the authority the key is associated with. Must be unique.
///
pub fn authgen(
    name: &str
) -> Mke08SecretAuthorityKey {
    // return secret authority key
    return Mke08SecretAuthorityKey {
        name: name.to_string(),
        r: rand::thread_rng().gen(),
    };
}

/// Sets up and generates a public Attribute Key for an Authority, if the attribute belongs to this auhtority
///
/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `attribute` - The name of the attribute given as String.
///	* `sk_a` - A Secret Authority Key (SKauth), generated by the function authgen()
///
pub fn request_authority_pk(
    pk: &Mke08PublicKey,
    attribute: &str,
    sk_a: &Mke08SecretAuthorityKey,
) -> Result<Mke08PublicAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(attribute, &sk_a.name) {
        match sha3_hash_fr(attribute) {
            Ok(hash_1) => {
                match sha3_hash_fr(&sk_a.name) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * sk_a.r;
                        // return PK and mke
                        Ok(Mke08PublicAttributeKey {
                            attr: attribute.to_string(),
                            g1: pk.g1 * exp,
                            g2: pk.g2 * exp,
                            gt1: pk.e_gg_y1.pow(exp),
                            gt2: pk.e_gg_y2.pow(exp),
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

/// Sets up and generates a secret Attribute Key for a given user by an authorized authority, if the attribute belongs to this auhtority and the user is eligible to own the attribute.
///
/// # Arguments
///
///	* `pk_u` - A Public User Key (PKu), generated by the function keygen()
///	* `attribute` - The name of the attribute given as String.
///	* `sk_a` - A Secret Authority Key (SKauth), generated by the function authgen()
///
pub fn request_authority_sk(
    pk_u: &Mke08PublicUserKey,
    attr: &str,
    sk_a: &Mke08SecretAuthorityKey,
) -> Result<Mke08SecretAttributeKey, RabeError> {
    // if attribute a is from authority sk_a
    return if from_authority(attr, &sk_a.name) && is_eligible(attr, &pk_u.name) {
        match sha3_hash_fr(attr) {
            Ok(hash_1) => {
                match sha3_hash_fr(&sk_a.name) {
                    Ok(hash_2) => {
                        let exp = hash_1 * hash_2 * sk_a.r;
                        // return PK and mke
                        Ok(Mke08SecretAttributeKey {
                            attr: attr.to_string(),
                            g1: pk_u.g1 * exp,
                            g2: pk_u.g2 * exp,
                        })
                    },
                    Err(e) => Err(e)
                }
            },
            Err(e) => Err(e)
        }
    } else {
        Err(RabeError::new(&format!("attribute {} is not from_authority() or !is_eligible()", attr.to_string())))
    }
}

/// The encrypt algorithm of MKE08. Generates an Mke08Ciphertext using an Mke08PublicKey,
/// a Vector of Mke08PublicAttributeKeys, an access policy given as String as well as some plaintext data given as [u8].
///
/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `attr_pks` - A Vector of all Mke08PublicAttributeKey that are involded in the policy
///	* `policy` - An access policy given as JSON &str
///	* `plaintext` - plaintext data given as a Vector of u8
///
pub fn encrypt(
    pk: &Mke08PublicKey,
    attr_pks: &[&Mke08PublicAttributeKey],
    policy: &str,
    language: PolicyLanguage,
    plaintext: &[u8],
) -> Result<Mke08Ciphertext, RabeError> {
    match parse(policy, language) {
        Ok(pol) => {
            // if policy is in DNF
            return if policy_in_dnf(&pol, false, None) {
                // random number generator
                let mut rng = rand::thread_rng();
                // an DNF policy from the given String
                let policy_dnf = DnfPolicy::from_string(&policy, attr_pks, language).unwrap();
                // random Gt msgs
                let msg1 = pairing(rng.gen(), rng.gen());
                let msg2 = msg1.pow(rng.gen());
                let msg = msg1 * msg2;
                // CT result vectors
                let mut e: Vec<Mke08CTConjunction> = Vec::new();
                // now add randomness using _r_j
                for term in policy_dnf.terms.into_iter() {
                    let r_j: Fr = rng.gen();
                    e.push(Mke08CTConjunction {
                        str: term.0,
                        j1: term.1.pow(r_j) * msg1,
                        j2: term.2.pow(r_j) * msg2,
                        j3: pk.p1 * r_j,
                        j4: pk.p2 * r_j,
                        j5: term.3 * r_j,
                        j6: term.4 * r_j,
                    });
                }
                //Encrypt plaintext using derived key from secret
                match encrypt_symmetric(msg, &plaintext.to_vec()) {
                    Ok(ct) => Ok(Mke08Ciphertext { policy: (policy.to_string(), language), e, ct }),
                    Err(e) => Err(e)
                }
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
///	* `sk` - A Mke08UserKey (SK), generated by the function keygen()
///	* `ct` - A Mke08Ciphertext
///
pub fn decrypt(
    sk: &Mke08UserKey,
    ct: &Mke08Ciphertext
) -> Result<Vec<u8>, RabeError> {
    let attr_str = sk.sk_a
        .iter()
        .map(|triple| {
            let _a = triple.clone();
            _a.attr.to_string()
        })
        .collect::<Vec<_>>();
    match parse(ct.policy.0.as_ref(), ct.policy.1) {
        Ok(pol) => {
            return if traverse_policy(&attr_str, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in mke08/decrypt: attributes in sk do not match policy in ct."))
            } else {
                let mut msg = Gt::one();
                for (_i, _e_j) in ct.e.iter().enumerate() {
                    if is_satisfiable(&_e_j.str, &sk.sk_a) {
                        let _sk_sum = calc_satisfiable(&_e_j.str, &sk.sk_a);
                        msg = _e_j.j1 * _e_j.j2 * pairing(_e_j.j3, _sk_sum.1) *
                            pairing(_sk_sum.0, _e_j.j4) *
                            (pairing(_e_j.j5, sk.sk.g2) * pairing(sk.sk.g1, _e_j.j6))
                                .inverse();
                        break;
                    }
                }
                // Decrypt plaintext using derived secret from mke08 scheme
                decrypt_symmetric(msg, &ct.ct)
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
///	* `conjunction` - A Conjunction of attributes given as String Vector
///	* `sk` - A Vector of Mke08SecretAttributeKeys
///
fn is_satisfiable(
    conjunction: &Vec<String>,
    sk: &Vec<Mke08SecretAttributeKey>
) -> bool {
    let mut ret: bool = true;
    for _attr in conjunction {
        match sk.into_iter().find(|&x| x.attr == *_attr) {
            None => {
                ret = false;
                break;
            }
            Some(_attr_sk) => {}
        }
    }
    ret
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
    sk: &Vec<Mke08SecretAttributeKey>
) -> (G1, G2) {
    let mut ret: (G1, G2) = (G1::one(), G2::one());
    for _i in 0usize..conjunction.len() {
        match sk.into_iter().find(
            |&x| x.attr == conjunction[_i].to_string(),
        ) {
            None => {}
            Some(found) => {
                if _i == 0 {
                    ret = (found.g1, found.g2);
                } else {
                    ret = (ret.0 + found.g1, ret.1 + found.g2);
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
///	* `attr` - Name of the attribute given as String
///	* `authority` - Name of the auhtority given as String
///
#[allow(dead_code)]
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
#[allow(dead_code)]
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
        let (pk, msk) = setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut sk = keygen(&pk, &msk, "user1");
        // authority1
        let auth1 = authgen("auth1");
        // authority2
        let auth2 = authgen("auth2");
        // authority1 owns A
        let _att1_pk = request_authority_pk(&pk, "auth1::A", &auth1).unwrap();
        // authority2 owns B
        let _att2_pk = request_authority_pk(&pk, "auth2::B", &auth2).unwrap();
        // add attribute sk's to user key
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth1::A", &auth1).unwrap(),
        );
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth2::B", &auth2).unwrap(),
        );
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children": [{"name": "auth1::A"}, {"name": "auth2::B"}]}"#);
        let att_pk: Vec<&Mke08PublicAttributeKey> = vec![&_att1_pk, &_att2_pk];
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext = encrypt(&pk, &att_pk.as_slice(), &policy, PolicyLanguage::JsonPolicy, &plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&sk, &_ct);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);
    }

    #[test]
    fn or() {
        // setup scheme
        let (pk, msk) = setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut sk = keygen(&pk, &msk, "user1");
        // authority1
        let auth1 = authgen("auth1");
        // authority2
        let auth2 = authgen("auth2");
        // authority1 owns C
        let _att1_pk = request_authority_pk(&pk, "auth1::C", &auth1).unwrap();
        // authority2 owns B
        let _att2_pk = request_authority_pk(&pk, "auth2::B", &auth2).unwrap();
        // add attribute sk's to user key
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth1::C", &auth1).unwrap(),
        );
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth2::B", &auth2).unwrap(),
        );
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "auth1::A"}, {"name": "auth2::B"}]}"#);
        let att_pks: Vec<&Mke08PublicAttributeKey> = vec![&_att1_pk, &_att2_pk];
        // cp-abe ciphertext
        let ct: Mke08Ciphertext = encrypt(&pk, att_pks.as_slice(), &policy, PolicyLanguage::JsonPolicy, &plaintext)
            .unwrap();
        // and now decrypt again with mathcing sk
        let ct_decrypted = decrypt(&sk, &ct);
        assert_eq!(ct_decrypted.is_ok(), true);
        assert_eq!(ct_decrypted.unwrap(), plaintext);
    }

    #[test]
    fn or_and() {
        // setup scheme
        let (pk, msk) = setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut sk = keygen(&pk, &msk, "user1");
        // authority1
        let auth1 = authgen("auth1");
        // authority2
        let auth2 = authgen("auth2");
        // authority1 owns A
        let attr1_pk = request_authority_pk(&pk, "auth1::A", &auth1).unwrap();
        // authority2 owns B
        let attr2_pk = request_authority_pk(&pk, "auth2::B", &auth2).unwrap();
        let attr3_pk = request_authority_pk(&pk, "auth2::X", &auth2).unwrap();
        // add attribute sk's to user key
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth1::A", &auth1).unwrap(),
        );
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth2::B", &auth2, ).unwrap(),
        );
        sk.sk_a.push(
            request_authority_sk(&sk.pk, "auth2::X", &auth2, ).unwrap(),
        );
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(
            r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "auth1::A"}, {"name": "auth2::B"}]}, {"name": "auth2::X"}]}"#,
        );
        let attr_pks: Vec<&Mke08PublicAttributeKey> = vec![&attr1_pk, &attr2_pk, &attr3_pk];
        // cp-abe ciphertext
        let ct: Mke08Ciphertext = encrypt(
            &pk,
            &attr_pks.as_slice(),
            &policy,
            PolicyLanguage::JsonPolicy,
            &plaintext,
        ).unwrap();
        // and now decrypt again with mathcing sk
        let ct_decrypted = decrypt(&sk, &ct);
        assert_eq!(ct_decrypted.is_ok(), true);
        assert_eq!(ct_decrypted.unwrap(), plaintext);
    }
}
