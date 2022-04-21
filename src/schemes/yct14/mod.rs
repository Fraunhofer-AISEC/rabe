//! `YCT14` scheme by Xuanxia Yao, Zhi Chen, Ye Tian.
//!
//! * Developped by Xuanxia Yao, Zhi Chen, Ye Tian, "A lightweight attribute-based encryption scheme for the Internet of things"
//! * Published in: Future Generation Computer Systems
//! * Available From: <http://www.sciencedirect.com/science/article/pii/S0167739X14002039>
//! * Type: encryption (key-policy attribute-based)
//! * Setting: No pairing
//! * Authors: Georg Bramm
//! * Date:	01/2021
//!
//! WARNING !
//! The YCT14 scheme was broken in [1] and a 'fixed' version was again broken in [2].
//! Demonstration how the attack can be implemented in practice in https://www.blackhat.com/eu-21/briefings/schedule/index.html#practical-attacks-against-attribute-based-encryption-25058.
//! 
//! [1] https://ieeexplore.ieee.org/document/8651482
//! [2] https://ieeexplore.ieee.org/document/9291064
//!
//!
//!
//! # Examples
//!
//! ```
//! use rabe::schemes::yct14::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//! let (pk, msk) = setup(vec!["A".to_string(), "B".to_string(), "C".to_string()]);
//!let plaintext = String::from("our plaintext!").into_bytes();
//!let policy = String::from(r#""A" or "B""#);
//!let ct_kp: Yct14AbeCiphertext = encrypt(&pk, &vec!["A".to_string(), "B".to_string()], &plaintext).unwrap();
//!let sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
//!assert_eq!(decrypt(&sk, &ct_kp).unwrap(), plaintext);
//! ```
use rabe_bn::{Fr, Gt};
use utils::{
    secretsharing::{gen_shares_policy, calc_coefficients, calc_pruned},
    aes::*
};
use rand::Rng;
use utils::policy::pest::{PolicyLanguage, parse};
use crate::error::RabeError;
use std::ops::Mul;
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Yct14Attribute {
    name: String,
    #[cfg_attr(feature = "borsh", borsh_skip)]
    #[cfg_attr(not(feature = "borsh"), serde(skip_serializing_if = "Option::is_none"))]
    node: Option<Yct14Type>,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub enum Yct14Type {
    Public(Gt),
    Private(Fr),
}

impl Yct14Type {
    pub fn public(&self) -> Result<Gt, RabeError> {
        match self {
            Yct14Type::Public(g) => Ok(g.clone()),
            _ => Err(RabeError::new("no public value (Gt) found"))
        }
    }
    pub fn  private(&self) -> Result<Fr, RabeError> {
        match self {
            Yct14Type::Private(fr) => Ok(fr.clone()),
            _ => Err(RabeError::new("no private value (Fr) found"))
        }
    }
}

impl Yct14Attribute {
    pub fn new(name: String, g: Gt) -> (Yct14Attribute, Yct14Attribute) {
        // random fr
        let si: Fr = rand::thread_rng().gen();
        (
            // public attribute part
            Yct14Attribute {
                name: name.clone(),
                node: Some(Yct14Type::Public(g.pow(si))),
            },
            //private attribute part
            Yct14Attribute {
                name,
                node: Some(Yct14Type::Private(si)),
            }
        )
    }
    pub fn private_from(input: (String, Fr), msk: &Yct14AbeMasterKey) -> Result<Yct14Attribute, RabeError> {
        match msk.get_private(&input.0) {
            Ok(si) => Ok(
                Yct14Attribute {
                    name: input.0,
                    node: Some(
                        Yct14Type::Private(
                            input.1.mul(si.inverse().unwrap())
                        )
                    )
                }
            ),
            Err(e) => Err(e)
        }

    }
    pub fn public_from(name: &String, pk: &Yct14AbePublicKey, k: Fr) -> Yct14Attribute {
        Yct14Attribute {
            name: name.to_string(),
            node: pk.attributes
                .clone()
                .into_iter()
                .filter(|attribute| attribute.name.as_str() == name)
                .map(|attribute| match attribute.node {
                    Some(node) => {
                        match node {
                            Yct14Type::Public(public) => {
                                Some(Yct14Type::Public(public.pow(k)))
                            },
                            _ => panic!("attribute {} has no public node value", attribute.name),
                        }
                    },
                    None => panic!("attribute {} has no public node", attribute.name),
                })
                .nth(0)
                .unwrap()
        }
    }
}

/// A Public Key (PK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Yct14AbePublicKey {
    g: Gt,
    attributes: Vec<Yct14Attribute>
}

/// A Master Key (MSK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Yct14AbeMasterKey {
    s: Fr,
    attributes: Vec<Yct14Attribute>
}

impl Yct14AbeMasterKey {
    pub fn get_private(&self, attribute: &String) -> Result<Fr, RabeError> {
        let res: Option<Fr> = self.attributes
            .clone()
            .into_iter()
            .filter(|a| a.name.as_str() == attribute && a.node.is_some())
            .map(|a| match a.node.unwrap().private() {
                Ok(node_value) => node_value,
                Err(e) => panic!("no private node value: {}",e)
            } )
            .nth(0);
        res.ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
    }
}

/// A Secret User Key (SK)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Yct14AbeSecretKey {
    policy: (String, PolicyLanguage),
    du: Vec<Yct14Attribute>,
}

impl Yct14AbeSecretKey {
    pub fn get_private(&self, attribute: &String) -> Result<Fr, RabeError> {
        let res: Option<Fr> = self.du
            .clone()
            .into_iter()
            .filter(|a| a.name.as_str() == attribute)
            .map(|a| match a.node.unwrap().private() {
                Ok(node_value) => node_value,
                Err(e) => panic!("no private node value: {}",e)
            } )
            .nth(0);
        res.ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
    }
}

/// A Ciphertext (CT)
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct Yct14AbeCiphertext {
    attributes: Vec<Yct14Attribute>,
    ct: Vec<u8>,
}

impl Yct14AbeCiphertext {
    pub fn get_public(&self, attribute: &String) -> Result<Gt, RabeError> {
        let res: Option<Gt> = self.attributes
            .clone()
            .into_iter()
            .filter(|a| a.name.as_str() == attribute)
            .map(|a| match a.node.unwrap().public() {
                Ok(node_value) => node_value,
                Err(e) => panic!("no public node value: {}",e)
            } )
            .nth(0);
        res.ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
    }
}

/// The setup algorithm of KP-ABE. Generates a new Yct14AbePublicKey and a new Yct14AbeMasterKey.
pub fn setup(attribute_keys: Vec<String>) -> (Yct14AbePublicKey, Yct14AbeMasterKey) {
    // random number generator
    let mut _rng = rand::thread_rng();
    // attribute vec
    let mut private: Vec<Yct14Attribute> = Vec::new();
    let mut public: Vec<Yct14Attribute> = Vec::new();
    // generate random values
    let s: Fr = _rng.gen();
    let g: Gt = _rng.gen();
    // generate randomized attributes
    for attribute in attribute_keys {
        let attribute_pair = Yct14Attribute::new(attribute, g);
        public.push(attribute_pair.0);
        private.push(attribute_pair.1);
    }
    return (
        Yct14AbePublicKey {
            g: g.pow(s),
            attributes: public
        },
        Yct14AbeMasterKey {
            s,
            attributes: private
        }
    );
}

/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_msk` - A Master Key (MSK), generated by the function setup()
///	* `_policy` - An access policy given as PolicyLanguage
///
pub fn keygen(
    _pk: &Yct14AbePublicKey,
    _msk: &Yct14AbeMasterKey,
    _policy: &String,
    _language: PolicyLanguage,
) -> Result<Yct14AbeSecretKey, RabeError> {
    match parse(_policy, _language) {
        Ok(pol) => {
            let mut du: Vec<Yct14Attribute> = Vec::new();
            match gen_shares_policy(_msk.s, &pol, None) {
                Some(shares) => {
                    for share in shares.into_iter() {
                        //println!("share {}", serde_json::to_string(&share.clone()).unwrap());
                        match Yct14Attribute::private_from(share, _msk) {
                            Ok(attribute) => du.push(attribute),
                            Err(e) => {
                                println!("Yct14Attribute::Private_from : {} ", e);
                            }
                        }
                    }
                    Ok(Yct14AbeSecretKey {
                        policy: (_policy.clone(), _language),
                        du
                    })
                },
                None => Err(RabeError::new("could not generate shares during keygen()"))
            }
        },
        Err(e) => Err(e)
    }
}

/// # Arguments
///
///	* `pk` - A Public Key (PK), generated by the function setup()
///	* `_attributes` - A set of attributes given as String Vector
///	* `_plaintext` - plaintext data given as a vec<u8>
///
pub fn encrypt(
    pk: &Yct14AbePublicKey,
    _attributes: &Vec<String>,
    _plaintext: &[u8],
) -> Result<Yct14AbeCiphertext, RabeError> {
    if _attributes.is_empty() {
        return Err(RabeError::new("attributes empty"));
    } 
    else if _plaintext.is_empty() {
        return Err(RabeError::new("plaintext empty"));
    }
    else {
        // attribute vector
        let mut attributes: Vec<Yct14Attribute> = Vec::new();
        // random secret
        let k: Fr = rand::thread_rng().gen();
        // aes secret = public g ** random k
        let _cs: Gt = pk.g.pow(k);

        for attr in _attributes.into_iter() {
            attributes.push(Yct14Attribute::public_from(attr, pk, k));
        }
        //Encrypt plaintext using aes secret
        match encrypt_symmetric(_cs, &_plaintext.to_vec()) {
            Ok(ct) => Ok(Yct14AbeCiphertext { attributes, ct }),
            Err(e) => Err(e)
        }
    }
}

/// # Arguments
///
///	* `_sk` - A Secret Key (SK), generated by keygen()
///	* `_ct` - A Ciphertext (CT), generated by encrypt()
///
pub fn decrypt(_sk: &Yct14AbeSecretKey, _ct: &Yct14AbeCiphertext) -> Result<Vec<u8>, RabeError> {
    let _attrs_str = _ct
        .attributes
        .iter()
        .map(|value| value.name.clone())
        .collect::<Vec<String>>();
    match parse(_sk.policy.0.as_ref(), _sk.policy.1) {
        Ok(pol) => {
            return match calc_pruned(&_attrs_str, &pol, None) {
                Err(e) => Err(e),
                Ok(_p) => {
                    let (_match, _list) = _p;
                    if _match {
                        let mut _prod_t = Gt::one();
                        let _coeffs: Vec<(String, Fr)> = calc_coefficients(&pol, Some(Fr::one()), None).unwrap();
                        for _attr in _list.into_iter() {
                            let z = _ct.get_public(&_attr).unwrap().pow(_sk.get_private(&_attr).unwrap());
                            let coeff = _coeffs
                                .clone()
                                .into_iter()
                                .filter(|a| a.0 == _attr)
                                .map(|a| a.1 )
                                .nth(0)
                                .unwrap();
                            _prod_t = _prod_t * z.pow(coeff);
                        }
                        decrypt_symmetric(_prod_t, &_ct.ct)
                    } else {
                        Err(RabeError::new("Error in decrypt: attributes do not match policy."))
                    }
                }
            }
        },
        Err(e)=> Err(e)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn or() {
        // a set of attributes
        let mut attributes: Vec<String> = Vec::new();
        attributes.push(String::from("A"));
        attributes.push(String::from("B"));
        attributes.push(String::from("C"));
        // setup scheme
        let (pk, msk) = setup(attributes.clone());
        //println!("pk attrs: {:?}", serde_json::to_string(&pk.attributes).unwrap());
        //println!("msk attrs: {:?}", serde_json::to_string(&msk.attributes).unwrap());
        // our plaintext
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "C"}]}"#);
        // kp-abe ciphertext
        let ct: Yct14AbeCiphertext = encrypt(&pk, &attributes, &plaintext).unwrap();
        //println!("ct: {:?}", serde_json::to_string(&ct).unwrap());
        // a kp-abe SK key
        let sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        //println!("sk: {:?}", serde_json::to_string(&sk).unwrap());
        // and now decrypt again with matching sk
        assert_eq!(decrypt(&sk, &ct).unwrap(), plaintext);
    }

}
