//! This is the documentation for the `Labe` scheme:
//!
//! * Developped by Bramm
//! * Unpublished
//! * Available from (not yet)
//! * Type: encryption (key-policy attribute-based)
//! * Setting: lattice based
//! * Authors: Georg Bramm
//! * Date:	12/2021
//!
//! # Examples
//!
//! ```
//! ```

use rand::Rng;
use utils::policy::pest::{PolicyLanguage, parse};
use RabeError;
use gmorph::*;
use bit_vec::BitVec;
use utils::secretsharing::numeric::{gen_shares_policy, calc_pruned, calc_coefficients, rand_mod, PRECALC, BORDER, PRECISION_FLOAT, PADDING, PRECISION_BIT, SECURITY_PARAMS_RLWE, SECURITY_PARAMS_LWE};
use utils::aes::{encrypt_symmetric, decrypt_symmetric};
use std::convert::TryInto;
use error::RabeError;
use utils::secretsharing::gen_shares_policy;

/// (PK)
#[derive(Debug, PartialEq)]
pub struct LabePublicKey {
    pub zero: Vec<Enc>,
    pub one: Vec<Enc>,
    pub attributes: Vec<LabeAttribute>
}

/// (MSK)
#[derive(Debug, PartialEq)]
pub struct LabeMasterKey {
    pub secret_key: KeyPair,
    pub secret_base: usize,
    pub attributes: Vec<LabeAttribute>,
}

/// A LSW Secret User Key (SK)
#[derive(PartialEq)]
pub struct LabeSecretKey {
    pub policy: (String, PolicyLanguage),
    pub d: Vec<LabeAttributeSecret>
}

/// A LSW Ciphertext (CT)
#[derive(Debug, PartialEq)]
pub struct LabeCiphertext {
    pub data: Vec<u8>,
    pub attributes: Vec<LabeAttribute>
}

/// An attribute Public Key (APK)
#[derive(Clone, Debug, PartialEq)]
pub struct LabeAttributePublic {
    pub name: String,
    pub value: Enc,
}

/// (Attribute secret)
#[derive(Debug, PartialEq)]
pub struct LabeAttributeSecret {
    pub name: String,
    pub key: usize,
}
/// (Attribute Enum)
#[derive(Debug, PartialEq)]
pub struct LabeAttributePair {
    secret: LabeAttributeSecret,
    public: LabeAttributePublic,
}

/// (Attribute Enum)
#[derive(Debug, PartialEq)]
pub enum LabeAttribute {
    SecretKey(LabeAttributeSecret),
    PublicKey(LabeAttributePublic),
}

impl LabeMasterKey {
    pub fn new(attributes: Vec<LabeAttribute>, secret_key: KeyPair) -> LabeMasterKey {
        LabeMasterKey {
            secret_key,
            secret_base: rand::thread_rng().gen(),
            attributes
        }
    }
}

impl LabePublicKey {
    pub fn new(attributes: Vec<LabeAttribute>, secret_key: &KeyPair) -> LabePublicKey {
        LabePublicKey {
            zero: (0..PRECALC)
                .into_iter()
                .map(|_| Enc::enc(secret_key, 0) )
                .collect(),
            one: (0..PRECALC)
                .into_iter()
                .map(|_| Enc::enc(secret_key, 1))
                .collect(),
            attributes
        }
    }
    pub fn get_one(&self) -> &Ciphertext {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.one.choose(&mut rng).unwrap()
    }
    pub fn get_zero(&self) -> &Ciphertext {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.zero.choose(&mut rng).unwrap()
    }
}

impl LabeSecretKey {
    pub fn get_private(&self, attribute: &String) -> Result<usize, RabeError> {
        self.d
            .iter()
            .filter(|a| a.name.as_str() == attribute)
            .map(|a| a.key )
            .nth(0)
            .ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
    }
}

impl LabeCiphertext {
    pub fn get_public(&self, attribute: &String) -> Result<&Ciphertext, RabeError> {
        self.attributes
            .iter()
            .filter_map(|val| match val {
                LabeAttribute::PublicKey(pk) => {
                    if pk.name.eq(attribute) {
                        Some(&pk.value)
                    }
                    else {
                        None
                    }
                },
                _ => None
            })
            .nth(0)
            .ok_or(RabeError::new(&format!("no public key found for {}", attribute)))
    }
}

impl LabeAttributePublic {
    pub fn new(
        secret_key: &KeyPair,
        secret_base: usize,
        secret: &LabeAttributeSecret,
    ) -> LabeAttributePublic{
        LabeAttributePublic {
            name: secret.name.clone(),
            value: Enc::enc(secret_key, secret.key + secret_base)
        }
    }

    pub fn from(
        name: &String,
        pk: &LabePublicKey,
        nonce: usize
    ) -> Result<LabeAttributePublic, RabeError> {
        use std::ops::Add;
        let mut ct: Ciphertext = pk.attributes
            .iter()
            .filter(|attr| match attr {
                LabeAttribute::PublicKey(pk) => &pk.name == name,
                _ => false,
            })
            .map(|attr| match attr {
                LabeAttribute::PublicKey(pka) => pka.clone().value,
                _ => panic!("nonce could not be added to attribute {}", name),
            })
            .nth(0)
            .expect("public attribute key not found");
        ct += nonce;
        Ok(LabeAttributePublic {
            name: name.to_string(),
            value: ct
        })
    }
}

impl LabeAttributeSecret {
    pub fn new(name: &String) -> LabeAttributeSecret{
        LabeAttributeSecret {
            name: name.to_string(),
            key: rand_mod()
        }
    }
    pub fn from(share: (String, usize)) -> LabeAttributeSecret {
        LabeAttributeSecret {
            name: share.0.to_string(),
            key: share.1
        }
    }
}

impl LabeAttributePair {
    pub fn new(secret: LabeAttributeSecret, public: LabeAttributePublic) -> LabeAttributePair {
        LabeAttributePair { secret, public }
    }
}

/// The setup algorithm of LABE. Generates a new LabePublicKey and a new LabeMasterKey.
pub fn setup(
    attributes: Vec<String>
) -> (LabePublicKey, LabeMasterKey) {
    let key = if !EncryptKey::keys_exist(&PARAMS.gen_prefix()) {
        println!("keys do not exist! generating now ...");
        let key = EncryptKey::new();
        key.save_to_files(&PARAMS.gen_prefix());
        key
    } else {
        println!("keys  do exist! loading now ...");
        EncryptKey::load_from_files(&PARAMS.gen_prefix())
    };
    let secret_base = rand_mod();
    let attr = derive_attributes(&key, secret_base, &attributes);
    (
        LabePublicKey::new(attr.0, &key),
        LabeMasterKey::new(attr.1, key)
    )
}

/// The keygen algorithm of LABE
pub fn keygen(
    msk: LabeMasterKey,
    policy: &String,
    language: PolicyLanguage
) -> Result<LabeSecretKey, RabeError> {
    match parse(policy, language) {
        Ok(pol) => {
            let mut key: LabeSecretKey = LabeSecretKey {
                policy: (policy.to_string(), language),
                d: vec![],
            };
            match gen_shares_policy(msk.secret_base, &pol, None) {
                Some(shares) => {
                    for share in shares.into_iter() {
                        key.d.push(LabeAttributeSecret::from(share))
                    }
                },
                None => panic!("could not generate shares during keygen()")
            }
            Ok(key)
        },
        Err(e) => Err(e)
    }
}

pub fn encrypt(
    pk: LabePublicKey,
    attributes: &Vec<String>,
    plaintext: &[u8],
) -> Result<LabeCiphertext, RabeError> {
    if attributes.is_empty() {
        Err(RabeError::new("attributes empty"))
    }
    else if plaintext.is_empty() {
        Err(RabeError::new("plaintext empty"))
    }
    else {
        // attribute vector
        let mut _ej: Vec<LabeAttribute> = Vec::new();
        let secret = rand_mod();
        for _attr in attributes.into_iter() {
            match LabeAttributePublic::from(_attr, &pk, secret) {
                Ok(pk_a) => {
                    _ej.push(LabeAttribute::PublicKey(pk_a));
                },
                Err(e) => panic!("could not derive public attribute {}: {}", &_attr, e.to_string())
            }
        }
        println!("encrypt: _s {}", secret);
        match encrypt_symmetric(&secret,  &plaintext.to_vec()) {
            Ok(ct) => Ok(LabeCiphertext {
                data: ct,
                attributes: _ej
            }),
            Err(e) => Err(e),
        }
    }
}

pub fn decrypt(
    sk: LabeSecretKey,
    ct: LabeCiphertext
) -> Result<Vec<u8>, RabeError> {
    let _attrs_str = ct
        .attributes
        .iter()
        .filter_map(|val| if let LabeAttribute::PublicKey(ref data) = *val {
            Some(data.name.to_string())
        } else {
            None
        })
        .collect::<Vec<String>>();
    match parse(sk.policy.0.as_ref(), sk.policy.1) {
        Ok(pol) => {
            return match calc_pruned(&_attrs_str, &pol, None) {
                Ok(_p) => {
                    let (_match, _list) = _p;
                    if _match {
                        let mut _prod_t = 1;
                        let _coeffs: Vec<(String, usize)> = calc_coefficients(&pol, Some(1), None).unwrap();
                        for _attr in _list.into_iter() {
                            match ct.get_public(&_attr) {
                                Ok(z) => {
                                    let sk_attr = sk.get_private(&_attr).unwrap();
                                    let coeff = _coeffs
                                        .clone()
                                        .into_iter()
                                        .filter(|a| a.0 == _attr)
                                        .map(|a| a.1 )
                                        .nth(0)
                                        .unwrap();
                                    _prod_t = _prod_t + coeff;
                                },
                                Err(e) => panic!("Attribute {} not found: {}", &_attr, e.to_string())
                            }
                        }
                        println!("decrypt: _s {}", _prod_t);
                        decrypt_symmetric(&_prod_t, &ct.data)
                    } else {
                        Err(RabeError::new("attributes do not match policy =("))
                    }
                },
                Err(e) => Err(e)
            }
        },
        Err(e)=> Err(e)
    }
}

fn derive_attributes(
    secret_key: &EncryptKey,
    secret_base: usize,
    attributes: &Vec<String>,
) -> (Vec<LabeAttribute>, Vec<LabeAttribute>) {
    let mut secrets: Vec<LabeAttribute> = vec![];
    let mut public: Vec<LabeAttribute> = vec![];
    for attr in attributes {
        let secret = LabeAttributeSecret::new(&attr);
        public.push(LabeAttribute::PublicKey(LabeAttributePublic::new(secret_key, secret_base, &secret)));
        secrets.push(LabeAttribute::SecretKey(secret));
    }
    (public, secrets)
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
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "C"}]}"#);
        // kp-abe ciphertext
        let ct = encrypt(pk, &attributes, &plaintext).unwrap();
        // a kp-abe SK key
        let sk = keygen(msk, &policy, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with matching sk
        assert_eq!(decrypt(sk, ct).unwrap(), plaintext);
    }


    #[test]
    fn setup_test() {
        // setup scheme
        let keypair = setup(vec!["A".to_string(), "B".to_string()]);
        assert_eq!(keypair.0.attributes.len() ,2)
    }
}
