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

use rand::{Rng, RngCore, thread_rng};
use utils::policy::pest::{PolicyLanguage, parse};
use crate::error::RabeError;
use nalgebra::Matrix3;
use utils::aes::{encrypt_symmetric, decrypt_symmetric};
use std::convert::TryInto;
use std::ops::{Add, Mul, MulAssign};
use bit_vec::BitVec;
use eax::aead::Key;
use gmorph::{Enc, Encrypt, KeyPair};
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
use num_bigint::{BigUint, RandBigInt};
use rabe_bn::Fr;
use utils::secretsharing::numeric::{calc_coefficients, calc_pruned, gen_shares_policy};

const PRECALC: u32 = 4;
const DIGITS: u32 = 9;
const PHI: u32 = 10u32.pow(DIGITS) / 2 - 1;

/// (PK)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabePublicKey {
    pub zero: Vec<Enc>,
    pub one: Vec<Enc>,
    pub base: [Enc; 4],
    pub attributes: Vec<LabeAttributePublic>
}

/// (MSK)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeMasterKey {
    pub key_pair: KeyPair,
    pub secret_base: [u32; 4]
}

/// A LSW Secret User Key (SK)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeSecretKey {
    pub policy: (String, PolicyLanguage),
    pub parts: Vec<LabeAttributePublic>
}
impl Default for LabeSecretKey {
    fn default() -> Self {
        LabeSecretKey {
            policy: ("".to_string(), PolicyLanguage::HumanPolicy),
            parts: vec![]
        }
    }
}
/// A LSW Ciphertext (CT)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeCiphertext {
    pub data: Vec<u8>,
    pub attributes: Vec<LabeAttributePublic>
}

/// A LSW Master Key (MSK)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct LabeAttributePublic {
    pub name: String,
    pub value: [Enc; 4],
}
impl LabeAttributePublic {
    pub fn new(
        key_pair: &KeyPair,
        secret: &LabeAttributeSecret,
    ) -> LabeAttributePublic {
        LabeAttributePublic {
            name: secret.name.clone(),
            value: [
                    Enc::encrypt(&key_pair, secret.value[0]),
                    Enc::encrypt(&key_pair, secret.value[1]),
                    Enc::encrypt(&key_pair, secret.value[2]),
                    Enc::encrypt(&key_pair, secret.value[3])
                ]
        }
    }
    pub fn encrypted(name: &String, value: [Enc; 4]) -> LabeAttributePublic {
        LabeAttributePublic {
            name: name.to_string(),
            value
        }
    }
}
/// (Attribute secret)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeAttributeSecret {
    pub name: String,
    pub value: [u32; 4],
}
/// (Attribute Enum)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct LabeAttributePair {
    secret: LabeAttributeSecret,
    public: LabeAttributePublic,
}

/// (Attribute Enum)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub enum LabeAttribute {
    SecretKey(LabeAttributeSecret),
    PublicKey(LabeAttributePublic),
}

impl LabeMasterKey {
    pub fn new(key_pair: KeyPair, secret_base: [u32; 4]) -> LabeMasterKey {
        LabeMasterKey {
            key_pair,
            secret_base
        }
    }
}

impl LabePublicKey {
    pub fn new(attributes: Vec<LabeAttributePublic>, key_pair: &KeyPair, secret_base: &[u32; 4]) -> LabePublicKey {
        LabePublicKey {
            zero: (0..PRECALC)
                .into_iter()
                .map(|_| Enc::encrypt(key_pair, 0))
                .collect(),
            one: (0..PRECALC)
                .into_iter()
                .map(|_| Enc::encrypt(key_pair, 1))
                .collect(),
            base: [
                Enc::encrypt(key_pair, secret_base[0]),
                Enc::encrypt(key_pair, secret_base[1]),
                Enc::encrypt(key_pair, secret_base[2]),
                Enc::encrypt(key_pair, secret_base[3])
            ],
            attributes,
        }
    }
    pub fn get_one(&self) -> &Enc {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.one.choose(&mut rng).unwrap()
    }
    pub fn get_zero(&self) -> &Enc {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.zero.choose(&mut rng).unwrap()
    }
    pub fn get_attribute(&self, attribute: &String) -> Option<LabeAttributePublic> {
        match self.attributes.iter().filter(|obj| &obj.name == attribute).nth(0) {
            Some(attr) => Some(attr.clone()),
            None => None
        }
    }
    pub fn double_and_add(&self, factors: &Vec<u32>) -> Vec<Enc> {
        use bit_vec::BitVec;
        assert_eq!(factors.len(), 4);
        let mut ret = vec![];
        for factor in factors.into_iter() {
            let mut blinding = self.get_zero().clone();
            println!("current: {:?}", factor);
            for c in BitVec::from_bytes(&factor.to_be_bytes()) {
                blinding = blinding.add(blinding);
                if c { blinding = blinding.add(self.get_one().clone()) }
            }
            ret.push(blinding)
        }
        ret
    }
    pub fn attribute_blinding(
        &self,
        attribute: &String,
        factor: &[Enc]
    ) -> Option<LabeAttributePublic> {
        match self.get_attribute(attribute) {
            Some (attr_pk) => {
                Some(LabeAttributePublic {
                    name: attr_pk.name,
                    value: [
                        attr_pk.value[0] + factor[0],
                        attr_pk.value[1] + factor[1],
                        attr_pk.value[2] + factor[2],
                        attr_pk.value[3] + factor[3]
                    ]
                })
            },
            None => None
        }
    }
}

impl LabeSecretKey {
    pub fn get_private(&self, attribute: &String) -> Result<[Enc; 4], RabeError> {
        self.parts
            .clone()
            .into_iter()
            .filter(|a| a.name.as_str() == attribute)
            .map(|a| a.value )
            .nth(0)
            .ok_or(RabeError::new(&format!("no private key found for {}", attribute)))
    }
}

impl LabeCiphertext {
    pub fn get_public(&self, attribute: &String) -> Result<&[Enc; 4], RabeError> {
        self.attributes
            .iter()
            .filter_map(|pk| if pk.name.eq(attribute) { Some(&pk.value) } else { None })
            .nth(0)
            .ok_or(RabeError::new(&format!("no public key found for {}", attribute)))
    }
    pub fn get_attributes(&self) -> Vec<String> {
        self.attributes
            .iter()
            .map(|obj| obj.name.to_string() )
            .collect()
    }
}

impl LabeAttributeSecret {
    pub fn new(name: String, value: [u32; 4]) -> LabeAttributeSecret {
        LabeAttributeSecret {
            name,
            value
        }
    }
    pub fn derive_from(name: String, secret_base: [u32; 4]) -> LabeAttributeSecret {
        LabeAttributeSecret {
            name: name.to_string(),
            value: hash_to_smallnum(name.to_string(), secret_base)
        }
    }
}
// Hash 'string' to a small number (i.e. u32)
pub(crate) fn hash_to_smallnum(input: String, secret_base: [u32; 4]) -> [u32; 4] {
    let mut n1: u32 = 0;
    let mut n2: u32 = 0;
    let mut n3: u32 = 0;
    let mut n4: u32 = 0;
    for ch in input.chars() {
        let temp1 = secret_base[0].wrapping_mul(u32::from(ch));
        let temp2 = secret_base[1].wrapping_mul(u32::from(ch));
        let temp3 = secret_base[2].wrapping_mul(u32::from(ch));
        let temp4 = secret_base[3].wrapping_mul(u32::from(ch));
        n1 = n1.wrapping_add(temp1);
        n2 = n2.wrapping_add(temp2);
        n3 = n3.wrapping_add(temp3);
        n4 = n4.wrapping_add(temp4);
    }
    [n1, n2, n3, n4]
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
    let key_pair = KeyPair::new();
    let secret_base: [u32; 4] = rand::thread_rng().gen();
    let attr = derive_attributes(&key_pair, secret_base, attributes);
    let msk = LabeMasterKey::new(key_pair, secret_base);
    (
        LabePublicKey::new(attr.0, &msk.key_pair, &msk.secret_base),
        msk

    )
}
/// The keygen algorithm of LABE
pub fn keygen(
    msk: &LabeMasterKey,
    policy: &String,
    language: PolicyLanguage
) -> Result<LabeSecretKey, RabeError> {
    match parse(policy, language) {
        Ok(pol) => {
            Ok(
                LabeSecretKey {
                    policy: (policy.to_string(), language),
                    parts: match gen_shares_policy(msk.secret_base, &pol, None) {
                        Some(shares) => shares.into_iter().map(|share| {
                            let encrypted_share: [Enc; 4] = [
                                Enc::encrypt(&msk.key_pair, share.1[0]),
                                Enc::encrypt(&msk.key_pair, share.1[1]),
                                Enc::encrypt(&msk.key_pair, share.1[2]),
                                Enc::encrypt(&msk.key_pair, share.1[3])
                            ];
                            LabeAttributePublic::encrypted(&share.0, encrypted_share)
                        } ).collect(),
                        None => panic!("cloud not generate shares !")
                    }
                }
            )
        },
        Err(e) => Err(e)
    }
}

pub fn encrypt(
    pk: &LabePublicKey,
    attributes: &mut Vec<String>,
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
        let mut blinded: Vec<LabeAttributePublic> = Vec::new();
        let mut rng = rand::thread_rng();
        let mut secret: Vec<u32> = (0..4).into_iter().map(|_| rng.gen()).collect();
        println!("secret {:?}", &secret);
        let mut encrypted_secrets: Vec<Enc> = pk.double_and_add(&secret);
        attributes.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
        for (i, attr) in attributes.into_iter().enumerate() {
            match pk.attribute_blinding(attr, encrypted_secrets.iter().enumerate().map(|item| item.1.clone()+pk.base[item.0]).collect::<Vec<Enc>>().as_slice()) {
                Some(apk) => {
                    blinded.push(apk);
                },
                None => panic!("attribute {} not found in public key!", attr)
            }
        }
        match encrypt_symmetric("".to_string(),  &plaintext.to_vec()) {
            Ok(ct) => Ok(LabeCiphertext {
                data: ct,
                attributes: blinded
            }),
            Err(e) => Err(e),
        }
    }
}

pub fn decrypt(
    sk: &LabeSecretKey,
    pk: &LabePublicKey,
    ct: &LabeCiphertext
) -> Result<Vec<u8>, RabeError> {
    let _attrs_str = ct.get_attributes();
    match parse(sk.policy.0.as_ref(), sk.policy.1) {
        Ok(pol) => {
            return match calc_pruned(&_attrs_str, &pol, None) {
                Ok((_match, _list)) => {
                    if _match {
                        let mut _prod_t = vec![0u32, 0u32, 0u32, 0u32];
                        let _coeffs: Vec<(String, i32)> = calc_coefficients(&pol, 1, None).unwrap();
                        println!("coeffs: {:?}", &_coeffs);
                        for _attr in _list.into_iter() {
                            match ct.get_public(&_attr) {
                                Ok(z) => {
                                    let sk_attr = sk.get_private(&_attr).unwrap();
                                    println!("sk_attr: {:?}", &sk_attr);

                                },
                                Err(e) => panic!("Attribute {} not found: {}", &_attr, e.to_string())
                            }
                        }
                        //println!("decrypt: _s {}", _prod_t);
                        decrypt_symmetric("_prod_t".to_string().as_bytes(), &ct.data)
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
    key_pair: &KeyPair,
    secret_base: [u32; 4],
    attributes: Vec<String>,
) -> (Vec<LabeAttributePublic>, Vec<LabeAttributeSecret>) {
    let mut pubk: Vec<LabeAttributePublic> = vec![];
    let mut seck: Vec<LabeAttributeSecret> = vec![];
    for current in attributes {
        let secret = LabeAttributeSecret::derive_from(current, secret_base);
        pubk.push(LabeAttributePublic::new(key_pair, &secret));
        seck.push(secret);
    }
    (pubk, seck)
}

#[cfg(test)]
mod tests {
    use bit_vec::BitVec;
    use gmorph::Decrypt;
    use num_bigint::RandBigInt;
    use super::*;

    fn setup_test() -> (LabePublicKey, LabeMasterKey) {
        // a set of attributes
        let mut attributes: Vec<String> = Vec::new();
        attributes.push(String::from("A"));
        attributes.push(String::from("B"));
        attributes.push(String::from("C"));
        // setup scheme
        setup(attributes.clone())
    }

    #[test]
    fn blinding_factor_test() {
        let (pk, msk) = setup_test();
        let mut rng = rand::thread_rng();
        let secret: Vec<u32> = vec![rng.gen(), rng.gen(), rng.gen(), rng.gen()];
        let blinds = pk.double_and_add(&secret);
        let mut bits_pt: Vec<u32> = vec![];
        for blind in blinds {
            bits_pt.push(blind.decrypt(&msk.key_pair));
        }
        assert_eq!(bits_pt, bits_pt)
    }
    #[test]
    fn test_setup() {
        let (pk, msk) = setup_test();
        let mut attributes: Vec<String> = Vec::new();
        attributes.push(String::from("A"));
        attributes.push(String::from("C"));
        let sk1= keygen(&msk, &String::from(r#"("A" and "B") or ("A" and "C")"#), PolicyLanguage::HumanPolicy).unwrap_or_default();
        println!("msk: {}", &serde_json::to_string(&msk).unwrap());
        println!("pk: {}", &serde_json::to_string(&pk).unwrap());
        println!("sk: {}", &serde_json::to_string(&sk1).unwrap());
        let ct= encrypt(&pk, &mut attributes, String::from("griaseng").as_bytes()).unwrap();
        let pt= decrypt(&sk1, &pk, &ct);
        println!("ct: {}", &serde_json::to_string(&ct).unwrap());
        println!("pt: {}", &serde_json::to_string(&pt).unwrap());
    }
}

