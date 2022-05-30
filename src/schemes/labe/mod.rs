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
use gmorph::{Decrypt, Enc, Encrypt, KeyPair, algebra::Q231};
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
    pub attributes: Vec<LabeAttributePublic>,
}

/// (MSK)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeMasterKey {
    pub attributes: Vec<LabeAttributeSecret>,
    pub secret_base: [u32; 4],
    pub private: KeyPair,
}

/// A LSW Secret User Key (SK)
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeSecretKey {
    pub policy: (String, PolicyLanguage),
    pub parts: Vec<LabeAttributeSecret>,
    pub attributes: Vec<LabeAttributeSecret>,
    pub private: KeyPair,
}
impl LabeSecretKey {
    pub fn get_part(&self, name: &String) -> Option<LabeAttributeSecret> {
        self.parts.iter().filter(|i| &i.name == name).nth(0).cloned()
    }
    pub fn get_attribute(&self, name: &String) -> Option<LabeAttributeSecret> {
        self.attributes.iter().filter(|i| &i.name == name).nth(0).cloned()
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
#[derive(Debug, Clone)]
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
    pub fn new(attributes: Vec<LabeAttributeSecret>, private: &KeyPair, secret_base: [u32; 4]) -> LabeMasterKey {
        LabeMasterKey {
            private: private.clone(),
            attributes,
            secret_base
        }
    }
    pub fn get_attribute(&self, name: &String) -> Option<&LabeAttributeSecret> {
        self.attributes.iter().filter(|i| &i.name == name).nth(0)
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
            name: name.to_string(),
            value: hash_to_smallnum(name, value)
        }
    }
    pub fn derive_from(input: (String, [u32; 4])) -> LabeAttributeSecret {
        LabeAttributeSecret {
            name: input.0.to_string(),
            value: input.1
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
    //let secret_base: [u32; 4] = rand::thread_rng().gen();
    let secret_base: [u32; 4] = [4, 3, 2, 1];
    println!("pk.base {:?}", &secret_base);
    let attr = derive_attributes(&key_pair, secret_base, attributes);
    let msk = LabeMasterKey::new(attr.1, &key_pair, secret_base);
    (
        LabePublicKey::new(attr.0, &key_pair, &msk.secret_base),
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
            let parts: Vec<LabeAttributeSecret> = match gen_shares_policy(msk.secret_base, &pol, None) {
                Some(shares) => shares.into_iter().map(|share| {
                    let attr = msk.get_attribute(&share.0);
                    println!("share {} : {}", share.0.to_string(), &serde_json::to_string(&share.1).unwrap());
                    LabeAttributeSecret::derive_from(share)
                } ).collect(),
                None => panic!("cloud not generate shares !")
            };
            let attributes = parts.iter().map(|a| msk.get_attribute(&a.name).unwrap().clone()).collect();
            Ok(
                LabeSecretKey {
                    policy: (policy.to_string(), language),
                    parts,
                    private: msk.private.clone(),
                    attributes
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
        //let secret: Vec<u32> = (0..4).into_iter().map(|_| rng.gen()).collect();
        let secret = vec![u32::MAX/2-4, 5, u32::MAX/2-16, 5];
        println!("encryption secret {:?}", &secret);
        let encrypted_secrets: Vec<Enc> = pk.double_and_add(&secret);
        // secret = secret + base
        let shifted_secrets = encrypted_secrets.iter().enumerate().map(|item| item.1.clone().add(pk.base[item.0])).collect::<Vec<Enc>>();
        attributes.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
        for (i, attr) in attributes.into_iter().enumerate() {
            // attr = attr.secret + (secret + base)
            match pk.attribute_blinding(attr, shifted_secrets.as_slice()) {
                Some(apk) => blinded.push(apk),
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
    pk: &LabePublicKey,
    sk: &LabeSecretKey,
    ct: &LabeCiphertext
) -> Result<Vec<u8>, RabeError> {
    let _attrs_str = ct.get_attributes();
    match parse(sk.policy.0.as_ref(), sk.policy.1) {
        Ok(pol) => {
            return match calc_pruned(&_attrs_str, &pol, None) {
                Ok((_match, _list)) => {
                    if _match {
                        let _coeff: Vec<(String, i32)> = calc_coefficients(&pol, 1, None).unwrap();
                        let mut _secret = [0i32, 0i32, 0i32, 0i32];
                        for (i, val) in sk.parts.iter().enumerate() {
                            for j in 0..4 {
                                let term = _coeff[i].1.wrapping_mul(val.value[j] as i32);
                                _secret[j] = _secret[j].wrapping_add(term);
                            }
                        }
                        let _secret = _secret.map(|i| i.wrapping_div(_list.len() as i32));
                        let _attrs_dec = ct.attributes
                            .iter()
                            .map(|a| {
                                a
                                    .value
                                    .iter()
                                    .map(|val| (a.name.to_string(), val.decrypt(&sk.private) ))
                                    .collect::<Vec<(String, u32)>>()
                            })
                            .collect::<Vec<Vec<(String, u32)>>>()
                            .iter()
                            .map(|u| u.iter().enumerate().map(|(i, v)| {
                                v.1
                                    .wrapping_sub(sk.get_attribute(&v.0).unwrap().value[i])
                                    .wrapping_sub(_secret[i] as u32)
                            } ).collect())
                            .collect::<Vec<Vec<u32>>>();
                        let first = _attrs_dec[0].clone();
                        assert!(_attrs_dec.iter().all(|item| item == &first));
                        println!("_attrs_dec: {:?}", &_attrs_dec[0]);
                        decrypt_symmetric("".to_string().as_bytes(), &ct.data)
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
        let secret = LabeAttributeSecret::new(current.to_string(), secret_base);
        println!("attribute {} secret {}", current.to_string(), &serde_json::to_string(&secret).unwrap());
        let public = LabeAttributePublic::new(key_pair, &secret);
        println!("attribute {} public {}", current, &serde_json::to_string(&public).unwrap());
        pubk.push(public);
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
        attributes.push(String::from("D"));
        // setup scheme
        setup(attributes.clone())
    }
/*
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
 */
    #[test]
    fn test_setup() {
        let (pk, msk) = setup_test();
        let mut attributes: Vec<String> = Vec::new();
        attributes.push(String::from("B"));
        attributes.push(String::from("C"));
        attributes.push(String::from("D"));
        let sk= keygen(&msk, &String::from(r#"("A" and "B") or ("A" and "C") or ("C" and "B" and "D")"#), PolicyLanguage::HumanPolicy).unwrap();
        println!("sk1: {}", &serde_json::to_string(&sk).unwrap());
        let ct= encrypt(&pk, &mut attributes, String::from("griaseng").as_bytes()).unwrap();
        let pt= decrypt(&pk,&sk, &ct);
        println!("ct: {}", &serde_json::to_string(&ct).unwrap());
        println!("pt: {}", &serde_json::to_string(&pt).unwrap());
    }
}

