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
use num_traits::identities::Zero;
use utils::policy::pest::{PolicyLanguage, parse};
use crate::error::RabeError;
use nalgebra::Matrix3;
use utils::aes::{encrypt_symmetric, decrypt_symmetric};
use std::convert::TryInto;
use std::ops::{Add, Mul, MulAssign};
use aes_gcm::Key;
use bit_vec::BitVec;
use gmorph::{Decrypt, Enc, Encrypt, KeyPair, algebra::Q231};
#[cfg(not(feature = "use-borsh"))]
use serde::{Serialize, Deserialize};
#[cfg(feature = "use-borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
use sha3::digest::generic_array::typenum::Bit;
use utils::secretsharing::numeric::{calc_coefficients, calc_pruned, gen_shares_policy};

const PRECALC: u32 = 16;

/// (PK)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabePublicKey {
    pub zero: Vec<Enc>,
    pub one: Vec<Enc>,
    pub alpha: [Enc; 4],
    pub attributes: Vec<LabeAttributePublic>,
}

/// (MSK)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeMasterKey {
    pub attributes: Vec<LabeAttributeSecret>,
    pub alpha: BitVec,
    pub public: Matrix3<Q231>,
    pub private: Matrix3<Q231>
}

/// A LSW Secret User Key (SK)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeSecretKey {
    pub policy: (String, PolicyLanguage, Vec<LabeAttributeSecret>),
    pub attributes: Vec<LabeAttributeSecret>,
    pub public: Matrix3<Q231>,
    pub private: Matrix3<Q231>
}
impl LabeSecretKey {
    pub fn get_part(&self, name: &String) -> Option<LabeAttributeSecret> {
        self.policy.2.iter().filter(|i| &i.name == name).nth(0).cloned()
    }
    pub fn get_attribute(&self, name: &String) -> Option<LabeAttributeSecret> {
        self.attributes.iter().filter(|i| &i.name == name).nth(0).cloned()
    }
    pub fn get_key(&self) -> Matrix3<Q231> {
        self.private
    }
}
/// A LSW Ciphertext (CT)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LabeCiphertext {
    pub data: Vec<u8>,
    pub attributes: Vec<LabeAttribute>,
}

/// A LSW Master Key (MSK)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
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
        let secret_num = secret.get_secret();
        LabeAttributePublic {
            name: secret.name.clone(),
            value: [
                    Enc::encrypt(&key_pair, secret_num[0]),
                    Enc::encrypt(&key_pair, secret_num[1]),
                    Enc::encrypt(&key_pair, secret_num[2]),
                    Enc::encrypt(&key_pair, secret_num[3])
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
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct LabeAttributeSecret {
    pub name: String,
    pub value: BitVec,
}
/// (Attribute Enum)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
pub struct LabeAttributePair {
    secret: LabeAttributeSecret,
    public: LabeAttributePublic,
}

/// (Attribute Enum)
#[cfg_attr(feature = "use-borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "use-borsh"), derive(Serialize, Deserialize))]
#[derive(Debug)]
pub enum LabeAttribute {
    SecretKey(LabeAttributeSecret),
    PublicKey(LabeAttributePublic),
}


impl LabeMasterKey {
    pub fn new(attributes: Vec<LabeAttributeSecret>, key_pair: &KeyPair, alpha: BitVec) -> LabeMasterKey {
        LabeMasterKey {
            attributes,
            alpha,
            public: key_pair.public.clone(),
            private: key_pair.private.clone()
        }
    }
    pub fn get_attribute(&self, name: &String) -> Option<&LabeAttributeSecret> {
        self.attributes.iter().filter(|i| &i.name == name).nth(0)
    }
}

impl LabePublicKey {
    pub fn new(attributes: Vec<LabeAttributePublic>, key_pair: &KeyPair, secret_base: &BitVec) -> LabePublicKey {
        let secret = vec_to_num(secret_base);
        println!("LabePublicKey alpha {:?}", secret);
        LabePublicKey {
            zero: (0..PRECALC)
                .into_iter()
                .map(|_| Enc::encrypt(key_pair, 0))
                .collect(),
            one: (0..PRECALC)
                .into_iter()
                .map(|_| Enc::encrypt(key_pair, 1))
                .collect(),
            alpha: [
                Enc::encrypt(key_pair, secret[0]),
                Enc::encrypt(key_pair, secret[1]),
                Enc::encrypt(key_pair, secret[2]),
                Enc::encrypt(key_pair, secret[3])
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
    pub fn get_apks(&self) -> Vec<(String, [Enc; 4])> {
        self.attributes
            .iter()
            .filter_map(|pk| {
                match pk {
                    LabeAttribute::PublicKey(apk) => Some((apk.name.to_string(), apk.value)),
                    _ => None
                }
            })
            .collect()
    }
    pub fn get_public(&self, attribute: &String) -> Result<&[Enc; 4], RabeError> {
        self.attributes
            .iter()
            .filter_map(|pk| {
                match pk {
                   LabeAttribute::PublicKey(apk) => Some(&apk.value),
                    _ => None
                }
            })
            .nth(0)
            .ok_or(RabeError::new(&format!("no public key found for {}", attribute)))
    }
    pub fn get_attributes(&self) -> Vec<String> {
        self.attributes
            .iter()
            .map(|obj| {
                match obj {
                    LabeAttribute::PublicKey(apk) => apk.name.to_string(),
                    LabeAttribute::SecretKey(ask) => ask.name.to_string()
                }
            } )
            .collect()
    }
}

impl LabeAttributeSecret {
    pub fn new(name: String, secret_base: &BitVec) -> LabeAttributeSecret {
         LabeAttributeSecret {
            name: name.to_string(),
            value: hash_to(name, secret_base)
        }
    }
    pub fn derive_from(input: (String, BitVec)) -> LabeAttributeSecret {
        LabeAttributeSecret {
            name: input.0.to_string(),
            value: input.1
        }
    }
    pub fn get_secret(&self) -> [u32; 4] {
        vec_to_num(&self.value)
    }
}

pub(crate) fn hash_to(input: String, secret_base: &BitVec) -> BitVec {
    let mut hasher = Shake128::default();
    hasher.update(input.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut res1 = [0u8; 16];
    reader.read(&mut res1);
    let mut hashed = BitVec::from_bytes(&res1);
    if hashed.xor(&secret_base) {
        hashed
    }
    else {
        BitVec::new()
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
    let key_pair = KeyPair::new();
    //let alpha: BitVec = BitVec::from_fn(128, |i| rand::thread_rng().gen());
    let alpha: BitVec = num_to_vec([1, 12, 1, 124234228]);
    let attr = derive_attributes(&key_pair, &alpha, attributes);
    let msk = LabeMasterKey::new(attr.1, &key_pair, alpha);
    (
        LabePublicKey::new(attr.0, &key_pair, &msk.alpha),
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
            println!("keygen alpha {:?}", vec_to_num(&msk.alpha));
            let parts: Vec<LabeAttributeSecret> = match gen_shares_policy(vec_to_num(&msk.alpha), &pol, None) {
                Some(shares) => shares.into_iter().map(|share| {
                    LabeAttributeSecret::derive_from((share.0, num_to_vec(share.1)))
                } ).collect(),
                None => panic!("cloud not generate shares !")
            };
            let mut random_pair = KeyPair::new();
            random_pair.private = random_pair.private * (random_pair.public * msk.private * msk.private * msk.public);
            random_pair.public = random_pair.public * (random_pair.private * msk.public * msk.public * msk.private);
            let attributes = parts.iter().map(|a| msk.get_attribute(&a.name).unwrap().clone()).collect();
            Ok(
                LabeSecretKey {
                    policy: (policy.to_string(), language, parts),
                    attributes,
                    public: random_pair.public.clone(),
                    private: random_pair.private.clone(),
                }
            )
        },
        Err(e) => Err(e)
    }
}

pub fn encrypt(
    pk: &LabePublicKey,
    msk: &LabeMasterKey,
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
        let mut blinded: Vec<LabeAttribute> = Vec::new();
        let mut rng = rand::thread_rng();
        //let secret: Vec<u32> = (0..4).into_iter().map(|_| rng.gen()).collect();
        let secret = vec![10, 11, 12, 13];
        println!("secret {:?}", &secret);
        let encrypted_secrets: Vec<Enc> = pk.double_and_add(&secret);
        // secret = secret + base
        let kp = KeyPair::from_keys(&msk.public, &msk.private);
        println!("enc secret {:?}", &[
            encrypted_secrets[0].decrypt(&kp),
            encrypted_secrets[1].decrypt(&kp),
            encrypted_secrets[2].decrypt(&kp),
            encrypted_secrets[3].decrypt(&kp)
        ]);
        let shifted_secrets = encrypted_secrets.iter().enumerate().map(|item| item.1.clone().add(pk.alpha[item.0])).collect::<Vec<Enc>>();
        println!("enc shifted_secrets {:?}", &[
            shifted_secrets[0].decrypt(&kp),
            shifted_secrets[1].decrypt(&kp),
            shifted_secrets[2].decrypt(&kp),
            shifted_secrets[3].decrypt(&kp)
        ]);
        attributes.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
        for (i, attr) in attributes.into_iter().enumerate() {
            // attr = attr.secret + (secret + base)
            println!("enc pk.attr {:?}", &[
                pk.get_attribute(attr).unwrap().value[0].decrypt(&kp),
                pk.get_attribute(attr).unwrap().value[1].decrypt(&kp),
                pk.get_attribute(attr).unwrap().value[2].decrypt(&kp),
                pk.get_attribute(attr).unwrap().value[3].decrypt(&kp)
            ]);
            match pk.attribute_blinding(attr, shifted_secrets.as_slice()) {
                Some(apk) => {
                    println!("enc apk {:?}", &[
                        apk.value[0].decrypt(&kp),
                        apk.value[1].decrypt(&kp),
                        apk.value[2].decrypt(&kp),
                        apk.value[3].decrypt(&kp)
                    ]);
                    blinded.push(LabeAttribute::PublicKey(apk))
                },
                None => panic!("attribute {} not found in public key!", attr)
            }
        }
        match encrypt_symmetric(format!("{:?}", secret).to_string(),  &plaintext.to_vec()) {
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
                        let _coeff: Vec<(String, i32)> = calc_coefficients(&pol, 1, None).unwrap();
                        println!("_coeff : {:?}", format!("{:?}", &_coeff).to_string());
                        let mut _alpha = [0i32, 0i32, 0i32, 0i32];
                        for (i, val) in sk.policy.2.iter().enumerate() {
                            let nums = vec_to_num(&val.value);
                            for j in 0..4 {
                                let term = _coeff[i].1.wrapping_mul(nums[j] as i32);
                                _alpha[j] = _alpha[j].wrapping_add(term);
                            }
                        }
                        println!("_alpha : {:?}", format!("{:?}", &_alpha).to_string());
                        let _secret = _alpha.map(|i| i.wrapping_div(_list.len() as i32));
                        println!("_alpha : {:?}", format!("{:?}", &_secret).to_string());
                        let _attrs_dec = ct
                            .get_apks()
                            .iter()
                            .map(| (name, values) | values.iter().enumerate().map(|(i, ctpart)| {
                                let first_step = ctpart.decrypt(&KeyPair::from_keys(&sk.public, &sk.private));
                                let nums = vec_to_num(&sk.get_attribute(&name).unwrap().value);
                                first_step
                                    .wrapping_sub(nums[i])
                                    .wrapping_sub(_secret[i] as u32)
                            } ).collect())
                            .collect::<Vec<Vec<u32>>>();
                        println!("final : {:?}", format!("{:?}", &_attrs_dec).to_string());
                        decrypt_symmetric("".to_string(), &ct.data)
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
    alpha: &BitVec,
    attributes: Vec<String>,
) -> (Vec<LabeAttributePublic>, Vec<LabeAttributeSecret>) {
    let mut pubk: Vec<LabeAttributePublic> = vec![];
    let mut seck: Vec<LabeAttributeSecret> = vec![];
    for current in attributes {
        let secret = LabeAttributeSecret::new(current.to_string(), alpha);
        pubk.push(LabeAttributePublic::new(key_pair, &secret));
        seck.push(secret);
    }
    (pubk, seck)
}

fn vec_to_num(
    secret: &BitVec
) -> [u32; 4] {
    let mut values: [u32; 4] = [0, 0, 0, 0];
    for i in 0..4 {
        let mut dst = [0u8; 4];
        dst.clone_from_slice(&secret.to_bytes()[(i*4)..(i+1)*4]);
        values[i] = u32::from_be_bytes(dst);
    }
    values
}
fn num_to_vec(
    number: [u32; 4]
) -> BitVec {
    let mut bytes = vec![];
    for i in 0..4 {
        let mut current_bytes = number[i].to_be_bytes().to_vec();
        bytes.append(&mut current_bytes)
    }
    BitVec::from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use bit_vec::BitVec;
    use gmorph::Decrypt;
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
        let ct= encrypt(&pk, &msk, &mut attributes, String::from("griaseng").as_bytes()).unwrap();
        let pt= decrypt(&sk, &pk, &ct);
        println!("ct: {}", &serde_json::to_string(&ct).unwrap());
        println!("pt: {}", &serde_json::to_string(&pt).unwrap());
    }

    #[test]
    fn test_num_to_vec() {
        assert_eq!([1, 2, 3, 4], vec_to_num(&num_to_vec([1, 2, 3, 4])));
    }
}

