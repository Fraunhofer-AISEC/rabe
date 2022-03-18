//! This is the documentation for the `BSW` scheme:
//!
//! * Developped by John Bethencourt, Amit Sahai, Brent Waters, "Ciphertext-Policy Attribute-Based Encryption"
//! * Published in Security and Privacy, 2007. SP'07. IEEE Symposium on. IEEE
//! * Available from https://doi.org/10.1109/SP.2007.11
//! * Type: encryption (attribute-based)
//! * Setting: bilinear groups (asymmetric)
//! * Authors: Georg Bramm
//! * Date: 04/2018
//!
//! # Examples
//!
//! ```
//!use rabe::schemes::bsw::*;
//! use rabe::utils::policy::pest::PolicyLanguage;
//!let (pk, msk) = setup();
//!let plaintext = String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
//!let policy = String::from(r#""A" and "B""#);
//!let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
//!let sk: CpAbeSecretKey = keygen(&pk, &msk, &vec!["A".to_string(), "B".to_string()]).unwrap();
//!assert_eq!(decrypt(&sk, &ct_cp).unwrap(), plaintext);
//! ```
use rabe_bn::{Fr, G1, G2, Gt, pairing};
use rand::Rng;
use utils::{
    secretsharing::{gen_shares_policy, calc_pruned, calc_coefficients},
    tools::*,
    aes::*,
    hash::*
};
use utils::policy::pest::{PolicyLanguage, parse, PolicyType};
use RabeError;

/// A BSW Public Key (PK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct CpAbePublicKey {
    pub _g1: G1,
    pub _g2: G2,
    pub _h: G1,
    pub _f: G2,
    pub _e_gg_alpha: Gt,
}

/// A BSW Master Key (MSK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct CpAbeMasterKey {
    pub _beta: Fr,
    pub _g2_alpha: G2,
}

/// A BSW Ciphertext (CT)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct CpAbeCiphertext {
    pub _policy: (String, PolicyLanguage),
    pub _c: G1,
    pub _c_p: Gt,
    pub _c_y: Vec<CpAbeAttribute>,
    pub _ct: Vec<u8>,
}

/// A BSW Secret User Key (SK)
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct CpAbeSecretKey {
    pub _d: G2,
    pub _d_j: Vec<CpAbeAttribute>,
}

/// A BSW Attribute
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct CpAbeAttribute {
    pub _str: String,
    pub _g1: G1,
    pub _g2: G2,
}

/// The setup algorithm of BSW CP-ABE. Generates a new CpAbePublicKey and a new CpAbeMasterKey.
pub fn setup() -> (CpAbePublicKey, CpAbeMasterKey) {
    // random number generator
    let mut _rng = rand::thread_rng();
    // generator of group G1: g1 and generator of group G2: g2
    let _g1:G1 = _rng.gen();
    let _g2:G2 = _rng.gen();
    // random
    let _beta:Fr = _rng.gen();
    let _alpha:Fr = _rng.gen();
    // vectors
    // calulate h and f
    let _h = _g1 * _beta;
    let _f = _g2 * _beta.inverse().unwrap();
    // calculate g2^alpha
    let _g2_alpha = _g2 * _alpha;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g1, _g2_alpha);

    // return PK and MSK
    return (
        CpAbePublicKey {_g1, _g2, _h, _f, _e_gg_alpha},
        CpAbeMasterKey {_beta, _g2_alpha},
    );
}

/// The key generation algorithm of BSW CP-ABE. Generates a CpAbeSecretKey using a CpAbePublicKey, a CpAbeMasterKey and a set of attributes given as Vec<String>.
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_msk` - A Master Key (MSK), generated by the function setup()
///	* `_attributes` - A Vector of String attributes assigned to this user key
///
pub fn keygen(
    _pk: &CpAbePublicKey,
    _msk: &CpAbeMasterKey,
    _attributes: &Vec<String>,
) -> Option<CpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if _attributes.is_empty() || _attributes.len() == 0 {
        return None;
    }
    // random number generator
    let mut _rng = rand::thread_rng();
    // generate random r1 and r2 and sum of both
    // compute Br as well because it will be used later too
    let _r:Fr = _rng.gen();
    let _g_r = _pk._g2 * _r;
    let _d = (_msk._g2_alpha + _g_r) * _msk._beta.inverse().unwrap();
    let mut _d_j: Vec<CpAbeAttribute> = Vec::new();
    for _j in _attributes {
        let _r_j:Fr = _rng.gen();
        _d_j.push(CpAbeAttribute {
            _str: _j.clone(), // attribute name
            _g1: _pk._g1 * _r_j, // D_j Prime
            _g2: _g_r + (sha3_hash(_pk._g2, &_j).expect("could not hash _j") * _r_j), // D_j
        });
    }
    return Some(CpAbeSecretKey {_d, _d_j});
}

/// The delegate generation algorithm of BSW CP-ABE. Generates a new CpAbeSecretKey using a CpAbePublicKey, a CpAbeSecretKey and a subset of attributes (of the key _sk) given as Vec<String>.
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_sk` - A Secret User Key (SK), generated by the function keygen()
///	* `_attributes` - A Vector of String attributes assigned to this user key
///
pub fn delegate(
    _pk: &CpAbePublicKey,
    _sk: &CpAbeSecretKey,
    _subset: &Vec<String>,
) -> Option<CpAbeSecretKey> {
    let _str_attr = _sk._d_j
        .iter()
        .map(|_values| _values._str.to_string())
        .collect::<Vec<_>>();

    return if !is_subset(&_subset, &_str_attr) {
        println!("Error: the given attribute set is not a subset of the given sk.");
        None
    } else {
        // if no attibutes or an empty policy
        // maybe add empty msk also here
        if _subset.is_empty() || _subset.len() == 0 {
            println!("Error: the given attribute subset is empty.");
            return None;
        }
        // random number generator
        let mut _rng = rand::thread_rng();
        // generate random r
        let _r: Fr = _rng.gen();
        // calculate derived _k_0
        let mut _d_k: Vec<CpAbeAttribute> = Vec::new();
        // calculate derived attributes
        for _attr in _subset {
            let _r_j: Fr = _rng.gen();
            let _d_j_val = _sk._d_j
                .iter()
                .find(|x| x._str == _attr.to_string())
                .map(|x| (x._g1, x._g2))
                .unwrap();
            _d_k.push(CpAbeAttribute {
                _str: _attr.clone(),
                _g1: _d_j_val.0 + (_pk._g1 * _r_j),
                _g2: _d_j_val.1 + (sha3_hash(_pk._g2, &_attr).expect("could not hash _attr") * _r_j) + (_pk._g2 * _r),
            });
        }
        Some(CpAbeSecretKey {
            _d: _sk._d + (_pk._f * _r),
            _d_j: _d_k,
        })
    }
}

/// The encrypt algorithm of BSW CP-ABE. Generates a new CpAbeCiphertext using an Ac17PublicKey, an access policy given as String and some plaintext data given as [u8].
///
/// # Arguments
///
///	* `_pk` - A Public Key (PK), generated by the function setup()
///	* `_policy` - An access policy given as JSON String
///	* `_plaintext` - plaintext data given as a Vector of u8
///
pub fn encrypt(
    _pk: &CpAbePublicKey,
    _policy: &String,
    _plaintext: &Vec<u8>,
    _language: PolicyLanguage,
) -> Result<CpAbeCiphertext, RabeError> {
    if _plaintext.is_empty() || _policy.is_empty() {
        RabeError::new("Error in bsw/encrypt: Plaintext or policy is empty.");
    }
    let mut _rng = rand::thread_rng();
    // the shared root secret
    let _s:Fr = _rng.gen();
    let _msg: Gt = _rng.gen();
    match parse(_policy, _language) {
        Ok(pol) => {
            let _shares: Vec<(String, Fr)> = gen_shares_policy(_s, &pol, None).unwrap();
            let _c = _pk._h * _s;
            let _c_p = _pk._e_gg_alpha.pow(_s) * _msg;
            let mut _c_y: Vec<CpAbeAttribute> = Vec::new();
            for (_j, _j_val) in _shares {
                _c_y.push(CpAbeAttribute {
                    _str: _j.clone(),
                    _g1: _pk._g1 * _j_val,
                    _g2: sha3_hash(_pk._g2, &_j).expect("could not hash _j") * _j_val,
                });
            }
            let _policy = _policy.to_string();
            let _ct = encrypt_symmetric(_msg, &_plaintext).unwrap();
            //Encrypt plaintext using derived key from secret
            return Ok(CpAbeCiphertext {_policy: (_policy, _language), _c, _c_p, _c_y, _ct});
        },
        Err(e) => Err(e)
    }

}

/// The decrypt algorithm of BSW CP-ABE. Reconstructs the original plaintext data as Vec<u8>, given a CpAbeCiphertext with a matching CpAbeSecretKey.
///
/// # Arguments
///
///	* `_sk` - A Secret Key (SK), generated by the function keygen()
///	* `_ct` - An BSW CP-ABE Ciphertext
///
pub fn decrypt(_sk: &CpAbeSecretKey, _ct: &CpAbeCiphertext) -> Result<Vec<u8>, RabeError> {
    let _str_attr = _sk._d_j
        .iter()
        .map(|_values| _values._str.to_string())
        .collect::<Vec<_>>();
    match parse(_ct._policy.0.as_ref(), _ct._policy.1) {
        Ok(pol) => {
            return if traverse_policy(&_str_attr, &pol, PolicyType::Leaf) == false {
                Err(RabeError::new("Error in bsw/encrypt: attributes do not match policy."))
            } else {
                match calc_pruned(&_str_attr, &pol, None) {
                    Err(e) => Err(e),
                    Ok(_pruned) => {
                        if !_pruned.0 {
                            Err(RabeError::new("Error in bsw/encrypt: attributes do not match policy."))
                        } else {
                            let _z = calc_coefficients(&pol, Some(Fr::one()), None).unwrap();
                            let mut _a = Gt::one();
                            for _j in _pruned.1 {
                                match _ct._c_y.iter().find(|x| x._str == _j.to_string()) {
                                    Some(_c_j) => {
                                        match _sk._d_j.iter().find(|x| x._str == _j.to_string()) {
                                            Some(_d_j) => {
                                                for _z_tuple in _z.iter() {
                                                    if _z_tuple.0 == _j {
                                                        _a = _a *
                                                            (pairing(_c_j._g1, _d_j._g2) *
                                                                pairing(_d_j._g1, _c_j._g2).inverse())
                                                                .pow(_z_tuple.1);
                                                    }
                                                }
                                            }
                                            None => {
                                                // do nothing
                                            }
                                        }
                                    }
                                    None => {
                                        // do nothing
                                    }
                                }
                            }
                            let _msg = _ct._c_p * ((pairing(_ct._c, _sk._d)) * _a.inverse()).inverse();
                            // Decrypt plaintext using derived secret from cp-abe scheme
                            decrypt_symmetric(_msg, &_ct._ct)
                        }
                    }
                }
            }
        },
        Err(e) => Err(e)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn or() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("D"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("C"));
        att_not_matching.push(String::from("D"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();

        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);

        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }

    #[test]
    fn and10() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        for n in 1..11 {
            let mut _c = String::from("attr");
            _c.push_str(&n.to_string());
            att_matching.push(_c);
        }

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("attr201"));
        att_not_matching.push(String::from("attr200"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        let mut _policy = String::from("{\"name\": \"and\", \"children\": [");
        for n in 1..11 {
            let mut _current = String::from("{\"name\": \"attr");
            if n < 10 {
                _current.push_str(&n.to_string());
                _current.push_str(&String::from("\"}, "));
            } else {
                _current.push_str(&n.to_string());
                _current.push_str(&String::from("\"}]"));
            }
            _policy.push_str(&_current);
        }
        _policy.push_str(&String::from("}"));
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &_policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();

        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);

        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }

    #[test]
    fn nested() {
        // setup scheme
        let (pk, msk) = setup();
        let _num_nested = 30; // maximum at about 50 to 60
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        for _i in 1..(_num_nested + 1) {
            let mut _attr = String::from("a");
            _attr.push_str(&_i.to_string());
            att_matching.push(_attr);
        }
        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("x"));
        att_not_matching.push(String::from("y"));
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        let mut _policy_mut = String::from("{\"name\":\"and\", \"children\": [{\"name\": \"a2\"}, {\"name\": \"a1\"}]}");
        for _i in 3.._num_nested {
            let mut _str = String::from("{\"name\":\"and\", \"children\":[");
            _str.push_str("{\"name\":\"");
            _str.push_str(&att_matching[_i - 1]);
            _str.push_str("\"},");
            _str.push_str(&_policy_mut);
            _str.push_str("]}");
            _policy_mut = _str.clone();
        }
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &_policy_mut, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);
        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }


    #[test]
    fn or3() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("B"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "X"}, {"name": "Y"}, {"name": "A"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();

        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);
        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }

    #[test]
    fn and() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));
        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("D"));
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children":  [{"name": "A"}, {"name": "B"}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);
        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }

    #[test]
    fn and3() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));
        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("D"));
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children":  [{"name": "A"}, {"name": "B"}, {"name": "C"}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);

        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }

    #[test]
    fn or_and() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));
        att_matching.push(String::from("D"));
        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "or", "children": [{"name": "and", "children":  [{"name": "A"}, {"name": "B"}]}, {"name": "and", "children":  [{"name": "C"}, {"name": "D"}]}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);
        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_ok(), false);
    }

    #[test]
    fn delegate_ab() {
        // setup scheme
        let (pk, msk) = setup();
        // a set of three attributes matching the policy
        let mut _atts: Vec<String> = Vec::new();
        _atts.push(String::from("A"));
        _atts.push(String::from("B"));
        _atts.push(String::from("C"));
        // a set of two delegated attributes
        let mut _delegate_att: Vec<String> = Vec::new();
        _delegate_att.push(String::from("A"));
        _delegate_att.push(String::from("B"));
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"name": "and", "children":  [{"name": "A"}, {"name": "B"}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::JsonPolicy).unwrap();
        // a cp-abe SK key matching
        let sk: CpAbeSecretKey = keygen(&pk, &msk, &_atts).unwrap();
        // delegate a cp-abe SK
        let del: CpAbeSecretKey = delegate(&pk, &sk, &_delegate_att).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&del, &ct_cp);
        assert_eq!(_match.is_ok(), true);
        assert_eq!(_match.unwrap(), plaintext);
    }
}
