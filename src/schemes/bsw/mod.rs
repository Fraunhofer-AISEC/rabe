extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate num_bigint;
extern crate blake2_rfc;

use std::string::String;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::*;
use rand::Rng;
use utils::secretsharing::{gen_shares_str, calc_pruned_str, calc_coefficients_str};
use utils::tools::*;
use utils::aes::*;

//////////////////////////////////////////////////////
// BSW CP-ABE structs
//////////////////////////////////////////////////////
#[derive(Serialize, Deserialize, PartialEq)]
pub struct CpAbePublicKey {
    _g1: bn::G1,
    _g2: bn::G2,
    _h: bn::G1,
    _f: bn::G2,
    _e_gg_alpha: bn::Gt,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct CpAbeMasterKey {
    _beta: bn::Fr,
    _g2_alpha: bn::G2,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct CpAbeCiphertext {
    _policy: String,
    _c: bn::G1,
    _c_p: bn::Gt,
    _c_y: Vec<(String, bn::G1, bn::G2)>,
    _ct: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct CpAbeSecretKey {
    _d: bn::G2,
    _d_j: Vec<(String, bn::G1, bn::G2)>,
}

//For C
#[derive(Serialize, Deserialize, PartialEq)]
pub struct CpAbeContext {
    pub _msk: CpAbeMasterKey,
    pub _pk: CpAbePublicKey,
}

/////////////////////////////////////////////
// BSW CP-ABE type-3
/////////////////////////////////////////////

pub fn setup() -> (CpAbePublicKey, CpAbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g1 and generator of group G2: g2
    let _g = G1::random(_rng);
    let _gp = G2::random(_rng);
    // random
    let _beta = Fr::random(_rng);
    let _alpha = Fr::random(_rng);
    // vectors
    // calulate h and f
    let _h = _g * _beta;
    let _f = _gp * _beta.inverse().unwrap();
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g, _gp * _alpha);
    // return PK and MSK
    return (
        CpAbePublicKey {
            _g1: _g,
            _g2: _gp,
            _h: _h,
            _f: _f,
            _e_gg_alpha: _e_gg_alpha,
        },
        CpAbeMasterKey {
            _beta: _beta,
            _g2_alpha: _gp * _alpha,
        },
    );
}

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
    let _rng = &mut rand::thread_rng();
    // generate random r1 and r2 and sum of both
    // compute Br as well because it will be used later too
    let _r = Fr::random(_rng);
    let _g_r = _pk._g2 * _r;
    let _d = (_msk._g2_alpha + _g_r) * _msk._beta.inverse().unwrap();
    let mut _d_j: Vec<(String, bn::G1, bn::G2)> = Vec::new();
    for _j in _attributes {
        let _r_j = Fr::random(_rng);
        _d_j.push((
            _j.clone(), // attribute name
            _pk._g1 * _r_j, // D_j Prime
            _g_r + (blake2b_hash_g2(_pk._g2, &_j) * _r_j), // D_j
        ));
    }
    return Some(CpAbeSecretKey { _d: _d, _d_j: _d_j });
}


// DELEGATE

pub fn delegate(
    _pk: &CpAbePublicKey,
    _sk: &CpAbeSecretKey,
    _subset: &Vec<String>,
) -> Option<CpAbeSecretKey> {
    if !is_subset(&_subset, &flatten(&_sk._d_j)) {
        println!("Error: the given attribute set is not a subset of the given sk.");
        return None;
    } else {
        // if no attibutes or an empty policy
        // maybe add empty msk also here
        if _subset.is_empty() || _subset.len() == 0 {
            println!("Error: the given attribute subset is empty.");
            return None;
        }
        // random number generator
        let _rng = &mut rand::thread_rng();
        // generate random r
        let _r = Fr::random(_rng);
        // calculate derived _k_0
        let mut _d_k: Vec<(String, bn::G1, bn::G2)> = Vec::new();
        // calculate derived attributes
        for _attr in _subset {
            let _r_j = Fr::random(_rng);
            let _d_j_val = _sk._d_j
                .iter()
                .find(|x| x.0 == _attr.to_string())
                .map(|x| (x.1, x.2))
                .unwrap();
            _d_k.push((
                _attr.clone(),
                _d_j_val.0 + (_pk._g1 * _r_j),
                _d_j_val.1 + (blake2b_hash_g2(_pk._g2, &_attr) * _r_j) +
                    (_pk._g2 * _r),
            ));
        }
        return Some(CpAbeSecretKey {
            _d: _sk._d + (_pk._f * _r),
            _d_j: _d_k,
        });
    }
}

// ENCRYPT

pub fn encrypt(
    _pk: &CpAbePublicKey,
    _policy: &String,
    _plaintext: &Vec<u8>,
) -> Option<CpAbeCiphertext> {
    if _plaintext.is_empty() || _policy.is_empty() {
        return None;
    }
    let _rng = &mut rand::thread_rng();
    // the shared root secret
    let _s = Fr::random(_rng);
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    let _shares: Vec<(String, Fr)> = gen_shares_str(_s, _policy).unwrap();
    let _c = _pk._h * _s;
    let _c_p = _pk._e_gg_alpha.pow(_s) * _msg;
    let mut _c_y: Vec<(String, bn::G1, bn::G2)> = Vec::new();
    for (_j, _j_val) in _shares {
        _c_y.push((
            _j.clone(),
            _pk._g1 * _j_val,
            blake2b_hash_g2(_pk._g2, &_j) * _j_val,
        ));
    }
    //Encrypt plaintext using derived key from secret
    return Some(CpAbeCiphertext {
        _policy: _policy.clone(),
        _c: _c,
        _c_p: _c_p,
        _c_y: _c_y,
        _ct: encrypt_symmetric(&_msg, &_plaintext).unwrap(),
    });

}

// DECRYPT

pub fn decrypt(_sk: &CpAbeSecretKey, _ct: &CpAbeCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&flatten(&_sk._d_j), &_ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let _pruned = calc_pruned_str(&flatten(&_sk._d_j), &_ct._policy);
        match _pruned {
            None => return None,
            Some(x) => {
                if !x.0 {
                    return None;
                } else {
                    let _z = calc_coefficients_str(&_ct._policy).unwrap();
                    let mut _a = Gt::one();
                    for _j in x.1 {
                        let _c_j = _ct._c_y
                            .iter()
                            .find(|x| x.0 == _j.to_string())
                            .map(|x| (x.1, x.2))
                            .unwrap();
                        let _d_j = _sk._d_j
                            .iter()
                            .find(|x| x.0 == _j.to_string())
                            .map(|x| (x.1, x.2))
                            .unwrap();
                        for _z_tuple in _z.iter() {
                            if _z_tuple.0 == _j {
                                _a = _a *
                                    (pairing(_c_j.0, _d_j.1) * pairing(_d_j.0, _c_j.1).inverse())
                                        .pow(_z_tuple.1);
                            }

                        }


                    }
                    let _msg = _ct._c_p * ((pairing(_ct._c, _sk._d)) * _a.inverse()).inverse();
                    // Decrypt plaintext using derived secret from cp-abe scheme
                    return decrypt_symmetric(&_msg, &_ct._ct);
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_or() {
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
        let policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext).unwrap();

        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), plaintext);

        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_none(), true);
    }

    #[test]
    fn test_and() {
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
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext).unwrap();

        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), plaintext);
        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_none(), true);
    }


    #[test]
    fn test_or_and() {
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
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext).unwrap();

        // and now decrypt again with mathcing sk
        let _match = decrypt(&keygen(&pk, &msk, &att_matching).unwrap(), &ct_cp);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), plaintext);
        let _no_match = decrypt(&keygen(&pk, &msk, &att_not_matching).unwrap(), &ct_cp);
        assert_eq!(_no_match.is_none(), true);
    }

    #[test]
    fn test_delegate() {
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
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext).unwrap();
        // a cp-abe SK key matching
        let sk: CpAbeSecretKey = keygen(&pk, &msk, &_atts).unwrap();
        // delegate a cp-abe SK
        let del: CpAbeSecretKey = delegate(&pk, &sk, &_delegate_att).unwrap();
        // and now decrypt again with mathcing sk
        let _match = decrypt(&del, &ct_cp);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), plaintext);

    }
}
