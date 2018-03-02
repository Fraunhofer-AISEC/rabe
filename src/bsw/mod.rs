extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate rustc_serialize;
extern crate num_bigint;
extern crate blake2_rfc;

use std::string::String;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use rustc_serialize::hex::ToHex;
use rand::Rng;
use policy::AbePolicy;
use tools::*;

//////////////////////////////////////////////////////
// BSW CP-ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbePublicKey {
    _g1: bn::G1,
    _g2: bn::G2,
    _h: bn::G1,
    _f: bn::G1,
    _e_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeMasterKey {
    _beta: bn::Fr,
    _g2_alpha: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeCiphertext {
    _policy: String,
    _c_0: bn::G2,
    _c: Vec<(bn::G2, bn::G1)>,
    _c_m: bn::Gt,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeSecretKey {
    _D: bn::G2,
    _D_j: Vec<(String, bn::G2, bn::G1)>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeContext {
    pub _msk: CpAbeMasterKey,
    pub _pk: CpAbePublicKey,
}

/////////////////////////////////////////////
// BSW CP-ABE type-3
/////////////////////////////////////////////

pub fn cpabe_setup() -> (CpAbePublicKey, CpAbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g1 and generator of group G2: g2
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    // random
    let _beta = Fr::random(_rng);
    let _alpha = Fr::random(_rng);
    // vectors
    // calulate h and f
    let _h = _g1 * _beta;
    let _f = _g1 * _beta.inverse().unwrap();
    let _g2_alpha = _g2 * _alpha;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g1, _g2_alpha);
    // set values of PK
    let _pk = CpAbePublicKey {
        _g1: _g1,
        _g2: _g2,
        _h: _h,
        _f: _f,
        _e_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = CpAbeMasterKey {
        _beta: _beta,
        _g2_alpha: _g2_alpha,
    };
    // return PK and MSK
    return (_pk, _msk);
}

pub fn cpabe_keygen(
    pk: &CpAbePublicKey,
    msk: &CpAbeMasterKey,
    attributes: &Vec<String>,
) -> Option<CpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if attributes.is_empty() || attributes.len() == 0 {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate random r1 and r2 and sum of both
    // compute Br as well because it will be used later too
    let _r = Fr::random(_rng);
    let _g2_r = pk._g2 * _r;
    let _D = (msk._g2_alpha + _g2_r) * msk._beta.inverse().unwrap();
    let mut _D_j: Vec<(String, bn::G2, bn::G1)> = Vec::new();
    for _j in attributes {
        let _r_j = Fr::random(_rng);
        _D_j.push((
            _j.clone(),
            _g2_r + (blake2b_hash_g2(pk._g2, &_j) * _r_j),
            pk._g1 * _r_j,
        ));
    }
    return Some(CpAbeSecretKey { _D: _D, _D_j: _D_j });
}

// ENCRYPT

pub fn cpabe_encrypt(
    pk: &CpAbePublicKey,
    policy: &String,
    plaintext: &Vec<u8>,
) -> Option<CpAbeCiphertext> {
    if plaintext.is_empty() {
        return None;
    }
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    // random number generator
    let _rng = &mut rand::thread_rng();
    // msp matrix M with size n1xn2
    let _rows = msp._m.len();
    let _cols = msp._m[0].len();
    // pick randomness
    let mut _u: Vec<(bn::Fr)> = Vec::new();
    for _i in 0usize.._cols {
        _u.push(Fr::random(_rng));
    }
    // the shared root secret
    let _s = _u[0];
    let _c_0 = pk._h * _s;

    let mut _c: Vec<(bn::G2, bn::G1)> = Vec::new();
    for _i in 0usize.._rows {
        let mut _sum = Fr::zero();
        for _j in 0usize.._cols {
            if msp._m[_i][_j] == 0 {
                // do nothing
            } else if msp._m[_i][_j] == 1 {
                _sum = _sum + _u[_j];
            } else {
                _sum = _sum - _u[_j];
            }
        }
        _c.push((
            pk._g2 * _sum,
            blake2b_hash_g1(pk._g1, &msp._pi[_i]) * _sum,
        ));
    }
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    println!(
        "ENC: Policy: {:?} MSP {:?},{:?} Message: {:?}, ",
        policy,
        msp._m,
        msp._pi,
        into_hex(_msg).unwrap()
    );
    let _c_m = pk._e_gg_alpha.pow(_s) * _msg;
    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&_msg, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            _rng.fill_bytes(&mut iv);
            let ct = CpAbeCiphertext {
                _policy: policy.clone(),
                _c_0: _c_0,
                _c: _c,
                _c_m: _c_m,
                _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

// DECRYPT

pub fn cpabe_decrypt(sk: &CpAbeSecretKey, ct: &CpAbeCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&flatten(&sk._k), &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let mut _prod = Gt::one();
        for _i in 0usize..ct._c.len() {
            let (c_attr1, c_attr2) = ct._c[_i];
            let (_str_value, k_attr1, k_attr2) = sk._k[_i].clone();
            _prod = _prod * (pairing(k_attr1, c_attr1) * pairing(c_attr2, k_attr2).inverse());
        }
        let _msg = (ct._c_m * _prod) * pairing(sk._k_0, ct._c_0).inverse();
        println!(
            "DEC: Policy: {:?} Message: {:?}",
            ct._policy,
            into_hex(_msg).unwrap()
        );
        // Decrypt plaintext using derived secret from cp-abe scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}

// DELEGATE

pub fn cpabe_delegate(
    pk: &CpAbePublicKey,
    sk: &CpAbeSecretKey,
    subset: &Vec<String>,
) -> Option<CpAbeSecretKey> {
    if is_subset(&subset, &flatten(&sk._k)) == false {
        println!("Error: the given attributes are not a subset of sk attributes.");
        return None;
    } else {
        // if no attibutes or an empty policy
        // maybe add empty msk also here
        if subset.is_empty() || subset.len() == 0 {
            println!("Error: the given attributes subset is empty.");
            return None;
        }
        // random number generator
        let _rng = &mut rand::thread_rng();
        // generate random r
        let _r = Fr::random(_rng);
        // calculate derived _k_0
        let _k_0 = sk._k_0 + (pk._f * _r);
        let mut _k: Vec<(String, bn::G1, bn::G2)> = Vec::new();
        // calculate derived attributes
        for (_attr_str, _attr_g1, _attr_g2) in sk._k.clone() {
            let _r_attr = Fr::random(_rng);
            _k.push((
                _attr_str.clone(),
                _attr_g1 + (pk._g1 * _r) +
                    (blake2b_hash_g1(pk._g1, &_attr_str) * _r_attr),
                _attr_g2 + pk._g2 * _r_attr,
            ));
        }
        return Some(CpAbeSecretKey { _k_0: _k_0, _k: _k });
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_and() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: Vec<String> = Vec::new();
        att_not_matching.push(String::from("A"));
        att_not_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();

        // a cp-abe SK key matching
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_not_matching).unwrap();


        // and now decrypt again with mathcing sk
        let _matching = cpabe_decrypt(&sk_matching, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }

    #[test]
    fn test_or() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
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
        let policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}, {"ATT": "C"}]}"#);

        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();

        // a cp-abe SK key matching
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_not_matching).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = cpabe_decrypt(&sk_matching, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }

    #[test]
    fn test_or_and() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
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
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();

        // a cp-abe SK key matching
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &att_not_matching).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = cpabe_decrypt(&sk_matching, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("CP-ABE: Cannot decrypt"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }

    #[test]
    fn test_delegate() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
        // a set of three attributes matching the policy
        let mut _atts: Vec<String> = Vec::new();
        _atts.push(String::from("A"));
        _atts.push(String::from("B"));
        _atts.push(String::from("C"));
        // a set of two delegated attributes
        let _delegate: Vec<_> = _atts[1..2].iter().cloned().collect();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let ct_cp: CpAbeCiphertext = cpabe_encrypt(&pk, &policy, &plaintext).unwrap();
        // a cp-abe SK key matching
        let sk: CpAbeSecretKey = cpabe_keygen(&pk, &msk, &_atts).unwrap();
        // a delegated cp-abe SK key matching
        let sk_delegate: CpAbeSecretKey = cpabe_delegate(&pk, &sk, &_delegate).unwrap();
        // and now decrypt using delegated key
        let _matching = cpabe_decrypt(&sk_delegate, &ct_cp);
        match _matching {
            None => println!("CP-ABE: Cannot decrypt using delegated sk"),
            Some(x) => println!("CP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }
    }
}
