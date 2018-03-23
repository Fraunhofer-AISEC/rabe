extern crate bn;
extern crate rand;
extern crate serde;
extern crate serde_json;

use std::string::String;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use rustc_serialize::hex::ToHex;
use rand::Rng;
use policy::dnf::DnfPolicy;
use tools::*;

//////////////////////////////////////////////////////
// MKE08 ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08PublicKey {
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _p1: bn::G1,
    pub _p2: bn::G2,
    pub _e_gg_y1: bn::Gt,
    pub _e_gg_y2: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08MasterKey {
    pub _g1_y: bn::G1,
    pub _g2_y: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08UserKey {
    pub _sk_u: Mke08SecretUserKey,
    pub _pk_u: Mke08PublicUserKey,
    pub _sk_a: Vec<Mke08SecretAttributeKey>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08PublicUserKey {
    pub _u: String,
    pub _pk_g1: bn::G1,
    pub _pk_g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretUserKey {
    pub _sk_g1: bn::G1,
    pub _sk_g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretAuthorityKey {
    pub _a: String,
    pub _r: bn::Fr,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08PublicAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
    pub _gt1: bn::Gt,
    pub _gt2: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08Ciphertext {
    pub _str: Vec<Vec<String>>,
    pub _e_j1: Vec<bn::Gt>,
    pub _e_j2: Vec<bn::Gt>,
    pub _e_j3: Vec<bn::G1>,
    pub _e_j4: Vec<bn::G2>,
    pub _e_j5: Vec<bn::G1>,
    pub _e_j6: Vec<bn::G2>,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}


//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08GlobalContext {
    pub _gk: Mke08PublicKey,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08Context {
    pub _mk: Mke08MasterKey,
    pub _pk: Mke08PublicKey,
}

//////////////////////////////////////////
// MKE08 DABE on type-3
//////////////////////////////////////////

// global key generation
pub fn mke08_setup() -> (Mke08PublicKey, Mke08MasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _g1 = G1::random(_rng);
    let _g2 = G2::random(_rng);
    let _p1 = G1::random(_rng);
    let _p2 = G2::random(_rng);
    let _y1 = Fr::random(_rng);
    let _y2 = Fr::random(_rng);
    // return PK and MK
    return (
        Mke08PublicKey {
            _g1: _g1,
            _g2: _g2,
            _p1: _p1,
            _p2: _p2,
            _e_gg_y1: pairing(_g1, _g2).pow(_y1),
            _e_gg_y2: pairing(_g1, _g2).pow(_y2),
        },
        Mke08MasterKey {
            _g1_y: _g1 * _y1,
            _g2_y: _g2 * _y2,
        },
    );
}

// user key generation
pub fn mke08_create_user(_pk: &Mke08PublicKey, _mk: &Mke08MasterKey, _u: &String) -> Mke08UserKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _mk_u = Fr::random(_rng);
    // return pk_u and sk_u
    return Mke08UserKey {
        _sk_u: Mke08SecretUserKey {
            _sk_g1: _mk._g1_y + (_pk._p1 * _mk_u),
            _sk_g2: _mk._g2_y + (_pk._p2 * _mk_u),
        },
        _pk_u: Mke08PublicUserKey {
            _u: _u.clone(),
            _pk_g1: _pk._g1 * _mk_u,
            _pk_g2: _pk._g2 * _mk_u,
        },
        _sk_a: Vec::new(),
    };
}

// authority setup
pub fn mke08_create_authority(_a: &String) -> Mke08SecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // return secret authority key
    return Mke08SecretAuthorityKey {
        _a: _a.clone(),
        _r: Fr::random(_rng),
    };
}

// request an attribute PK from an authority
pub fn mke08_request_authority_pk(
    _pk: &Mke08PublicKey,
    _a: &String,
    _sk_a: &Mke08SecretAuthorityKey,
) -> Option<Mke08PublicAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(_a, &_sk_a._a) {
        let exponent = blake2b_hash_fr(_a) * blake2b_hash_fr(&_sk_a._a) * _sk_a._r;
        // return PK and mke
        return Some(Mke08PublicAttributeKey {
            _str: _a.clone(),
            _g1: _pk._g1 * exponent,
            _g2: _pk._g2 * exponent,
            _gt1: _pk._e_gg_y1.pow(exponent),
            _gt2: _pk._e_gg_y2.pow(exponent),
        });
    } else {
        return None;
    }
}

// request an attribute PK from an authority
pub fn mke08_request_authority_sk(
    _a: &String,
    _sk_a: &Mke08SecretAuthorityKey,
    _pk_u: &Mke08PublicUserKey,
) -> Option<Mke08SecretAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(_a, &_sk_a._a) && is_eligible(_a, &_pk_u._u) {
        let exponent = blake2b_hash_fr(_a) * blake2b_hash_fr(&_sk_a._a) * _sk_a._r;
        // return PK and mke
        return Some(Mke08SecretAttributeKey {
            _str: _a.clone(),
            _g1: _pk_u._pk_g1 * exponent,
            _g2: _pk_u._pk_g2 * exponent,
        });
    } else {
        return None;
    }
}
/* encrypt
 * _attr_pks is a vector of all public attribute keys
 */
pub fn mke08_encrypt(
    _pk: &Mke08PublicKey,
    _attr_pks: &Vec<Mke08PublicAttributeKey>,
    _policy: &String,
    _plaintext: &[u8],
) -> Option<Mke08Ciphertext> {
    // if policy is in DNF
    if DnfPolicy::is_in_dnf(&_policy) {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // an DNF policy from the given String
        let dnf: DnfPolicy = DnfPolicy::from_string(&_policy, _attr_pks).unwrap();
        // random Gt msgs
        let _msg1 = pairing(G1::random(_rng), G2::random(_rng));
        let _msg2 = _msg1.pow(Fr::random(_rng));
        let _msg = _msg1 * _msg2;
        // CT result vectors
        let mut _e_str: Vec<Vec<String>> = Vec::new();
        let mut _e_j1: Vec<bn::Gt> = Vec::new();
        let mut _e_j2: Vec<bn::Gt> = Vec::new();
        let mut _e_j3: Vec<bn::G1> = Vec::new();
        let mut _e_j4: Vec<bn::G2> = Vec::new();
        let mut _e_j5: Vec<bn::G1> = Vec::new();
        let mut _e_j6: Vec<bn::G2> = Vec::new();
        // now add randomness using _r_j
        for _term in dnf._terms {
            let _r_j = Fr::random(_rng);
            _e_str.push(_term.0);
            _e_j1.push(_term.1.pow(_r_j) * _msg1);
            _e_j2.push(_term.2.pow(_r_j) * _msg2);
            _e_j3.push(_pk._p1 * _r_j);
            _e_j4.push(_pk._p2 * _r_j);
            _e_j5.push(_term.3 * _r_j);
            _e_j6.push(_term.4 * _r_j);
        }
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
                return Some(Mke08Ciphertext {
                    _str: _e_str,
                    _e_j1: _e_j1,
                    _e_j2: _e_j2,
                    _e_j3: _e_j3,
                    _e_j4: _e_j4,
                    _e_j5: _e_j5,
                    _e_j6: _e_j6,
                    _ct: encrypt_aes(&_plaintext, &key, &iv).ok().unwrap(),
                    _iv: iv,
                });
            }
        }
    } else {
        return None;
    }
}

/*
 * decrypt
 * Decrypt a ciphertext
 * SK is the user's private key dictionary sk.attr: { xxx , xxx }
*/
pub fn mke08_decrypt(
    _pk: &Mke08PublicKey,
    _ct: &Mke08Ciphertext,
    _sk: &Mke08UserKey,
    _policy: &String,
) -> Option<Vec<u8>> {
    if traverse_str(&flatten_mke08(&_sk._sk_a), &_policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
        let mut _msg = Gt::one();
        for _i in 0usize.._ct._str.len() {
            if is_satisfiable(&_ct._str[_i], &_sk._sk_a) {
                let _sk_sum = calc_satisfiable(&_ct._str[_i], &_sk._sk_a);
                _msg = _ct._e_j1[_i] * _ct._e_j2[_i] * pairing(_ct._e_j3[_i], _sk_sum.1) *
                    pairing(_sk_sum.0, _ct._e_j4[_i]) *
                    (pairing(_ct._e_j5[_i], _sk._sk_u._sk_g2) *
                         pairing(_sk._sk_u._sk_g1, _ct._e_j6[_i])).inverse();
                break;
            }
        }
        // Decrypt plaintext using derived secret from mke08 scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&_ct._ct[..], &key, &_ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;


    #[test]
    fn test_and() {
        // setup scheme
        let (_pk, _msk) = mke08_setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = mke08_create_user(&_pk, &_msk, &String::from("user1"));
        // authority1
        let _a1_key = mke08_create_authority(&String::from("authority1"));
        // authority2
        let _a2_key = mke08_create_authority(&String::from("authority2"));
        // our attributes
        let _att1 = String::from("A");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = mke08_request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = mke08_request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        // add attribute sk's to user key
        _u_key._sk_a.push(
            mke08_request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap(),
        );
        _u_key._sk_a.push(
            mke08_request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap(),
        );
        // our plaintext
        let _plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let _policy = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext =
            mke08_encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext).unwrap();
        // and now decrypt again with mathcing sk
        let _match = mke08_decrypt(&_pk, &_ct, &_u_key, &_policy);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }


    #[test]
    fn test_or() {
        // setup scheme
        let (_pk, _msk) = mke08_setup();
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = mke08_create_user(&_pk, &_msk, &String::from("user1"));
        // authority1
        let _a1_key = mke08_create_authority(&String::from("authority1"));
        // authority2
        let _a2_key = mke08_create_authority(&String::from("authority2"));
        // our attributes
        let _att1 = String::from("C");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = mke08_request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = mke08_request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        // add attribute sk's to user key
        _u_key._sk_a.push(
            mke08_request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap(),
        );
        _u_key._sk_a.push(
            mke08_request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap(),
        );
        // our plaintext
        let _plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();
        // our policy
        let _policy = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        // cp-abe ciphertext
        let _ct: Mke08Ciphertext =
            mke08_encrypt(&_pk, &vec![_att1_pk, _att2_pk], &_policy, &_plaintext).unwrap();
        // and now decrypt again with mathcing sk
        let _match = mke08_decrypt(&_pk, &_ct, &_u_key, &_policy);
        assert_eq!(_match.is_some(), true);
        assert_eq!(_match.unwrap(), _plaintext);
    }
}
