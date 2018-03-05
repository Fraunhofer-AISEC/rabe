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
use policy::DnfPolicy;
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
    pub _e_gg_y: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08MasterKey {
    pub _g1_y: bn::G1,
    pub _g2_y: bn::G2,
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
    pub _gt: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08SecretAttributeKey {
    pub _str: String,
    pub _g1: bn::G1,
    pub _g2: bn::G2,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08Ciphertext {
    pub _c: Vec<(Vec<String>, bn::Gt, bn::G1, bn::G2, bn::G1, bn::G2)>,
    pub _ct: Vec<u8>,
    pub _iv: [u8; 16],
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08UserKey {
    pub _sk_u: Mke08SecretUserKey,
    pub _pk_u: Mke08PublicUserKey,
    pub _sk_a: Vec<Mke08SecretAttributeKey>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08GlobalContext {
    pub _gk: Mke08PublicKey,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct Mke08Context {
    pub _mke: Mke08MasterKey,
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
    let _y_g1 = Fr::random(_rng);
    let _y_g2 = Fr::random(_rng);
    // return PK and MK
    return (
        Mke08PublicKey {
            _g1: _g1,
            _g2: _g2,
            _p1: _p1,
            _p2: _p2,
            _e_gg_y: pairing(_g1, _g2).pow(_y_g1 * _y_g2),
        },
        Mke08MasterKey {
            _g1_y: _g1 * _y_g1,
            _g2_y: _g2 * _y_g2,
        },
    );
}

// user key generation
pub fn mke08_create_user(pk: &Mke08PublicKey, mk: &Mke08MasterKey, user: &String) -> Mke08UserKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    let _mk_u = Fr::random(_rng);
    // return pk_u and sk_u
    return Mke08UserKey {
        _sk_u: Mke08SecretUserKey {
            _sk_g1: mk._g1_y + (pk._p1 * _mk_u),
            _sk_g2: mk._g2_y + (pk._p2 * _mk_u),
        },
        _pk_u: Mke08PublicUserKey {
            _u: user.clone(),
            _pk_g1: pk._g1 * _mk_u,
            _pk_g2: pk._g2 * _mk_u,
        },
        _sk_a: Vec::new(),
    };
}

// authority setup
pub fn mke08_create_authority(pk: &Mke08PublicKey, authority: &String) -> Mke08SecretAuthorityKey {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // return secret authority key
    return Mke08SecretAuthorityKey {
        _a: authority.clone(),
        _r: Fr::random(_rng),
    };
}

// request an attribute PK from an authority
pub fn mke08_request_authority_pk(
    pk: &Mke08PublicKey,
    a: &String,
    sk_a: &Mke08SecretAuthorityKey,
) -> Option<Mke08PublicAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(a, &sk_a._a) {
        let exponent = blake2b_hash_fr(a) + sk_a._r + blake2b_hash_fr(&sk_a._a);
        // return PK and mke
        return Some(Mke08PublicAttributeKey {
            _str: a.clone(),
            _g1: pk._g1 * exponent,
            _g2: pk._g2 * exponent,
            _gt: pk._e_gg_y.pow(exponent * exponent),
        });
    } else {
        return None;
    }
}

// request an attribute PK from an authority
pub fn mke08_request_authority_sk(
    a: &String,
    sk_a: &Mke08SecretAuthorityKey,
    pk_u: &Mke08PublicUserKey,
) -> Option<Mke08SecretAttributeKey> {
    // if attribute a is from authority sk_a
    if from_authority(a, &sk_a._a) && is_eligible(a, &pk_u._u) {
        let exponent = blake2b_hash_fr(a) + sk_a._r + blake2b_hash_fr(&sk_a._a);
        // return PK and mke
        return Some(Mke08SecretAttributeKey {
            _str: a.clone(),
            _g1: pk_u._pk_g1 * exponent,
            _g2: pk_u._pk_g2 * exponent,
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
        // random Gt msg
        let _msg = pairing(G1::random(_rng), G2::random(_rng));
        println!("ENCRYPT: {:?}", into_hex(_msg).unwrap());
        // CT result vector
        let mut _c: Vec<(Vec<String>, bn::Gt, bn::G1, bn::G2, bn::G1, bn::G2)> = Vec::new();
        // now add randomness using _r_j
        for _term in dnf._terms {
            let _r_j = Fr::random(_rng);
            _c.push((
                _term.0,
                _term.1.pow(_r_j * _r_j) * _msg,
                _pk._p1 * _r_j,
                _pk._p2 * _r_j,
                _term.2 * _r_j,
                _term.3 * _r_j,
            ));
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
                    _c: _c,
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
        let mut _msg = Gt::zero();
        for _ct in _ct._c.iter() {
            println!("conjunction: {:?}", &_ct.0);
            if is_satisfiable(&_ct.0, &_sk._sk_a) {
                let _sk_sum = calc_satisfiable(&_ct.0, &_sk._sk_a);
                _msg = _ct.1 * (pairing(_ct.2, _sk_sum.1) * pairing(_sk_sum.0, _ct.3)) *
                    (pairing(_ct.4, _sk._sk_u._sk_g2) * pairing(_sk._sk_u._sk_g1, _ct.5)).inverse();
                break;
            }
        }
        println!("DECRYPT1: {:?}", into_hex(_msg).unwrap());
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
        // user1
        let _u = String::from("user1");
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = mke08_create_user(&_pk, &_msk, &_u);
        // authority1
        let _a1 = String::from("authority1");
        let _a1_key = mke08_create_authority(&_pk, &_a1);
        // authority2
        let _a2 = String::from("authority2");
        let _a2_key = mke08_create_authority(&_pk, &_a2);
        // our attributes
        let _att1 = String::from("A");
        let _att2 = String::from("B");
        // authority1 owns A
        let _att1_pk = mke08_request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = mke08_request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        // get "A"'s secret key from authority1
        let _att1_u_sk = mke08_request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap();
        // get "B"'s secret key from authority2
        let _att2_u_sk = mke08_request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap();
        // add attribute sk's to user key
        _u_key._sk_a.push(_att1_u_sk);
        _u_key._sk_a.push(_att2_u_sk);


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
        // user1
        let _u = String::from("user1");
        // generate mutable user key(in order to add attribute sk's later on)
        let mut _u_key = mke08_create_user(&_pk, &_msk, &_u);
        // authority1
        let _a1 = String::from("authority1");
        let _a1_key = mke08_create_authority(&_pk, &_a1);
        // authority2
        let _a2 = String::from("authority2");
        let _a2_key = mke08_create_authority(&_pk, &_a2);
        // our attributes
        let _att1 = String::from("B");
        let _att2 = String::from("C");
        // authority1 owns A
        let _att1_pk = mke08_request_authority_pk(&_pk, &_att1, &_a1_key).unwrap();
        // authority2 owns B
        let _att2_pk = mke08_request_authority_pk(&_pk, &_att2, &_a2_key).unwrap();
        // get "A"'s secret key from authority1
        let _att1_u_sk = mke08_request_authority_sk(&_att1, &_a1_key, &_u_key._pk_u).unwrap();
        // get "B"'s secret key from authority2
        let _att2_u_sk = mke08_request_authority_sk(&_att2, &_a2_key, &_u_key._pk_u).unwrap();
        // add attribute sk's to user key
        _u_key._sk_a.push(_att1_u_sk);
        _u_key._sk_a.push(_att2_u_sk);


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
