// no serde traits until now
//#[macro_use]
//extern crate serde_derive;

extern crate serde;
extern crate serde_json;

extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate rustc_serialize;
extern crate num_bigint;

use std::collections::LinkedList;
use std::string::String;
use std::str;
use num_bigint::BigInt;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
//use rustc_serialize::{Encodable, Decodable};
//use rustc_serialize::hex::{FromHex, ToHex};
//use byteorder::{ByteOrder, BigEndian};
//use rand::Rng;

// Barreto-Naehrig (BN) curve construction with an efficient bilinear pairing e: G1 × G2 → GT

pub struct AbePublicKey {
    _h: bn::G2,
    _h1: bn::G2,
    _h2: bn::G2,
    _t1: bn::Gt,
    _t2: bn::Gt,
}

pub struct AbeCiphertext {
    _ct_0: (bn::G2, bn::G2, bn::G2),
    _ct_prime: bn::Gt,
    _ct_y: Vec<(bn::G1, bn::G1, bn::G1)>,
}

pub struct AbeMasterKey {
    _g: bn::G1,
    _h: bn::G2,
    _a1: bn::Fr,
    _a2: bn::Fr,
    _b1: bn::Fr,
    _b2: bn::Fr,
    _g_d1: bn::G1,
    _g_d2: bn::G1,
    _g_d3: bn::G1,
}

pub struct AbeSecretKey {
    _sk0: (bn::G2, bn::G2, bn::G2),
    _ski: Vec<(bn::G1, bn::G1, bn::G1)>,
}

pub struct MSP {
    m: Vec<Vec<bn::Fr>>,
    pi: Vec<String>,
    deg: usize
}

pub fn abe_setup() -> (AbePublicKey, AbeMasterKey) {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let g = G1::one();
    let h = G2::one();
    // generate a1,a2 from Z*_p (* means it must not be null, can we be sure?)
    let a1 = Fr::random(rng);
    let a2 = Fr::random(rng);
    // generate d1,d2,d3 from Z_p
    let d1 = Fr::random(rng);
    let d2 = Fr::random(rng);
    let d3 = Fr::random(rng);
    // calculate h^a1 and h^a2
    let h1 = h * a1;
    let h2 = h * a2;
    // calculate pairing for T1 and T2
    let t1 = pairing(g, h).pow(d1 * a1 + d3);
    let t2 = pairing(g, h).pow(d2 * a2 + d3);
    // set values of PK
    let pk = AbePublicKey {
        _h: h,
        _h1: h1,
        _h2: h2,
        _t1: t1,
        _t2: t2,
    };
    // generate b1,b2 from Z*_p (*means it must not be null, can we be sure?)
    let b1 = Fr::random(rng);
    let b2 = Fr::random(rng);
    // calculate g^d1, g^d2, g^d3
    let g_b1 = g * d1;
    let g_b2 = g * d2;
    let g_b3 = g * d3;
    // set values of MSK
    let msk = AbeMasterKey {
        _g: g,
        _h: h,
        _a1: a1,
        _a2: a2,
        _b1: b1,
        _b2: b2,
        _g_d1: g_b1,
        _g_d2: g_b2,
        _g_d3: g_b3,
    };
    // return pk and msk
    return (pk, msk);
}

pub fn abe_keygen(msk: &AbeMasterKey, msp: &MSP, attributes: &LinkedList<String>) -> AbeSecretKey {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate random r1 and r2
    let r1 = Fr::random(rng);
    let r2 = Fr::random(rng);
    // msp matrix M with size n1xn2
    let n1 = msp.m.len();
    let n2 = msp.m[0].len();
    // data structure for random sigma' values
    let mut sgima_prime: Vec<bn::Fr> = Vec::new();
    // generate 2..n1 random sigma' values
    for _i in 2..n2 {
        sgima_prime.push(Fr::random(rng))
    }
    // and compute sk0
    let _sk_0 = (
        msk._h * (msk._b1 * r1),
        msk._h * (msk._b2 * r2),
        msk._h * (r1 + r2),
    );
    // sk_i data structure
    let mut sk_i: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    // for all i=1,...n1 compute
    for i in 1..n1 {
        // pick random sigma
        let sigma = Fr::random(rng);
        // calculate sk_{i,3}
        let mut sk_i3 = G1::one();
        for j in 2..n2 {
            sk_i3 = sk_i3 + ((msk._g * -sgima_prime[j]) * msp.m[i][j]);
        }
        sk_i3 = sk_i3 + (msk._g_d3 * msp.m[i][0]) + (msk._g * (-sigma));
        // calculate sk_{i,1} and sk_{i,2}
        let mut sk_i1 = G1::one();
        let mut sk_i2 = G1::one();
        for j in 2..n2 {
            sk_i1 = sk_i1 +
                (((hash_to_element(b"todo") * (msk._b1 * r1 * msk._a1.inverse().unwrap())) +
                      (hash_to_element(b"todo") * (msk._b2 * r2 * msk._a1.inverse().unwrap())) +
                      (hash_to_element(b"todo") * ((r1 + r2) * msk._a1.inverse().unwrap())) +
                      (msk._g * (-sgima_prime[j] * msk._a1.inverse().unwrap()))) *
                     msp.m[i][j]);
            sk_i2 = sk_i2 +
                (((hash_to_element(b"todo") * (msk._b1 * r1 * msk._a2.inverse().unwrap())) +
                      (hash_to_element(b"todo") * (msk._b2 * r2 * msk._a2.inverse().unwrap())) +
                      (hash_to_element(b"todo") * ((r1 + r2) * msk._a2.inverse().unwrap())) +
                      (msk._g * (-sgima_prime[j] * msk._a2.inverse().unwrap()))) *
                     msp.m[i][j]);
        }
        sk_i1 = sk_i1 + (hash_to_element(b"todo") * (msk._b1 * r1 * msk._a1.inverse().unwrap())) +
            (hash_to_element(b"todo") * (msk._b2 * r2 * msk._a1.inverse().unwrap())) +
            (hash_to_element(b"todo") * ((r1 + r2) * msk._a1.inverse().unwrap())) +
            (msk._g * (sigma * msk._a1.inverse().unwrap())) +
            (msk._g_d1 * msp.m[i][0]);

        sk_i2 = sk_i2 + (hash_to_element(b"todo") * (msk._b1 * r1 * msk._a2.inverse().unwrap())) +
            (hash_to_element(b"todo") * (msk._b2 * r2 * msk._a2.inverse().unwrap())) +
            (hash_to_element(b"todo") * ((r1 + r2) * msk._a2.inverse().unwrap())) +
            (msk._g * (sigma * msk._a2.inverse().unwrap())) +
            (msk._g_d2 * msp.m[i][0]);
        sk_i.push((sk_i1, sk_i2, sk_i3));
    }
    // now generate sk key
    let sk = AbeSecretKey {
        _sk0: _sk_0,
        _ski: sk_i,
    };
    for str in attributes.iter() {
        print!("attribute: {}", str);
    }
    return sk;
}

pub fn hash_to_element(data: &[u8]) -> bn::G1 {
    let mut sha = Sha3::sha3_256();
    sha.input(data);
    let i = BigInt::parse_bytes(sha.result_str().as_bytes(), 16).unwrap();
    return G1::one() * Fr::from_str(&i.to_str_radix(10)).unwrap();
}


pub fn hash_string_to_element(text: &String) -> bn::G1 {
    return hash_to_element(text.as_bytes());
}

fn lw(msp: &mut MSP, p: &serde_json::Value, v: Vec<bn::Fr>, c: &mut usize) {
    let mut v_tmp_left = Vec::new();
    let mut v_tmp_right = v.clone();
    
   if *p == serde_json::Value::Null {
       println!("Error passed null!");
       return;
   }

    //Leaf
    if (p["ATT"] != serde_json::Value::Null) {
        msp.m.insert(0, v_tmp_right);
        match p["ATT"].as_str() {
          Some(s) => msp.pi.insert(0, String::from(s)),
          None => println!("ERROR attribute value"),
        }
        if (msp.deg < *c) {
            msp.deg = *c;
        }
        return;
    }


    if (p["OR"] != serde_json::Value::Null) {
        println!("found OR");
        v_tmp_left = v.clone();
    } else {
        println!("found AND");
        *c = *c + 1;
        v_tmp_right.resize(*c - 1, bn::Fr::zero());
        v_tmp_right.push(bn::Fr::one());
        v_tmp_left.resize(*c - 1 , bn::Fr::zero());
        v_tmp_left.push(bn::Fr::zero() - bn::Fr::one());
    }

    if (p["OR"] != serde_json::Value::Null) {
        lw(msp, &p["OR"][0], v_tmp_right, c);
        lw(msp, &p["OR"][1], v_tmp_left, c);
    } else {
        lw(msp, &p["AND"][0], v_tmp_right, c);
        lw(msp, &p["AND"][1], v_tmp_left, c);
    }
}

pub fn policy_to_msp(data: &[u8], mut msp: &mut MSP) -> bool {
    let pol = serde_json::from_str(str::from_utf8(data).unwrap()).unwrap();
    let mut v: Vec<bn::Fr> = Vec::new();
    v.push (bn::Fr::one());
    let mut c = 1;
    lw (&mut msp, &pol, v, &mut c);
    for mut p in &mut msp.m {
      p.resize(msp.deg, bn::Fr::zero());
    }
    return true;
}

pub fn abe_encrypt(
    pk: &AbePublicKey,
    tags: &LinkedList<String>,
    plaintext: bn::Gt,
    ) -> Option<AbeCiphertext> {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate s1,s2
    let s1 = Fr::random(rng);
    let s2 = Fr::random(rng);
    let mut _ct_yl: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    for _tag in tags.iter() {
        let _attribute: (bn::G1, bn::G1, bn::G1) = (
            hash_string_to_element(_tag),
            hash_string_to_element(_tag),
            hash_string_to_element(_tag),
            );
        _ct_yl.push(_attribute);
    }
    let ct = AbeCiphertext {
        _ct_0: (pk._h1 * s1, pk._h2 * s2, pk._h * (s1 + s2)),
        _ct_prime: (pk._t1.pow(s1) * pk._t1.pow(s2) * plaintext),
        _ct_y: _ct_yl,
    };
    return None;
}

pub fn abe_decrypt(
    pk: &AbePublicKey,
    sk: &AbeSecretKey,
    ciphertext: &Vec<u8>,
    plaintext: &mut Vec<u8>,
    ) -> bool {
    return true;
}

pub fn abe_public_key_serialize(pk: &AbePublicKey, pk_serialized: &mut Vec<u8>) -> bool {
    return true;
}

pub fn abe_public_key_deserialize(pk_data: &Vec<u8>) -> Option<AbePublicKey> {
    return None;
}

#[cfg(test)]
mod tests {
    use abe_setup;
    use abe_keygen;
    use hash_string_to_element;
    use policy_to_msp;
    use AbePublicKey;
    use AbeMasterKey;
    use MSP;
    use Fr;
    use std::collections::LinkedList;
    use std::string::String;
    use bn::*;
    use bincode::SizeLimit::Infinite;
    use bincode::rustc_serialize::{encode, decode};
    use rustc_serialize::{Encodable, Decodable};
    use rustc_serialize::hex::{FromHex, ToHex};


    pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
        encode(&obj, Infinite).ok().map(|e| e.to_hex())
    }

    pub fn from_hex<S: Decodable>(s: &str) -> Option<S> {
        let s = s.from_hex().unwrap();
        decode(&s).ok()
    }


    #[test]
    fn test_setup() {
        let (pk, msk) = abe_setup();
    }

    #[test]
    fn test_hash() {
        let s1 = String::from("hashing");
        let point1 = hash_string_to_element(&s1);
        let expected_str: String = into_hex(point1).unwrap();
        println!("Expected: {:?}", expected_str); // print msg's during test: "cargo test -- --nocapture"
        assert_eq!(
            "0403284c4eb462be32679deba32fa662d71bb4ba7b1300f7c8906e1215e6c354aa0d973373c26c7f2859c2ba7a0656bc59a79fa64cb3a5bbe99cf14d0f0f08ab46",
            into_hex(point1).unwrap()
            );

    }
    #[test]
    fn test_to_msp() {
        let policy = r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}]}"#;
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let mut _msp = MSP {
            m: _values,
            pi: _attributes,
            deg: 1
        };
        assert!(Fr::zero() == (Fr::one() + (Fr::zero() - Fr::one())));
        policy_to_msp(policy.as_bytes(), &mut _msp);
        for p in _msp.m {
            print!("|");
            for x in &p {
                print!("{}|", into_hex(x).unwrap());
            }
            println!("\n");
        }
    }
    #[test]
    fn test_keygen() {
        let (pk, msk) = abe_setup();
        let mut attrs: LinkedList<String> = LinkedList::new();
        attrs.push_back(String::from("a1"));
        attrs.push_back(String::from("a2"));
        attrs.push_back(String::from("a3"));
        //let sk = abe_keygen(&pk, &msk, &attrs);
        //assert!(!sk.is_none());
        //assert_ne!(None, sk);
    }
}
