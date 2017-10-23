// Barreto-Naehrig (BN) curve construction with an efficient bilinear pairing e: G1 × G2 → GT
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate tiny_keccak;

use std::collections::LinkedList;
use std::string::String;
use std::str;
use bn::*;
use tiny_keccak::Keccak;
//use byteorder::{ByteOrder, BigEndian};
//use rand::Rng;

pub struct AbePublicKey {
    _h: bn::G2,
    _h1: bn::G2,
    _h2: bn::G2,
    _t1: bn::Gt,
    _t2: bn::Gt,
}

pub struct AbeAttribute {
    _a1: bn::G1,
    _a2: bn::G1,
    _a3: bn::G1,
}

pub struct AbeCiphertext {
    _ct_0: (bn::G2, bn::G2, bn::G2),
    _ct_prime: bn::Gt,
    _ct_y: Vec<AbeAttribute>,
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
    _sk0: Vec<bn::G2>,
    _ski: Vec<AbeAttribute>,
}

pub struct MSP {
    _M: Vec<Vec<bn::Fr>>,
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

pub fn abe_keygen(
    msk: &AbeMasterKey,
    msp: &MSP,
    attributes: &LinkedList<String>,
) -> Option<AbeSecretKey> {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate random r1 and r2
    let r1 = Fr::random(rng);
    let r2 = Fr::random(rng);
    // msp matrix M with size n1xn2
    let n1 = msp._M.len();
    let n2 = msp._M[0].len();
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
    // for all i=1,...n1 compute
    for i in 1..n1 {
        // sk_i data structure
        let mut sk_i: Vec<Vec<bn::G1>> = Vec::new();
        // sk_i_{1,2,3} data structure
        let mut sk_i_t: Vec<bn::G1> = Vec::new();
        // pick random sigma
        let sigma = Fr::random(rng);
        // calculate sk_{i,3}
        let mut sk_i3 = G1::one();
        for j in 2..n2 {
            sk_i3 = sk_i3 + ((msk._g * -sgima_prime[j]) * msp._M[i][j]);
        }
        sk_i3 = sk_i3 + (msk._g_d3 * msp._M[i][0]) + (msk._g * (-sigma));
        // calculate sk_{i,1} and sk_{i,2}
        //let h1 = element_from_hash();

        let sk_i1 = (msk._g * (sigma * msk._a1.inverse().unwrap())) + (msk._g_d1 * msp._M[i][0]);
        let sk_i2 = (msk._g * (sigma * msk._a2.inverse().unwrap())) + (msk._g_d2 * msp._M[i][0]);


        sk_i_t.push(sk_i1);
        sk_i_t.push(sk_i2);
        sk_i_t.push(sk_i3);
        sk_i.push(sk_i_t);
    }
    // now generate sk key
    /*let sk = AbeSecretKey {
        _sk0: [_sk0_1, _sk0_2, _sk0_3].to_Vec(),
        _ski: [],
    };*/

    for str in attributes.iter() {
        print!("{}", str);
    }
    return None;
}

pub fn element_from_hash(text: &String) -> bn::G1 {
    // create a SHA3-256 object
    let mut sha3 = Keccak::new_sha3_256();
    // update sha with message
    sha3.update(text.as_bytes());
    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);
    println!("SHA3 Result: {:?}", res);
    return G1::one() * Fr::from_str("1234").unwrap();
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
    let mut _ct_yl: Vec<AbeAttribute> = Vec::new();
    for _tag in tags.iter() {
        let _attribute = AbeAttribute {
            _a1: element_from_hash(_tag),
            _a2: element_from_hash(_tag),
            _a3: element_from_hash(_tag),
        };
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
    use element_from_hash;
    use AbePublicKey;
    use AbeMasterKey;
    use std::collections::LinkedList;
    use std::string::String;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
    #[test]
    fn test_setup() {
        let (pk, msk) = abe_setup();
    }
    #[test]
    fn test_element_to_hash() {
        let s1 = String::from("hashing");
        let s2 = String::from("to an");
        let s3 = String::from("element");
        let point1 = element_from_hash(&s1);
        let point2 = element_from_hash(&s2);
        let point3 = element_from_hash(&s3);
        //println!("{:?}", point1);
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
