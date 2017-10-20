// Barreto-Naehrig (BN) curve construction with an efficient bilinear pairing e: G1 × G2 → GT
extern crate bn;
extern crate rand;
extern crate sha3;
extern crate byteorder;

use std::collections::LinkedList;
use std::string::String;
use bn::*;
use sha3::{Digest, Sha3_256};
use byteorder::{ByteOrder, BigEndian};
//use rand::Rng;

pub struct AbePublicKey {
    _h: bn::G2,
    _h1: bn::G2,
    _h2: bn::G2,
    _t1: bn::Gt,
    _t2: bn::Gt,
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

pub struct AbeSecretKeyAttribute {
    _sk_i1: bn::G1,
    _sk_i2: bn::G1,
    _sk_i3: bn::G1,
}

pub struct AbeSecretKey {
    _sk0: Vec<bn::G2>,
    _ski: Vec<AbeSecretKeyAttribute>,
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
    // and compute sk0
    let _sk0_1 = msk._h * (msk._b1 * r1);
    let _sk0_2 = msk._h * (msk._b2 * r2);
    let _sk0_3 = msk._h * (r1 + r2);
    // msp matrix M with size n1xn2
    let n1 = msp._M.len();
    let n2 = msp._M[0].len();
    let mut sgimaPrime: Vec<bn::Fr> = Vec::new();
    // generate 2..n1 random sigma' values
    for x in 2..n2 {
        sgimaPrime.push(Fr::random(rng))
    }
    // sk_i data structure
    let mut sk_i: Vec<Vec<bn::G1>> = Vec::new();

    // for all i=1,...n1 compute
    for i in 1..n1 {
        // sk_i data structure
        let mut sk_it: Vec<bn::G1> = Vec::new();

        // pick random sigma
        let sigma = Fr::random(rng);

        let sk_i1 = G1::one();
        let sk_i2 = G1::one();
        let sk_i3 = G1::one();

        sk_it.push(sk_i1);
        sk_it.push(sk_i2);
        sk_it.push(sk_i3);

        sk_i.push(sk_it);
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

fn bn_hash(str: String) {
    //Precomp. TODO make constants
    let sqrt3 = 3.0_f64.sqrt();
    let j = (-1_f64 + sqrt3) / 2_f64;
    let mut hasher = Sha3_256::default();

    hasher.input(str.as_bytes());
    let hash = hasher.result();
    let t = BigEndian::read_i32(&hash);
    //Main computation
}

pub fn abe_encrypt(
    pk: &AbePublicKey,
    tags: &LinkedList<String>,
    plaintext: &Vec<u8>,
    ciphertext: &mut Vec<u8>,
) -> bool {
    // random number generator
    let rng = &mut rand::thread_rng();

    // generate s1,s2
    let s1 = Fr::random(rng);
    let s2 = Fr::random(rng);

    // calculate ct0
    let h1s1 = pk._h1 * s1;
    let h2s2 = pk._h2 * s2;
    let hs1s2 = pk._h * (s1 + s2);

    let ct0 = (h1s1, h2s2, hs1s2);

    for tag in tags.iter() {
        //TODO calculate ct_tag_x; x in [3]
    }
    return true;
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
    fn test_keygen() {
        let (pk, msk) = abe_setup();
        let mut attrs: LinkedList<String> = LinkedList::new();
        attrs.push_back(String::from("a1"));
        attrs.push_back(String::from("a2"));
        attrs.push_back(String::from("a3"));
        let sk = abe_keygen(&pk, &msk, &attrs);
        assert!(!sk.is_none());
        //assert_ne!(None, sk);
    }
}
