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
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use bincode::SizeLimit::Infinite;
//use bincode::rustc_serialize::{encode, decode};
use bincode::rustc_serialize::encode;
//use rustc_serialize::{Encodable, Decodable};
//use rustc_serialize::hex::{FromHex, ToHex};
use rustc_serialize::hex::ToHex;
//use byteorder::{ByteOrder, BigEndian};
use rand::Rng;
use policy::AbePolicy;

mod policy;

// Barreto-Naehrig (BN) curve construction with an efficient bilinear pairing e: G1 × G2 → GT

//#[doc = /**
// * TODO
// * - Put everything in a module (?)
// * - Encrypt/Decrypt
// * - Serialization, bn::Gt is not serializable :(((
// *
// */]
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbePublicKey {
    _h: bn::G2,
    _hn: Vec<(bn::G2)>,
    _tn: Vec<(bn::Gt)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeCiphertext {
    _ct_0: (bn::G2, bn::G2, bn::G2),
    _ct_prime: bn::Gt,
    _ct_y: Vec<(bn::G1, bn::G1, bn::G1)>,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeMasterKey {
    _g: bn::G1,
    _h: bn::G2,
    _a: Vec<(bn::Fr)>,
    _b: Vec<(bn::Fr)>,
    _d: Vec<(bn::Fr)>,
}

pub struct AbeSecretKey {
    _sk0: (bn::G2, bn::G2, bn::G2),
    _ski: Vec<(bn::G1, bn::G1, bn::G1)>,
}

impl AbePolicy {
    pub fn from_string(policy: String) -> Option<AbePolicy> {
        policy::string_to_msp(policy)
    }
    pub fn from_json(json: &serde_json::Value) -> Option<AbePolicy> {
        policy::json_to_msp(json)
    }
}

pub fn abe_setup() -> (AbePublicKey, AbeMasterKey) {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let g = G1::one();
    let h = G2::one();
    // vec's msk and pk
    let mut _msk_a: Vec<(bn::Fr)> = Vec::new();
    let mut _msk_b: Vec<(bn::Fr)> = Vec::new();
    let mut _msk_d: Vec<(bn::Fr)> = Vec::new();
    let mut _pk_hn: Vec<(bn::G2)> = Vec::new();
    let mut _pk_tn: Vec<(bn::Gt)> = Vec::new();
    // generate d1,d2 and d3 from Z_p (* means it must not be null, can we be sure?)
    let d1 = Fr::random(rng);
    let d2 = Fr::random(rng);
    let d3 = Fr::random(rng);
    // generate a1,a2 from Z*_p (* means it must not be null, can we be sure?)
    let a1 = Fr::random(rng);
    let a2 = Fr::random(rng);
    // push into vecs
    _msk_a.push(a1);
    _msk_a.push(a2);
    // generate random b1,b2 from Z_p and push into vec b
    _msk_b.push(Fr::random(rng));
    _msk_b.push(Fr::random(rng));
    // generate g^d1, g^d2 and g^d3
    _msk_d.push(d1);
    _msk_d.push(d2);
    _msk_d.push(d3);
    // calculate h^a1 and h^a2 and push into vec hn
    _pk_hn.push(h * a1);
    _pk_hn.push(h * a2);
    // calculate pairing for T1 and T2
    _pk_tn.push(pairing(g, h).pow(d1 * a1 + d3));
    _pk_tn.push(pairing(g, h).pow(d2 * a2 + d3));
    // set values of PK
    let pk = AbePublicKey {
        _h: h,
        _hn: _pk_hn,
        _tn: _pk_tn,
    };
    let msk = AbeMasterKey {
        _g: g,
        _h: h,
        _a: _msk_a,
        _b: _msk_b,
        _d: _msk_d,
    };
    // return pk and msk
    return (pk, msk);
}

pub fn abe_keygen(
    msk: &AbeMasterKey,
    msp: &AbePolicy,
    attributes: &LinkedList<String>,
) -> Option<AbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk als here
    if attributes.is_empty() || msp._m.is_empty() || msp._m.len() == 0 || msp._m[0].len() == 0 {
        return None;
    }
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate random r1 and r2
    let r1 = Fr::random(rng);
    let r2 = Fr::random(rng);
    // msp matrix M with size n1xn2
    let n1 = msp._m.len();
    let n2 = msp._m[0].len();
    // data structure for random sigma' values
    let mut sgima_prime: Vec<bn::Fr> = Vec::new();
    // generate 2..n1 random sigma' values
    for _i in 2..n2 {
        sgima_prime.push(Fr::random(rng))
    }
    // and compute sk0
    let _sk_0 = (
        msk._h * (msk._b[0] * r1),
        msk._h * (msk._b[1] * r2),
        msk._h * (r1 + r2),
    );
    // sk_i data structure
    let mut sk_i: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    // for all i=1,...n1 compute
    for i in 1..n1 {
        // vec to collect triples in loop
        let mut sk_triple: Vec<(bn::G1)> = Vec::new();
        // pick random sigma
        let sigma = Fr::random(rng);
        // calculate sk_{i,1} and sk_{i,2}
        let mut sk_it = G1::one();
        for t in 1..2 {
            let current_t: usize = t - 1;
            let at = msk._a[current_t];
            // calculate the first part of the sk_it term for sk_{i,1} and sk_{i,2}
            sk_it = sk_it +
                (hash_to_element(combine_string(&msp._pi[i - 1], 1, t as u32).as_bytes()) *
                     (msk._b[0] * r1 * at.inverse().unwrap())) +
                (hash_to_element(combine_string(&msp._pi[i - 1], 2, t as u32).as_bytes()) *
                     (msk._b[1] * r2 * at.inverse().unwrap())) +
                (hash_to_element(combine_string(&msp._pi[i - 1], 3, t as u32).as_bytes()) *
                     ((r1 + r2) * at.inverse().unwrap())) +
                msk._g * (sigma * at.inverse().unwrap()) +
                (msk._g * (msk._d[current_t])) * msp._m[i - 1][0];

            // now calculate the product over j=2 until n2 for sk_it in a loop
            for j in 2..n2 {
                sk_it = sk_it +
                    (hash_to_element(combine_string(&j.to_string(), 1, t as u32).as_bytes()) *
                         (msk._b[0] * r1 * at.inverse().unwrap()) +
                         hash_to_element(
                            combine_string(&j.to_string(), 2, t as u32).as_bytes(),
                        ) * (msk._b[1] * r2 * at.inverse().unwrap()) +
                         hash_to_element(
                            combine_string(&j.to_string(), 3, t as u32).as_bytes(),
                        ) * ((r1 + r2) * at.inverse().unwrap()) +
                         (msk._g * (sgima_prime[j - 2] * at.inverse().unwrap()))) *
                        msp._m[i - 1][j - 1];
            }
            sk_triple.push(sk_it);
        }
        // calculate sk_{i,3}
        let mut sk_i3 = G1::one();
        for j in 2..n2 {
            sk_i3 = sk_i3 + ((msk._g * -sgima_prime[j]) * msp._m[i][j]);
        }
        sk_i3 = sk_i3 + ((msk._g * msk._d[2]) * msp._m[i][0]) + (msk._g * (-sigma));
        // and push it in vec
        sk_triple.push(sk_i3);
        // now push all three values into sk_i vec
        sk_i.push((sk_triple[0], sk_triple[1], sk_triple[2]));
    }
    // output string attributes
    for str in attributes.iter() {
        print!("attributes in new key: {}", str);
    }
    return Some(AbeSecretKey {
        _sk0: _sk_0,
        _ski: sk_i,
    });
}

pub fn combine_string(text: &String, j: u32, t: u32) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    _combined.push_str(&t.to_string());
    return _combined.to_string();
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

fn encrypt_aes(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn abe_encrypt(
    pk: &AbePublicKey,
    tags: &LinkedList<String>,
    plaintext: &Vec<u8>,
) -> Option<AbeCiphertext> {
    if tags.is_empty() || plaintext.is_empty() {
        return None;
    }
    // random number generator
    let rng = &mut rand::thread_rng();
    //Choose random secret
    let secret = pairing(G1::random(rng), G2::random(rng));
    // generate s1,s2
    let s1 = Fr::random(rng);
    let s2 = Fr::random(rng);
    let mut _ct_yl: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    for _tag in tags.iter() {
        let _attribute: (bn::G1, bn::G1, bn::G1) =
            (
                hash_string_to_element(&combine_string(&_tag, 1, 1)) * s1 +
                    hash_string_to_element(&combine_string(&_tag, 1, 2)) * s2,
                hash_string_to_element(&combine_string(&_tag, 2, 1)) * s1 +
                    hash_string_to_element(&combine_string(&_tag, 2, 2)) * s2,
                hash_string_to_element(&combine_string(&_tag, 3, 1)) * s1 +
                    hash_string_to_element(&combine_string(&_tag, 3, 2)) * s2,
            );
        _ct_yl.push(_attribute);
    }
    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&secret, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            rng.fill_bytes(&mut iv);
            let ct = AbeCiphertext {
                _ct_0: (pk._hn[0] * s1, pk._hn[1] * s2, pk._h * (s1 + s2)),
                _ct_prime: (pk._tn[0].pow(s1) * pk._tn[0].pow(s2) * secret),
                _ct_y: _ct_yl,
                _ct: encrypt_aes(plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
fn decrypt_aes(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn abe_decrypt(sk: &AbeSecretKey, ct: &AbeCiphertext) -> Option<Vec<u8>> {
    let mut _ct = (bn::G1::one(), bn::G1::one(), bn::G1::one());
    let mut _sk = (bn::G1::one(), bn::G1::one(), bn::G1::one());
    for ct_i in ct._ct_y.iter() {
        _ct = (_ct.0 + ct_i.0, _ct.1 + ct_i.1, _ct.2 + ct_i.2);
    }
    for sk_i in sk._ski.iter() {
        _sk = (_sk.0 + sk_i.0, _sk.1 + sk_i.1, _sk.2 + sk_i.2);
    }
    let num = ct._ct_prime * pairing(_ct.0, sk._sk0.0) * pairing(_ct.1, sk._sk0.1) *
        pairing(_ct.2, sk._sk0.2);
    let den = pairing(_sk.0, ct._ct_0.0) * pairing(_sk.1, ct._ct_0.1) * pairing(_sk.2, ct._ct_0.2);
    let secret = num * den.inverse();
    // Decrypt plaintext using derived secret from abe scheme
    let mut sha = Sha3::sha3_256();
    match encode(&secret, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            return Some(decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use abe_setup;
    use abe_keygen;
    use hash_string_to_element;
    use combine_string;
    use AbePublicKey;
    use AbeMasterKey;
    use AbePolicy;
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
        // assert generators
        assert_eq!(into_hex(msk._h).unwrap(), into_hex(pk._h).unwrap());
        assert_eq!(
            into_hex(msk._h).unwrap(),
            "0404d4bf3239f77cee7b47c7245e9281b3e9c1182d6381a87bbf81f9f2a6254b731df569cda95e060bee91ba69b3f2d103658a7aea6b10e5bdc761e5715e7ee4bb01b4c328f0cbdb4aada63b3d09100d792376b94d07a6004e46054eeec849e8de9835158a11d28483dd8db236ea49f3630edc9e41944e494c5aacfc36af3b66e7"
        );
        assert_eq!(
            into_hex(msk._g).unwrap(),
            "0400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"
        );
        println!("g: {:?}", into_hex(msk._h).unwrap());
        println!("h: {:?}", into_hex(msk._g).unwrap());
        // assert random values a
        let hn0 = into_hex(msk._h * msk._a[0]).unwrap();
        let hn1 = into_hex(msk._h * msk._a[1]).unwrap();
        assert_eq!(hn0, into_hex(pk._hn[0]).unwrap());
        assert_eq!(hn1, into_hex(pk._hn[1]).unwrap());
        // assert random values d with pairing e
        let p1 = into_hex(pairing(
            msk._g * ((msk._d[0] * msk._a[0]) + msk._d[2]),
            msk._h,
        )).unwrap();
        assert_eq!(p1, into_hex(pk._tn[0]).unwrap());
        let p2 = into_hex(pairing(
            msk._g,
            msk._h * ((msk._d[1] * msk._a[1]) + msk._d[2]),
        )).unwrap();
        assert_eq!(p2, into_hex(pk._tn[1]).unwrap());
    }

    #[test]
    fn test_combine_string() {
        let s1 = String::from("hashing");
        let u2: u32 = 1;
        let u3: u32 = 2;
        let _combined = combine_string(&s1, u2, u3);
        assert_eq!(_combined, String::from("hashing12"));
    }

    #[test]
    fn test_hash() {
        let s1 = String::from("hashing");
        let point1 = hash_string_to_element(&s1);
        let expected_str: String = into_hex(point1).unwrap();
        //println!("Expected: {:?}", expected_str); // print msg's during test: "cargo test -- --nocapture"
        assert_eq!(
            "0403284c4eb462be32679deba32fa662d71bb4ba7b1300f7c8906e1215e6c354aa0d973373c26c7f2859c2ba7a0656bc59a79fa64cb3a5bbe99cf14d0f0f08ab46",
            into_hex(point1).unwrap()
        );
    }

    #[test]
    fn test_to_msp() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let p1 = vec![Fr::zero(), Fr::zero(), Fr::zero() - Fr::one()];
        let p2 = vec![Fr::one(), Fr::zero(), Fr::one()];
        let p3 = vec![Fr::zero(), Fr::zero() - Fr::one(), Fr::zero()];
        let p4 = vec![Fr::one(), Fr::one(), Fr::zero()];
        let mut _msp_test = AbePolicy {
            _m: vec![p1, p2, p3, p4],
            _pi: vec![
                String::from("A"),
                String::from("B"),
                String::from("A"),
                String::from("C"),
            ],
            _deg: 3,
        };
        assert!(Fr::zero() == (Fr::one() + (Fr::zero() - Fr::one())));
        match AbePolicy::from_string(policy) {
            None => assert!(false),
            Some(_msp) => {
                for i in 0..4 {
                    let p = &_msp._m[i];
                    let p_test = &_msp_test._m[i];
                    for j in 0..3 {
                        assert!(p[j] == p_test[j]);
                    }
                }
                assert!(_msp_test._deg == _msp._deg);
            }
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
