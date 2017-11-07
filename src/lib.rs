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
use num_bigint::BigInt;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use bincode::SizeLimit::Infinite;
//use bincode::rustc_serialize::{encode, decode};
use bincode::rustc_serialize::encode;
use rustc_serialize::Encodable;
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
    _h_n: Vec<(bn::G2)>,
    _t_n: Vec<(bn::Gt)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeMasterKey {
    _g: bn::G1,
    _h: bn::G2,
    _a: Vec<(bn::Fr)>,
    _b: Vec<(bn::Fr)>,
    _d: Vec<(bn::G1)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeCiphertext {
    _ct_0: Vec<(bn::G2)>,
    _ct_y: Vec<(bn::G1, bn::G1, bn::G1)>,
    _ct_prime: bn::Gt,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

pub struct CpAbeSecretKey {
    _sk_0: Vec<(bn::G2)>,
    _sk_y: Vec<(bn::G1, bn::G1, bn::G1)>,
    _sk_t: Vec<(bn::G1)>,
}

pub struct KpAbeSecretKey {
    _sk_0: Vec<(bn::G2)>,
    _sk_y: Vec<(bn::G1, bn::G1, bn::G1)>,
}

impl AbePolicy {
    pub fn from_string(policy: String) -> Option<AbePolicy> {
        policy::string_to_msp(policy)
    }
    pub fn from_json(json: &serde_json::Value) -> Option<AbePolicy> {
        policy::json_to_msp(json)
    }
}

// BOTH SHARE

pub fn abe_setup() -> (AbePublicKey, AbeMasterKey) {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let g = G1::random(rng);
    let h = G2::random(rng);
    // vec's msk and pk
    let mut _msk_a: Vec<(bn::Fr)> = Vec::new();
    let mut _msk_b: Vec<(bn::Fr)> = Vec::new();
    let mut _msk_d: Vec<(bn::G1)> = Vec::new();
    let mut _pk_hn: Vec<(bn::G2)> = Vec::new();
    let mut _pk_tn: Vec<(bn::Gt)> = Vec::new();
    // generate d1,d2 and d3 from Z_p (* means it must not be null, can we be sure?)
    // TODO: check in lib if Fr::random(rng) can produce zero or not at all
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
    _msk_d.push(g * d1);
    _msk_d.push(g * d2);
    _msk_d.push(g * d3);
    // calculate h^a1 and h^a2 and push into vec hn
    _pk_hn.push(h * a1);
    _pk_hn.push(h * a2);
    // calculate pairing for T1 and T2
    _pk_tn.push(pairing(g, h).pow(d1 * a1 + d3));
    _pk_tn.push(pairing(g, h).pow(d2 * a2 + d3));
    // set values of PK
    let pk = AbePublicKey {
        _h: h,
        _h_n: _pk_hn,
        _t_n: _pk_tn,
    };
    // set values of MSK
    let msk = AbeMasterKey {
        _g: g,
        _h: h,
        _a: _msk_a,
        _b: _msk_b,
        _d: _msk_d,
    };
    // return PK and MSK
    return (pk, msk);
}

// CP ABE PART

pub fn cpabe_keygen(msk: &AbeMasterKey, s: &LinkedList<String>) -> Option<CpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if s.is_empty() || s.len() == 0 {
        return None;
    }
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate random r1 and r2
    let r1 = Fr::random(rng);
    let r2 = Fr::random(rng);
    // and compute sk0
    let mut sk_0: Vec<(bn::G2)> = Vec::new();
    sk_0.push(msk._h * (msk._b[0] * r1));
    sk_0.push(msk._h * (msk._b[1] * r2));
    sk_0.push(msk._h * (r1 + r2));
    // sk_i data structure
    let mut sk_y: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    // vec to collect 3 skt values
    let mut sk_t: Vec<(bn::G1)> = Vec::new();
    // for all i=1,...n1 compute
    for _y in s.iter() {
        // vec to collect triples in loop
        let mut sk_yt: Vec<(bn::G1)> = Vec::new();
        // pick random sigma
        let sigma = Fr::random(rng);
        // calculate sk_{i,1} and sk_{i,2}
        for t in 1..3 {
            let current_t: usize = t - 1;
            let at = msk._a[current_t].inverse().unwrap();
            let h1 = hash_to(combine_string(_y, 1, t as u32).as_bytes()) * ((msk._b[0] * r1) * at);
            let h2 = hash_to(combine_string(_y, 2, t as u32).as_bytes()) * ((msk._b[1] * r2) * at);
            let h3 = hash_to(combine_string(_y, 3, t as u32).as_bytes()) * ((r1 + r2) * at);
            sk_yt.push(h1 + h2 + h3 + (msk._g * -sigma));
        }
        // now push all three values into sk_i vec
        sk_y.push((sk_yt[0], sk_yt[1], (msk._g * -sigma)));
    }
    // now calculate skt
    let h0 = String::from("01");
    for t in 1..3 {
        // pick random sigma
        let sigma = Fr::random(rng);
        let current_t: usize = t - 1;
        let at = msk._a[current_t].inverse().unwrap();

        let h1 = hash_to(combine_string(&h0, 1, t as u32).as_bytes()) * ((msk._b[0] * r1) * at);
        let h2 = hash_to(combine_string(&h0, 2, t as u32).as_bytes()) * ((msk._b[1] * r2) * at);
        let h3 = hash_to(combine_string(&h0, 3, t as u32).as_bytes()) * ((r1 + r2) * at);
        sk_t.push(h1 + h2 + h3 + (msk._g * (sigma * at)) + msk._d[current_t]);
    }

    return Some(CpAbeSecretKey {
        _sk_0: sk_0,
        _sk_y: sk_y,
        _sk_t: sk_t,
    });
}

pub fn cpabe_encrypt(
    pk: &AbePublicKey,
    msp: &AbePolicy,
    plaintext: &Vec<u8>,
) -> Option<AbeCiphertext> {
    if msp._m.len() == 0 || msp._m[0].len() == 0 || plaintext.is_empty() {
        return None;
    }
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate s1,s2
    let s1 = Fr::random(rng);
    let s2 = Fr::random(rng);
    // msp matrix M with size n1xn2
    let n1 = msp._m.len();
    let n2 = msp._m[0].len();
    let mut _ct_yl: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    let secret = pairing(G1::random(rng), G2::random(rng));
    println!("cp-abe encrypt secret: {:?}", into_hex(secret).unwrap());
    // pre-compute hashes
    let mut _hash_table: Vec<Vec<Vec<(bn::G1)>>> = Vec::new();
    for _j in 0..(n2) {
        let mut _x: Vec<Vec<(bn::G1)>> = Vec::new();
        let _string1 = String::from("0") + &(_j + 1).to_string();
        for _l in 1..4 {
            let mut _y: Vec<(bn::G1)> = Vec::new();
            let _string2 = _string1.clone() + &_l.to_string();
            for _t in 1..3 {
                let _string3 = _string2.clone() + &_t.to_string();
                let mut _hash = hash_string_to_element(&_string3);
                _y.push(_hash);
            }
            _x.push(_y);
        }
        _hash_table.push(_x);
    }
    for _i in 0..(n1) {
        let mut _ct_yl_temp: Vec<(bn::G1)> = Vec::new();
        for _l in 1..4 {
            let mut _prod = G1::one();
            for _t in 1..3 {
                let mut _hash =
                    hash_string_to_element(&combine_string(&msp._pi[_i], _l as u32, _t as u32));
                for _j in 1..(msp._m[_i].len() + 1) {
                    _hash = _hash + _hash_table[_j - 1][_l - 1][_t - 1] * msp._m[_i][_j - 1];
                }
                _hash = _hash * s1;
                _hash = _hash * s2;
                _prod = _prod + _hash;
            }
            _ct_yl_temp.push(_prod);
        }
        _ct_yl.push((_ct_yl_temp[0], _ct_yl_temp[1], _ct_yl_temp[2]));
    }
    let mut ct_0: Vec<(bn::G2)> = Vec::new();
    ct_0.push(pk._h_n[0] * s1);
    ct_0.push(pk._h_n[1] * s2);
    ct_0.push(pk._h * (s1 + s2));
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
            println!("key: {:?}", &key);
            let ct = AbeCiphertext {
                _ct_0: ct_0,
                _ct_prime: (pk._t_n[0].pow(s1) * pk._t_n[1].pow(s2) * secret),
                _ct_y: _ct_yl,
                _ct: encrypt_aes(plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

pub fn cpabe_decrypt(sk: &CpAbeSecretKey, ct: &AbeCiphertext) -> Option<Vec<u8>> {
    let mut prod1_gt = Gt::one();
    let mut prod2_gt = Gt::one();
    for _i in 0..2 {
        let mut prod_h = G1::one(); // sk
        let mut prod_g = G1::one(); // ct
        for _j in 0..ct._ct_y.len() {
            let (sk0, sk1, sk2) = sk._sk_y[_j];
            let (ct0, ct1, ct2) = ct._ct_y[_j];
            prod_h = prod_h + sk0 + sk1 + sk2;
            prod_g = prod_g + ct0 + ct1 + ct2;
        }
        prod1_gt = prod1_gt * pairing(sk._sk_t[_i] + prod_h, ct._ct_0[_i]);
        prod2_gt = prod2_gt * pairing(prod_g, sk._sk_0[_i]);
    }
    let secret = ct._ct_prime * (prod2_gt * prod1_gt.inverse());
    println!("cp-abe decrypt secret: {:?}", into_hex(secret).unwrap());
    let r: Vec<u8> = Vec::new();
    return Some(r);
    // Decrypt plaintext using derived secret from abe scheme
    /*let mut sha = Sha3::sha3_256();
    match encode(&secret, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            println!("key: {:?}", &key);
            let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
            return Some(aes);
        }
    }*/
}
// KP ABE PART

pub fn kpabe_keygen(msk: &AbeMasterKey, msp: &AbePolicy) -> Option<KpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if msp._m.is_empty() || msp._m.len() == 0 || msp._m[0].len() == 0 {
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
    let mut sigma_prime: Vec<bn::Fr> = Vec::new();
    // generate 2..n1 random sigma' values
    for _i in 2..(n2 + 1) {
        sigma_prime.push(Fr::random(rng))
    }
    // and compute sk0
    let mut _sk_0: Vec<(bn::G2)> = Vec::new();
    _sk_0.push(msk._h * (msk._b[0] * r1));
    _sk_0.push(msk._h * (msk._b[1] * r2));
    _sk_0.push(msk._h * (r1 + r2));
    // sk_i data structure
    let mut sk_i: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    // for all i=1,...n1 compute
    for i in 1..(n1 + 1) {
        // vec to collect triples in loop
        let mut sk_i_temp: Vec<(bn::G1)> = Vec::new();
        // pick random sigma
        let sigma = Fr::random(rng);
        // calculate sk_{i,1} and sk_{i,2}
        for t in 1..3 {
            let current_t: usize = t - 1;
            let at = msk._a[current_t];
            let h1 = hash_to(combine_string(&msp._pi[i - 1], 1, t as u32).as_bytes());
            let h2 = hash_to(combine_string(&msp._pi[i - 1], 2, t as u32).as_bytes());
            let h3 = hash_to(combine_string(&msp._pi[i - 1], 3, t as u32).as_bytes());
            // calculate the first part of the sk_it term for sk_{i,1} and sk_{i,2}
            let mut sk_it = h1 * ((msk._b[0] * r1) * at.inverse().unwrap()) +
                h2 * ((msk._b[1] * r2) * at.inverse().unwrap()) +
                h3 * ((r1 + r2) * at.inverse().unwrap());
            // now calculate the product over j=2 until n2 for sk_it in a loop
            for j in 2..(n2 + 1) {
                let j1 = hash_to(combine_string(&j.to_string(), 1, t as u32).as_bytes());
                let j2 = hash_to(combine_string(&j.to_string(), 2, t as u32).as_bytes());
                let j3 = hash_to(combine_string(&j.to_string(), 3, t as u32).as_bytes());
                sk_it = sk_it +
                    (j1 * ((msk._b[0] * r1) * at.inverse().unwrap()) +
                         j2 * ((msk._b[1] * r2) * at.inverse().unwrap()) +
                         j3 * ((r1 + r2) * at.inverse().unwrap()) +
                         (msk._g * (sigma_prime[j - 2] * at.inverse().unwrap()))) *
                        msp._m[i - 1][j - 1];
            }
            sk_i_temp.push(sk_it);
        }
        let mut sk_i3 = (msk._g * -sigma) + (msk._d[2] * msp._m[i - 1][0]);
        // calculate sk_{i,3}
        for j in 2..(n2 + 1) {
            sk_i3 = sk_i3 + ((msk._g * -sigma_prime[j - 2]) * msp._m[i - 1][j - 1]);
        }
        // now push all three values into sk_i vec
        sk_i.push((sk_i_temp[0], sk_i_temp[1], sk_i3));
    }
    return Some(KpAbeSecretKey {
        _sk_0: _sk_0,
        _sk_y: sk_i,
    });
}

pub fn kpabe_encrypt(
    pk: &AbePublicKey,
    tags: &LinkedList<String>,
    plaintext: &Vec<u8>,
) -> Option<AbeCiphertext> {
    if tags.is_empty() || plaintext.is_empty() {
        return None;
    }
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate s1,s2
    let s1 = Fr::random(rng);
    let s2 = Fr::random(rng);
    //Choose random secret
    let secret = pairing(G1::random(rng), G2::random(rng));
    println!("kp-abe encrypt secret: {:?}", into_hex(secret).unwrap());
    let mut _ct_yl: Vec<(bn::G1, bn::G1, bn::G1)> = Vec::new();
    for _tag in tags.iter() {
        let mut _ct_yl_temp: Vec<(bn::G1)> = Vec::new();
        for _l in 1..4 {
            let h1 = hash_string_to_element(&combine_string(&_tag, _l as u32, 1));
            let h2 = hash_string_to_element(&combine_string(&_tag, _l as u32, 2));
            _ct_yl_temp.push((h1 * s1) + (h2 * s2));
        }
        _ct_yl.push((_ct_yl_temp[0], _ct_yl_temp[1], _ct_yl_temp[2]));
    }

    let mut ct_0: Vec<(bn::G2)> = Vec::new();
    ct_0.push(pk._h_n[0] * s1);
    ct_0.push(pk._h_n[1] * s2);
    ct_0.push(pk._h * (s1 + s2));

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
            println!("key: {:?}", &key);
            let ct = AbeCiphertext {
                _ct_0: ct_0,
                _ct_prime: (pk._t_n[0].pow(s1) * pk._t_n[1].pow(s2) * secret),
                _ct_y: _ct_yl,
                _ct: encrypt_aes(plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

pub fn kpabe_decrypt(sk: &KpAbeSecretKey, ct: &AbeCiphertext) -> Option<Vec<u8>> {
    let mut prod1_gt = Gt::one();
    let mut prod2_gt = Gt::one();
    for _i in 1..3 {
        let mut prod_h = G1::one(); // sk
        let mut prod_g = G1::one(); // ct
        for _j in 0..ct._ct_y.len() {
            let (sk0, sk1, sk2) = sk._sk_y[_j];
            let (ct0, ct1, ct2) = ct._ct_y[_j];
            prod_h = prod_h + sk0 + sk1 + sk2;
            prod_g = prod_g + ct0 + ct1 + ct2;
        }
        prod1_gt = prod1_gt * pairing(prod_h, ct._ct_0[_i]);
        prod2_gt = prod2_gt * pairing(prod_g, sk._sk_0[_i]);
    }
    let secret = ct._ct_prime * (prod2_gt * prod1_gt.inverse());
    println!("kp-abe decrypt secret: {:?}", into_hex(secret).unwrap());
    let r: Vec<u8> = Vec::new();
    return Some(r);
    // Decrypt plaintext using derived secret from abe scheme
    /*
    let mut sha = Sha3::sha3_256();
    match encode(&secret, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            println!("key: {:?}", &key);
            let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
            return Some(aes);
        }
    }
    */
}

// Helper functions from here on
pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| e.to_hex())
}

pub fn combine_string(text: &String, j: u32, t: u32) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    _combined.push_str(&t.to_string());
    return _combined.to_string();
}

pub fn hash_to(data: &[u8]) -> bn::G1 {
    let mut sha = Sha3::sha3_256();
    sha.input(data);
    let i = BigInt::parse_bytes(sha.result_str().as_bytes(), 16).unwrap();
    // TODO: check if there is a better (faster) hashToElement method
    return G1::one() * Fr::from_str(&i.to_str_radix(10)).unwrap();
}

pub fn hash_string_to_element(text: &String) -> bn::G1 {
    return hash_to(text.as_bytes());
}

// AES functions from here on

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

#[cfg(test)]
mod tests {
    use abe_setup;
    use cpabe_keygen;
    use cpabe_encrypt;
    use cpabe_decrypt;
    use kpabe_keygen;
    use kpabe_encrypt;
    use kpabe_decrypt;
    use hash_string_to_element;
    use combine_string;
    use AbePolicy;
    use AbeCiphertext;
    use CpAbeSecretKey;
    use KpAbeSecretKey;
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

    // TODO: write tests for all algorithms of the scheme
    // PROBLEM: random blinding of nearly all values
    // TODO: check if static values can be injected in rust!?

    #[test]
    fn test_setup() {
        let (pk, msk) = abe_setup();
        // assert generators
        assert_eq!(into_hex(msk._h).unwrap(), into_hex(pk._h).unwrap());
        // assert random values a
        let hn0 = into_hex(msk._h * msk._a[0]).unwrap();
        let hn1 = into_hex(msk._h * msk._a[1]).unwrap();
        assert_eq!(hn0, into_hex(pk._h_n[0]).unwrap());
        assert_eq!(hn1, into_hex(pk._h_n[1]).unwrap());
    }

    #[test]
    fn test_keygen() {
        let (pk, msk) = abe_setup();
        // 4 attributes a, b, c and d
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let msp: AbePolicy = AbePolicy::from_string(policy).unwrap();
        // 4 rows
        assert_eq!(msp._m.len(), 4);
        // with 3 columns
        assert_eq!(msp._m[0].len(), 3);
        // create sk from msk and msp
        let sk: KpAbeSecretKey = kpabe_keygen(&msk, &msp).unwrap();
        assert_eq!(sk._sk_y.len(), 4);
    }

    #[test]
    fn test_cp_abe_and_encryption() {
        // setup scheme
        let (pk, msk) = abe_setup();
        // a set of two attributes
        let mut attributes: LinkedList<String> = LinkedList::new();
        attributes.push_back(String::from("A"));
        attributes.push_back(String::from("B"));
        // an msp policy (A and B)
        let msp1: AbePolicy = AbePolicy::from_string(
            String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        ).unwrap();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!");
        // cp-abe ciphertext
        let ct_cp: AbeCiphertext = cpabe_encrypt(&pk, &msp1, &plaintext.clone().into_bytes())
            .unwrap();
        // some assertions
        // TODO
        // a cp-abe SK key using msp
        let sk_cp: CpAbeSecretKey = cpabe_keygen(&msk, &attributes).unwrap();
        // some assertions
        // TODO
        // and now decrypt again
        let plaintext_cp: Vec<u8> = cpabe_decrypt(&sk_cp, &ct_cp).unwrap();
        let cp = String::from_utf8(plaintext_cp).unwrap();
        println!("plaintext_cp: {:?}", cp);
    }

    #[test]
    fn test_kp_abe_and_encryption() {
        // setup scheme
        let (pk, msk) = abe_setup();
        // a set of two attributes
        let mut attributes: LinkedList<String> = LinkedList::new();
        attributes.push_back(String::from("A"));
        attributes.push_back(String::from("B"));
        // an msp policy (A and B)
        let msp1: AbePolicy = AbePolicy::from_string(
            String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        ).unwrap();
        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!");
        // kp-abe ciphertext
        let ct_kp: AbeCiphertext = kpabe_encrypt(&pk, &attributes, &plaintext.clone().into_bytes())
            .unwrap();
        // some assertions
        // TODO
        // a kp-abe SK key using msp
        let sk_kp: KpAbeSecretKey = kpabe_keygen(&msk, &msp1).unwrap();
        // some assertions
        // TODO
        // and now decrypt again
        let plaintext_kp: Vec<u8> = kpabe_decrypt(&sk_kp, &ct_kp).unwrap();
        let kp = String::from_utf8(plaintext_kp).unwrap();
        println!("plaintext_kp: {:?}", kp);
    }

    #[test]
    fn test_combine_string() {
        let s1 = String::from("hashing");
        let u2: u32 = 4;
        let u3: u32 = 8;
        let _combined = combine_string(&s1, u2, u3);
        assert_eq!(_combined, String::from("hashing48"));
    }

    #[test]
    fn test_hash() {
        let s1 = String::from("hashing");
        let point1 = hash_string_to_element(&s1);
        let expected_str: String = into_hex(point1).unwrap();
        //println!("Expected: {:?}", expected_str); // print msg's during test: "cargo test -- --nocapture"
        assert_eq!(
            "0403284c4eb462be32679deba32fa662d71bb4ba7b1300f7c8906e1215e6c354aa0d973373c26c7f2859c2ba7a0656bc59a79fa64cb3a5bbe99cf14d0f0f08ab46",
            expected_str
        );
    }

    #[test]
    fn test_to_msp() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let p1 = vec![Fr::zero(), Fr::zero(), Fr::one().inverse().unwrap()];
        let p2 = vec![Fr::one(), Fr::zero(), Fr::one()];
        let p3 = vec![Fr::zero(), Fr::one().inverse().unwrap(), Fr::zero()];
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
}
