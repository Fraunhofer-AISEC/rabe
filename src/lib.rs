// no serde traits until now
//#[macro_use]
//extern crate serde_derive;

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

use libc::*;
use blake2_rfc::blake2b::{Blake2b, blake2b};
use std::ffi::CString;
use std::ffi::CStr;
use std::mem::transmute;
use std::collections::LinkedList;
use std::string::String;
use std::convert::AsMut;
use std::ops::Add;
use std::ops::Sub;
use std::ops::Mul;
use std::ops::Div;
use std::ops::Neg;
use std::mem;
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

#[macro_use]
extern crate arrayref;

mod policy;

// Barreto-Naehrig (BN) curve construction with an efficient bilinear pairing e: G1 × G2 → GT
const ASSUMPTION_SIZE: usize = 2;

//#[doc = /**
// * TODO
// * - Put everything in a module (?)
// * - Encrypt/Decrypt
// * - Serialization, bn::Gt is not serializable :(((
// *
// */]
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbePublicKey {
    _g1: bn::G1,
    _g2: bn::G2,
    _h: bn::G2,
    _e_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeMasterKey {
    _beta: bn::Fr,
    _g1_alpha: bn::G1,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeCiphertext {
    _c_0: bn::G2,
    _c: Vec<(bn::G2, bn::G1)>,
    _c_m: bn::Gt,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

pub struct AbeSecretKey {
    _k_0: bn::G1,
    _k: Vec<(bn::G1, bn::G2)>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeContext {
    _msk: AbeMasterKey,
    _pk: AbePublicKey,
}

impl AbePolicy {
    pub fn from_string(policy: &String) -> Option<AbePolicy> {
        policy::string_to_msp(policy)
    }
    pub fn from_json(json: &serde_json::Value) -> Option<AbePolicy> {
        policy::json_to_msp(json)
    }
}

// BSW CP-ABE

pub fn abe_setup() -> (AbePublicKey, AbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generator of group G1: g1 and generator of group G2: g2
    let _g1 = G1::one();
    let _g2 = G2::one();
    // random
    let _beta = Fr::random(_rng);
    let _alpha = Fr::random(_rng);
    // vectors
    // calulate h and f
    let _h = _g2 * _beta;
    let _g1_alpha = _g1 * _alpha;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g1_alpha, _g2);
    // set values of PK
    let _pk = AbePublicKey {
        _g1: _g1,
        _g2: _g2,
        _h: _h,
        _e_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = AbeMasterKey {
        _beta: _beta,
        _g1_alpha: _g1_alpha,
    };
    // return PK and MSK
    return (_pk, _msk);
}

//////////////////////////////////////////
// CP ABE SCHEME:
//////////////////////////////////////////

// KEYGEN

pub fn cpabe_keygen(
    pk: &AbePublicKey,
    msk: &AbeMasterKey,
    attributes: &LinkedList<String>,
) -> Option<AbeSecretKey> {
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
    let _g1_r = pk._g1 * _r;
    let _beta_inverse = msk._beta.inverse().unwrap();
    let _k_0 = (msk._g1_alpha + _g1_r) * _beta_inverse;
    let mut _k: Vec<(bn::G1, bn::G2)> = Vec::new();
    for _attr in attributes {
        let _r_attr = Fr::random(_rng);
        _k.push((
            _g1_r + (blake2b_hash_to(pk._g1, &_attr) * _r_attr),
            pk._g2 * _r_attr,
        ));
    }
    return Some(AbeSecretKey { _k_0: _k_0, _k: _k });
}

// ENCRYPT

pub fn cpabe_encrypt(
    pk: &AbePublicKey,
    msp: &AbePolicy,
    plaintext: &Vec<u8>,
) -> Option<AbeCiphertext> {
    if msp._m.len() == 0 || msp._m[0].len() == 0 || plaintext.is_empty() {
        return None;
    }
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
            blake2b_hash_to(pk._g1, &msp._pi[_i]) * _sum,
        ));
    }
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
    println!("_msg: {:?}", into_dec(_msg).unwrap());
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
            println!("key: {:?}", &key);
            let ct = AbeCiphertext {
                _c_0: _c_0,
                _c: _c,
                _c_m: _c_m,
                _ct: encrypt_aes(plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

pub fn cpabe_decrypt(sk: &AbeSecretKey, ct: &AbeCiphertext) -> Option<Vec<u8>> {
    let mut _prod = Gt::one();
    for _i in 0usize..ct._c.len() {
        let (c_attr1, c_attr2) = ct._c[_i];
        let (k_attr1, k_attr2) = sk._k[_i];
        _prod = _prod * (pairing(k_attr1, c_attr1) * pairing(c_attr2, k_attr2).inverse());
    }
    let _msg = (ct._c_m * _prod) * pairing(sk._k_0, ct._c_0).inverse();
    // Decrypt plaintext using derived secret from cp-abe scheme
    let mut sha = Sha3::sha3_256();
    match encode(&_msg, Infinite) {
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
}
/*
//////////////////////////////////////////
// KP ABE SCHEME:
//////////////////////////////////////////

pub fn kpabe_keygen(msk: &AbeMasterKey, msp: &AbePolicy) -> Option<KpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if msp._m.is_empty() || msp._m.len() == 0 || msp._m[0].len() == 0 {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate random r1 and r2
    let r1 = Fr::random(_rng);
    let r2 = Fr::random(_rng);
    // msp matrix M with size n1xn2
    let n1 = msp._m.len();
    let n2 = msp._m[0].len();
    // data structure for random sigma' values
    let mut sigma_prime: Vec<bn::Fr> = Vec::new();
    // generate 2..n1 random sigma' values
    for _i in 2..(n2 + 1) {
        sigma_prime.push(Fr::random(_rng))
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
        let sigma = Fr::random(_rng);
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
    plaintext: &[u8],
) -> Option<AbeCiphertext> {
    if tags.is_empty() || plaintext.is_empty() {
        return None;
    }
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate s1,s2
    let s1 = Fr::random(_rng);
    let s2 = Fr::random(_rng);
    //Choose random secret
    let secret = pairing(G1::random(_rng), G2::random(_rng));
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
            _rng.fill_bytes(&mut iv);
            println!("key: {:?}", &key);
            let ct = AbeCiphertext {
                _ct_0: ct_0,
                _ct_prime: (pk._e_gh_k[0].pow(s1) * pk._e_gh_k[1].pow(s2) * secret),
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

    let mut sha = Sha3::sha3_256();
    match encode(&secret, Infinite) {
        Err(val) => {println!("Error: {:?}", val);return None},
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);

            println!("key: {:?}", &key);
            println!("XXX");
            let res = decrypt_aes(ct._ct.as_slice(), &key, &ct._iv).unwrap();
            println!("YYY");
            return Some(res);
        }
    }
}
*/

#[no_mangle]
pub extern "C" fn abe_context_create() -> *mut AbeContext {
    let (pk, msk) = abe_setup();
    let _ctx = unsafe { transmute(Box::new(AbeContext { _msk: msk, _pk: pk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn abe_context_destroy(ctx: *mut AbeContext) {
    let _ctx: Box<AbeContext> = unsafe { transmute(ctx) };
    // Drop reference for GC
}

/*
#[no_mangle]
pub extern "C" fn kpabe_secret_key_create(
    ctx: *mut AbeContext,
    policy: *mut c_char,
) -> *mut KpAbeSecretKey {
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _msp = AbePolicy::from_string(&pol).unwrap();
    let _ctx = unsafe { &mut *ctx };
    let sk = kpabe_keygen(&_ctx._msk, &_msp).unwrap();
    let _sk = unsafe {
        transmute(Box::new(KpAbeSecretKey {
            _sk_0: sk._sk_0.clone(),
            _sk_y: sk._sk_y.clone(),
        }))
    };
    _sk
}
*/
#[no_mangle]
pub extern "C" fn abe_secret_key_destroy(sk: *mut AbeSecretKey) {
    let _sk: Box<AbeSecretKey> = unsafe { transmute(sk) };
    // Drop reference for GC
}

#[no_mangle]
pub extern "C" fn kpabe_decrypt_native(sk: *mut AbeSecretKey, ct: *mut c_char) -> i32 {
    //TODO: Deserialize ct
    //TODO: Call abe_decrypt
    //TODO: serialize returned pt and store under pt
    return 1;
}

// Helper functions from here on
pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| e.to_hex())
}

pub fn into_dec<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| {
        BigInt::parse_bytes(e.to_hex().as_bytes(), 16)
            .unwrap()
            .to_str_radix(10)
    })
}

pub fn combine_string(text: &String, j: usize, t: usize) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    _combined.push_str(&t.to_string());
    return _combined.to_string();
}



pub fn blake2b_hash_to(g: bn::G1, data: &String) -> bn::G1 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
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
    return Ok(final_result);
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
    //use kpabe_keygen;
    //use kpabe_encrypt;
    //use kpabe_decrypt;
    use blake2b_hash_to;
    use combine_string;
    use AbePolicy;
    use AbeCiphertext;
    use AbeSecretKey;
    //use KpAbeSecretKey;
    //use Fr;
    use std::collections::LinkedList;
    use std::string::String;
    use std::ops::Add;
    use std::ops::Sub;
    use bn::*;
    use num_bigint::BigInt;
    use bincode::SizeLimit::Infinite;
    use bincode::rustc_serialize::{encode, decode};
    use rustc_serialize::{Encodable, Decodable};
    use rustc_serialize::hex::{FromHex, ToHex};

    pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
        encode(&obj, Infinite).ok().map(|e| e.to_hex())
    }

    pub fn into_dec<S: Encodable>(obj: S) -> Option<String> {
        encode(&obj, Infinite).ok().map(|e| {
            BigInt::parse_bytes(e.to_hex().as_bytes(), 16)
                .unwrap()
                .to_str_radix(10)
        })
    }

    pub fn from_hex<S: Decodable>(s: &str) -> Option<S> {
        let s = s.from_hex().unwrap();
        decode(&s).ok()
    }

    // TODO: write tests for all algorithms of the scheme
    // PROBLEM: random blinding of nearly all values
    // TODO: check if static values can be injected in rust!?
    /*
    #[test]
    fn test_setup() {
        let (pk, msk) = abe_setup();
        // assert random values a
        let hn0 = into_hex(msk._h * msk._a[0]).unwrap();
        let hn1 = into_hex(msk._h * msk._a[1]).unwrap();
        assert_eq!(hn0, into_hex(pk._h_a[0]).unwrap());
        assert_eq!(hn1, into_hex(pk._h_a[1]).unwrap());
    }

    #[test]
    fn test_keygen() {
        let (pk, msk) = abe_setup();
        // 4 attributes a, b, c and d
        let mut attributes: LinkedList<String> = LinkedList::new();
        attributes.push_back(String::from("A"));
        attributes.push_back(String::from("B"));
        attributes.push_back(String::from("C"));
        attributes.push_back(String::from("D"));
        // 4 attributes a, b, c and d
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
        // 4 rows
        assert_eq!(msp._m.len(), 4);
        // with 3 columns
        assert_eq!(msp._m[0].len(), 3);
        // create sk from msk and msp
        //let kp_sk: KpAbeSecretKey = kpabe_keygen(&msk, &msp).unwrap();

        let cp_sk: CpAbeSecretKey = cpabe_keygen(&msk, &attributes).unwrap();
        //assert_eq!(sk._sk_y.len(), 4);
    }
*/
    #[test]
    fn test_cp_abe_and() {
        // setup scheme
        let (pk, msk) = abe_setup();
        // a set of two attributes matching the policy
        let mut matching: LinkedList<String> = LinkedList::new();
        matching.push_back(String::from("A"));
        matching.push_back(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut not_matching: LinkedList<String> = LinkedList::new();
        not_matching.push_back(String::from("A"));
        not_matching.push_back(String::from("C"));

        // an msp policy (A and B)
        let msp: AbePolicy = AbePolicy::from_string(
            &String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#),
        ).unwrap();

        // our plaintext
        let pt = String::from("dance like no one's watching, encrypt like everyone is!");

        // cp-abe ciphertext
        let ct_cp: AbeCiphertext = cpabe_encrypt(&pk, &msp, &pt.into_bytes()).unwrap();

        // some assertions
        // TODO

        // a cp-abe SK key matching
        let sk_matching: AbeSecretKey = cpabe_keygen(&pk, &msk, &matching).unwrap();
        // a cp-abe SK key NOT matching
        let sk_not_matching: AbeSecretKey = cpabe_keygen(&pk, &msk, &not_matching).unwrap();

        // some assertions
        // TODO

        // and now decrypt again with mathcing sk
        let matching: Vec<u8> = cpabe_decrypt(&sk_matching, &ct_cp).unwrap();

        // and now decrypt again without matching sk
        let pnot_matching: Vec<u8> = cpabe_decrypt(&sk_not_matching, &ct_cp).unwrap();

        println!("_matching: {:?}", String::from_utf8(matching).unwrap());

        println!(
            "not_matching: {:?}",
            String::from_utf8(not_matching).unwrap()
        );
    }
    /*
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
            &String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#),
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
*/
    #[test]
    fn test_combine_string() {
        let s1 = String::from("hashing");
        let u2: usize = 4;
        let u3: usize = 8;
        let _combined = combine_string(&s1, u2, u3);
        assert_eq!(_combined, String::from("hashing48"));
    }

    #[test]
    fn test_to_msp() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let _zero = 0;
        let _plus = 1;
        let _minus = -1;
        let p1 = vec![_zero, _zero, _minus];
        let p2 = vec![_plus, _zero, _plus];
        let p3 = vec![_zero, _minus, _zero];
        let p4 = vec![_plus, _plus, _zero];
        let mut _msp_static = AbePolicy {
            _m: vec![p1, p2, p3, p4],
            _pi: vec![
                String::from("A"),
                String::from("B"),
                String::from("C"),
                String::from("D"),
            ],
            _deg: 3,
        };
        match AbePolicy::from_string(&policy) {
            None => assert!(false),
            Some(_msp) => {
                for i in 0..4 {
                    let p = &_msp._m[i];
                    let p_test = &_msp_static._m[i];
                    for j in 0..3 {
                        //println!("_mspg[{:?}][{:?}]: {:?}", i, j, p[j]);
                        //println!("_msps[{:?}][{:?}]: {:?}", i, j, p_test[j]);
                        assert!(p[j] == p_test[j]);
                    }
                    //println!("_pi[{:?}]{:?} _pi[{:?}]{:?}",i,_msp_static._pi[i],i,_msp._pi[i]);
                    assert!(_msp_static._pi[i] == _msp._pi[i]);
                }
                assert!(_msp_static._deg == _msp._deg);

            }
        }
    }
    /*
    #[test]
    fn test_enc_dec() {
        let test_str = "hello world";
        let (pk, msk) = abe_setup();
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}]}"#);
        let abe_pol = AbePolicy::from_string(&policy).unwrap();
        let mut tags = LinkedList::new();
        tags.push_back(String::from("A"));
        let ciphertext = kpabe_encrypt(&pk, &tags, test_str.as_bytes()).unwrap();
        let sk = kpabe_keygen(&msk, &abe_pol).unwrap();
        println!("Ctlen: {:?}", ciphertext._ct.len());

        let plaintext = kpabe_decrypt(&sk, &ciphertext).unwrap();
        println!("plain: {:?}", plaintext);
        assert!(plaintext == test_str.as_bytes());
    }
    */
}
