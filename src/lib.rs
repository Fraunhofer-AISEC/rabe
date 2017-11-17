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
use serde_json::Value;
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

//#[doc = /**
// * TODO
// * - Put everything in a module (?)
// * - Encrypt/Decrypt
// * - Serialization, bn::Gt is not serializable :(((
// *
// */]
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbePublicKey {
    _g1: bn::G1,
    _g2: bn::G2,
    _h: bn::G2,
    _e_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeMasterKey {
    _beta: bn::Fr,
    _g1_alpha: bn::G1,
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

pub struct CpAbeSecretKey {
    _attr: Vec<(String)>,
    _k_0: bn::G1,
    _k: Vec<(bn::G1, bn::G2)>,
}

//For C
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct CpAbeContext {
    _msk: CpAbeMasterKey,
    _pk: CpAbePublicKey,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbePublicKey {
    _g_g1: bn::G1,
    _g_g2: bn::G2,
    _g1_b: Vec<(bn::G1)>,
    _g_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbeMasterKey {
    _alpha: Vec<(bn::Fr)>,
    _h_g1: bn::G1,
    _h_g2: bn::G2,
}

pub struct KpAbeSecretKey {
    _policy: String,
    _d_i: Vec<(bn::G1, bn::G2, bn::G1, bn::G2, bn::G2)>,
}

impl AbePolicy {
    pub fn from_string(policy: &String) -> Option<AbePolicy> {
        policy::string_to_msp(policy)
    }
    pub fn from_json(json: &serde_json::Value) -> Option<AbePolicy> {
        policy::json_to_msp(json)
    }
}

//////////////////////////////////////////
// BSW CP-ABE on type-3
//////////////////////////////////////////

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
    let _h = _g2 * _beta;
    let _g1_alpha = _g1 * _alpha;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g1_alpha, _g2);
    // set values of PK
    let _pk = CpAbePublicKey {
        _g1: _g1,
        _g2: _g2,
        _h: _h,
        _e_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = CpAbeMasterKey {
        _beta: _beta,
        _g1_alpha: _g1_alpha,
    };
    // return PK and MSK
    return (_pk, _msk);
}

pub fn cpabe_keygen(
    pk: &CpAbePublicKey,
    msk: &CpAbeMasterKey,
    attributes: &LinkedList<String>,
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
    let _g1_r = pk._g1 * _r;
    let _beta_inverse = msk._beta.inverse().unwrap();
    let _k_0 = (msk._g1_alpha + _g1_r) * _beta_inverse;
    let mut _k: Vec<(bn::G1, bn::G2)> = Vec::new();
    let mut _attr_vec: Vec<(String)> = Vec::new();
    for _attr in attributes {
        let _r_attr = Fr::random(_rng);
        _attr_vec.push(_attr.clone());
        _k.push((
            _g1_r + (blake2b_hash_to(pk._g1, &_attr) * _r_attr),
            pk._g2 * _r_attr,
        ));
    }
    return Some(CpAbeSecretKey {
        _attr: _attr_vec,
        _k_0: _k_0,
        _k: _k,
    });
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
            blake2b_hash_to(pk._g1, &msp._pi[_i]) * _sum,
        ));
    }
    let _msg = pairing(G1::random(_rng), G2::random(_rng));
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

pub fn cpabe_decrypt(sk: &CpAbeSecretKey, ct: &CpAbeCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&sk._attr, &ct._policy) == false {
        println!("Error: attributes in sk do not match policy in ct.");
        return None;
    } else {
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
                let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}

//////////////////////////////////////////
// LSW KP-ABE on type-3
//////////////////////////////////////////

pub fn kpabe_setup() -> (KpAbePublicKey, KpAbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate random alpha1, alpha2 and b
    let mut _alpha: Vec<bn::Fr> = Vec::new();
    // generate 2..n1 random sigma' values
    for _i in 0..3 {
        _alpha.push(Fr::random(_rng))
    }
    let _g_g1 = G1::random(_rng);
    let _g_g2 = G2::random(_rng);
    let _h_g1 = G1::random(_rng);
    let _h_g2 = G2::random(_rng);
    // generate _g1_b values
    let mut _g1_b: Vec<bn::G1> = Vec::new();
    _g1_b.push(_g_g1 * _alpha[2]);
    _g1_b.push(_g1_b[0] * _alpha[2]);
    _g1_b.push(_h_g1 * _alpha[2]);
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g_g1, _g_g2).pow(_alpha[0] * _alpha[1]);
    // set values of PK
    let _pk = KpAbePublicKey {
        _g_g1: _g_g1,
        _g_g2: _g_g2,
        _g1_b: _g1_b,
        _g_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = KpAbeMasterKey {
        _alpha: _alpha,
        _h_g1: _h_g1,
        _h_g2: _h_g2,
    };
    // return PK and MSK
    return (_pk, _msk);
}

pub fn kpabe_keygen(
    pk: &KpAbePublicKey,
    msk: &KpAbeMasterKey,
    policy: &String,
) -> Option<KpAbeSecretKey> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let secret = msk._alpha[0];
    let shares = calculateSharesDict(secret, policy);
    let mut _d: Vec<(bn::G1, bn::G2, bn::G1, bn::G2, bn::G2)> = Vec::new();
    for _i in 0usize..msp._pi.len() {
        let mut _d_i: (bn::G1, bn::G2, bn::G1, bn::G2, bn::G2) =
            (G1::one(), G2::one(), G1::one(), G2::one(), G2::one());
        let _r = Fr::random(_rng);
        if is_negative(&msp._pi[_i]) {
            //_d_i.2 = pk._g_g2 * shares[x] + (pk._g1_b[1] ** _r);
            //_d_i.3 = pk._g1_b[0] * (r * blake2b_hash_to(x)) + (pk['h_G1'] ** r);
            //_d_i.4 = pk._g_g1 ** -r;
        } else {
            _d_i.0 = pk._g_g1 * (msk._alpha[1] * shares[_i]) +
                (blake2b_hash_to(pk._g_g1, &msp._pi[_i]) * _r);
            _d_i.1 = pk._g_g2 * _r;
        }
        _d.push(_d_i);
    }
    return Some(KpAbeSecretKey {
        _policy: policy.clone(),
        _d_i: _d,
    });
}

pub fn kpabe_encrypt(
    pk: &CpAbePublicKey,
    tags: &LinkedList<String>,
    plaintext: &[u8],
) -> Option<CpAbeCiphertext> {
    if tags.is_empty() || plaintext.is_empty() {
        return None;
    }

}

pub fn kpabe_decrypt(sk: &KpCpAbeSecretKey, ct: &CpAbeCiphertext) -> Option<Vec<u8>> {}


//////////////////////////////////////////
// LW KP-ABE on type-3
//////////////////////////////////////////

#[no_mangle]
pub extern "C" fn abe_context_create() -> *mut CpAbeContext {
    let (pk, msk) = cpabe_setup();
    let _ctx = unsafe { transmute(Box::new(CpAbeContext { _msk: msk, _pk: pk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn abe_context_destroy(ctx: *mut CpAbeContext) {
    let _ctx: Box<CpAbeContext> = unsafe { transmute(ctx) };
    // Drop reference for GC
}

/*
#[no_mangle]
pub extern "C" fn kpabe_secret_key_create(
    ctx: *mut CpAbeContext,
    policy: *mut c_char,
) -> *mut KpCpAbeSecretKey {
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _msp = AbePolicy::from_string(&pol).unwrap();
    let _ctx = unsafe { &mut *ctx };
    let sk = kpabe_keygen(&_ctx._msk, &_msp).unwrap();
    let _sk = unsafe {
        transmute(Box::new(KpCpAbeSecretKey {
            _sk_0: sk._sk_0.clone(),
            _sk_y: sk._sk_y.clone(),
        }))
    };
    _sk
}
*/
#[no_mangle]
pub extern "C" fn abe_secret_key_destroy(sk: *mut CpAbeSecretKey) {
    let _sk: Box<CpAbeSecretKey> = unsafe { transmute(sk) };
    // Drop reference for GC
}

#[no_mangle]
pub extern "C" fn kpabe_decrypt_native(sk: *mut CpAbeSecretKey, ct: *mut c_char) -> i32 {
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

pub fn is_negative(_attr: &String) -> bool {
    let first_char = &_attr[..1];
    return first_char == '!'.to_string();
}

pub fn polynomial(_coeff: Vec<bn::Fr>, _x: bn::Fr) -> bn::Fr {
    let _sum = Fr::zero();
    for _i in 0usize.._coeff.len() {
        _sum = _sum + _coeff[_i] * (_x.pow(usize_to_Fr(_i)));
    }
    return _sum;
}

pub fn calculate_share(_secret: bn::Fr, _k: usize, _n: usize) -> Vec<bn::Fr> {
    let _shares: Vec<bn::Fr> = Vec::new();
    if _k <= _n {
        // random number generator
        let _rng = &mut rand::thread_rng();
        let _a: Vec<bn::Fr> = Vec::new();
        for _i in 0.._k {
            if _i == 0 {
                _a.push(_secret);
            } else {
                _a.push(Fr::random(_rng))
            }
        }
        for _i in 0..(_n + 1) {
            _shares.push(polynomial(_a, usize_to_Fr(_i)));
        }
    }
    return _shares;
}

pub fn usize_to_Fr(_i: usize) -> bn::Fr {
    let b = mem::transmute::<usize, [u8; 64]>(_i);
    return Fr::interpret(&b);
}

pub fn calculate_shares_str(_secret: bn::Fr, _policy: &String) -> Option<Vec<bn::Fr>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            return Some(calculate_shares_json(_secret, &pol).unwrap());
        }
    }
}

pub fn calculate_shares_json(_secret: bn::Fr, _json: &serde_json::Value) -> Option<Vec<bn::Fr>> {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return None;
    } else {
        // inner node
        if _json["OR"].is_array() || _json["AND"].is_array() {

        }
        // leaf node
        else if _json["ATT"] != serde_json::Value::Null {

        }
        // error
        else {
            println!("Policy invalid. No AND or OR found");
            return false;
        }
    }
}

pub fn traverse_str(_attr: &Vec<(String)>, _policy: &String) -> bool {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return false;
        }
        Ok(pol) => {
            return traverse_json(_attr, &pol);
        }
    }
}

pub fn traverse_json(_attr: &Vec<(String)>, _json: &serde_json::Value) -> bool {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return false;
    }
    if _attr.len() == 0 {
        println!("Error: No attributes in List!");
        return false;
    }
    // inner node or
    if _json["OR"].is_array() {
        let _num_terms = _json["OR"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = false;
            for _i in 0usize.._num_terms {
                ret = ret || traverse_json(_attr, &_json["OR"][_i]);
            }
            return ret;
        } else {
            println!("Invalid policy.");
            return false;
        }
    }
    // inner node and
    else if _json["AND"].is_array() {
        let _num_terms = _json["AND"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = true;
            for _i in 0usize.._num_terms {
                ret = ret && traverse_json(_attr, &_json["AND"][_i]);
            }
            return ret;
        } else {
            println!("Invalid policy.");
            return false;
        }
    }
    // leaf node
    else if _json["ATT"] != serde_json::Value::Null {
        match _json["ATT"].as_str() {
            Some(s) => {
                // check if ATT in _attr list
                return (&_attr).into_iter().any(|v| v == &s);
            }
            None => {
                println!("ERROR attribute not in list");
                return false;
            }
        }
    }
    // error
    else {
        println!("Policy invalid. No AND or OR found");
        return false;
    }
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
    use cpabe_setup;
    use cpabe_keygen;
    use cpabe_encrypt;
    use cpabe_decrypt;
    use traverse_str;
    use traverse_json;
    //use kpabe_keygen;
    //use kpabe_encrypt;
    //use kpabe_decrypt;
    use blake2b_hash_to;
    use combine_string;
    use AbePolicy;
    use CpAbeCiphertext;
    use CpAbeSecretKey;
    //use KpCpAbeSecretKey;
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

    #[test]
    fn test_traverse() {
        let policyfalse = String::from(r#"joking-around?"#);
        let policy1 = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy2 = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy3 = String::from(
            r#"{"AND": [{"OR": [{"ATT": "C"}, {"ATT": "D"}]}, {"ATT": "B"}]}"#,
        );

        let mut _set0: Vec<String> = Vec::new();
        _set0.push(String::from("X"));
        _set0.push(String::from("Y"));

        let mut _set1: Vec<String> = Vec::new();
        _set1.push(String::from("A"));
        _set1.push(String::from("B"));

        let mut _set2: Vec<String> = Vec::new();
        _set2.push(String::from("C"));
        _set2.push(String::from("D"));

        let mut _set3: Vec<String> = Vec::new();
        _set3.push(String::from("A"));
        _set3.push(String::from("B"));
        _set3.push(String::from("C"));
        _set3.push(String::from("D"));

        assert_eq!(traverse_str(&_set1, &policyfalse), false);

        assert_eq!(traverse_str(&_set0, &policy1), false);
        assert_eq!(traverse_str(&_set1, &policy1), true);
        assert_eq!(traverse_str(&_set2, &policy1), false);
        assert_eq!(traverse_str(&_set3, &policy1), true);

        assert_eq!(traverse_str(&_set1, &policy2), true);
        assert_eq!(traverse_str(&_set2, &policy2), false);
        assert_eq!(traverse_str(&_set3, &policy2), true);

        assert_eq!(traverse_str(&_set1, &policy3), false);
        assert_eq!(traverse_str(&_set2, &policy3), false);
        assert_eq!(traverse_str(&_set3, &policy3), true);
    }

    #[test]
    fn test_cp_abe_and() {
        // setup scheme
        let (pk, msk) = cpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: LinkedList<String> = LinkedList::new();
        att_matching.push_back(String::from("A"));
        att_matching.push_back(String::from("B"));

        // a set of two attributes NOT matching the policy
        let mut att_not_matching: LinkedList<String> = LinkedList::new();
        att_not_matching.push_back(String::from("A"));
        att_not_matching.push_back(String::from("C"));

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
            None => println!("Cannot decrypt"),
            Some(x) => println!("Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        let _not_matching = cpabe_decrypt(&sk_not_matching, &ct_cp);
        match _not_matching {
            None => println!("Cannot decrypt"),
            Some(x) => println!("Result: {}", String::from_utf8(x).unwrap()),
        }
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
        let ct_kp: CpAbeCiphertext = kpabe_encrypt(&pk, &attributes, &plaintext.clone().into_bytes())
            .unwrap();
        // some assertions
        // TODO
        // a kp-abe SK key using msp
        let sk_kp: KpCpAbeSecretKey = kpabe_keygen(&msk, &msp1).unwrap();
        // some assertions
        // TODO
        // and now decrypt again
        let plaintext_kp: Vec<u8> = kpabe_decrypt(&sk_kp, &ct_kp).unwrap();
        let kp = String::from_utf8(plaintext_kp).unwrap();
        println!("plaintext_kp: {:?}", kp);
    }*/

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
}
