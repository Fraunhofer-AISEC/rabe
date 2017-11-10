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
    _h_a: Vec<(bn::G2)>,
    _e_gh_k: Vec<(bn::Gt)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeMasterKey {
    _g: bn::G1,
    _h: bn::G2,
    _a: Vec<(bn::Fr)>,
    _b: Vec<(bn::Fr)>,
    _g_d: Vec<(bn::G1)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct AbeCiphertext {
    _ct_0: Vec<(bn::G2)>,
    _ct_y: Vec<Vec<(bn::G1)>>,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}

pub struct CpAbeSecretKey {
    _sk_0: Vec<(bn::G2)>,
    _sk_y: Vec<Vec<(bn::G1)>>,
    _sk_t: Vec<(bn::G1)>,
}

pub struct KpAbeSecretKey {
    _sk_0: Vec<(bn::G2)>,
    _sk_y: Vec<(bn::G1, bn::G1, bn::G1)>,
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

// BOTH SHARE

pub fn abe_setup() -> (AbePublicKey, AbeMasterKey) {
    // random number generator
    let rng = &mut rand::thread_rng();
    // generator of group G1: g and generator of group G2: h
    let g = G1::one();
    let h = G2::one();
    // vectors
    // generate two instances of the k-linear assumption
    let mut a: Vec<(bn::Fr)> = Vec::new();
    let mut b: Vec<(bn::Fr)> = Vec::new();
    // generate random a and b's
    // without zero !
    for _i in 0usize..ASSUMPTION_SIZE {
        a.push(Fr::random(rng));
        b.push(Fr::random(rng));
    }

    // temp k vector
    let mut _d: Vec<(bn::Fr)> = Vec::new();
    // generate three instances of random Zp
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _d.push(Fr::random(rng));
    }
    // h^a vector
    let mut h_a: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        h_a.push(h * a[_i]);
    }
    h_a.push(h);
    // compute the e([k]_1, [A]_2) term
    let mut g_d: Vec<(bn::G1)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        g_d.push(g * _d[_i]);
    }
    // calculate the pairing between g and h
    let e_gh = pairing(g, h);
    let mut e_gh_k: Vec<(bn::Gt)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        e_gh_k.push(e_gh.pow(_d[_i] * a[_i] + _d[ASSUMPTION_SIZE]));
    }
    // set values of PK
    let pk = AbePublicKey {
        _h_a: h_a,
        _e_gh_k: e_gh_k,
    };
    // set values of MSK
    let msk = AbeMasterKey {
        _g: g,
        _h: h,
        _a: a,
        _b: b,
        _g_d: g_d,
    };
    // return PK and MSK
    return (pk, msk);
}

//////////////////////////////////////////
// CP ABE SCHEME:
//////////////////////////////////////////

pub fn cpabe_keygen(msk: &AbeMasterKey, s: &LinkedList<String>) -> Option<CpAbeSecretKey> {
    // if no attibutes or an empty policy
    // maybe add empty msk also here
    if s.is_empty() || s.len() == 0 {
        return None;
    }
    // random number generator
    let rng = &mut rand::thread_rng();
    // generate random r1 and r2 and sum of both
    // compute Br as well because it will be used later too
    let mut _r: Vec<(bn::Fr)> = Vec::new();
    let mut _br: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        _r.push(Fr::random(rng));
        _sum = _sum + _r[_i];
        _br.push(msk._b[_i] * _r[_i]);
    }
    _br.push(_sum);
    // now compute sk_0
    let mut _sk_0: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        _sk_0.push(msk._h * _br[_i]);
    }
    // now compute sk_(y,t)
    let mut _key: Vec<Vec<(bn::G1)>> = Vec::new();
    for attr in s {
        let mut _sk_y: Vec<(bn::G1)> = Vec::new();
        let sigma_y = Fr::random(rng);
        for _t in 0usize..ASSUMPTION_SIZE {
            let a_t = msk._a[_t].inverse().unwrap();
            let mut _sk_y_t = msk._g * (sigma_y * a_t);
            for _l in 0usize..(ASSUMPTION_SIZE + 1) {
                let str = combine_string(attr, _l, _t);
                println!("keygen-1: {:?}", str);
                _sk_y_t = _sk_y_t + hash_to(str.as_bytes()) * (_br[_l] * a_t);
            }
            _sk_y.push(_sk_y_t);
        }
        _sk_y.push(msk._g * -sigma_y);
        _key.push(_sk_y);
    }
    // now compute sk_t'
    let mut _sk_t: Vec<bn::G1> = Vec::new();
    let sigma = Fr::random(rng);
    for _t in 0usize..ASSUMPTION_SIZE {
        let mut _sk_tp = msk._g_d[_t];
        let a_t = msk._a[_t].inverse().unwrap();
        for _l in 0usize..(ASSUMPTION_SIZE + 1) {
            let str = combine_string(&String::from("01"), _l, _t);
            println!("keygen-2: {:?}", str);
            _sk_tp = _sk_tp + hash_to(str.as_bytes()) * (_br[_l] * a_t);
        }
        _sk_tp = _sk_tp + msk._g * (sigma * a_t);
        _sk_t.push(_sk_tp);
    }
    _sk_t.push(msk._g_d[ASSUMPTION_SIZE] + msk._g * -sigma);
    return Some(CpAbeSecretKey {
        _sk_0: _sk_0,
        _sk_y: _key,
        _sk_t: _sk_t,
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
    // pick randomness
    let mut _s: Vec<(bn::Fr)> = Vec::new();
    let mut _sum = Fr::zero();
    for _i in 0usize..ASSUMPTION_SIZE {
        _s.push(Fr::random(rng));
        _sum = _sum + _s[_i];
    }
    // compute the [As]_2 term
    let mut _ct_0: Vec<(bn::G2)> = Vec::new();
    for _i in 0usize..ASSUMPTION_SIZE {
        _ct_0.push(pk._h_a[_i] * _s[_i]);
    }
    _ct_0.push(pk._h_a[ASSUMPTION_SIZE] * _sum);
    // msp matrix M with size n1xn2
    let n1 = msp._m.len();
    let n2 = msp._m[0].len();
    //pre-compute hashes
    let mut hash_table: Vec<Vec<Vec<(bn::G1)>>> = Vec::new();
    for _j in 0..n2 {
        let mut _x: Vec<Vec<(bn::G1)>> = Vec::new();
        let input_hash1 = String::from("0") + &(_j + 1).to_string();
        for _l in 0..(ASSUMPTION_SIZE + 1) {
            let mut _y: Vec<(bn::G1)> = Vec::new();
            let input_hash2 = input_hash1.clone() + &(_l).to_string();
            for _t in 0..ASSUMPTION_SIZE {
                let str = input_hash2.clone() + &(_t).to_string();
                println!("encrypt-1: {:?}", str);
                _y.push(hash_to(str.as_bytes()));
            }
            _x.push(_y);
        }
        hash_table.push(_x);
    }
    // now compute ct_i,l
    let mut _ct_i: Vec<Vec<(bn::G1)>> = Vec::new();
    for _i in 0usize..n1 {
        let mut _ct_il: Vec<(bn::G1)> = Vec::new();
        let attr = &msp._pi[_i];
        for _l in 0..(ASSUMPTION_SIZE + 1) {
            let mut _ct_ilt = G1::zero();
            for _t in 0..ASSUMPTION_SIZE {
                let str = combine_string(attr, _l, _t);
                let mut _prod = hash_to(str.as_bytes());
                println!("encrypt-2: {:?}", str);
                for _j in 0usize..n2 {
                    // use hash_table
                    if msp._m[_i][_j] == 0 {
                        // if M(i,j)==0 : do nothing
                    } else if msp._m[_i][_j] == 1 {
                        // if M(i,j)==1 : add hash value
                        _prod = _prod + hash_table[_j][_l][_t];
                    } else if msp._m[_i][_j] == -1 {
                        // if M(i,j)==0 : sub hash value
                        _prod = _prod - hash_table[_j][_l][_t];
                    }
                }
                _ct_ilt = _ct_ilt + _prod * _s[_t];
            }
            _ct_il.push(_ct_ilt);
        }
        _ct_i.push(_ct_il);
    }

    let mut _cp = Gt::one();
    println!("secret-enc: {:?}", into_dec(_cp).unwrap());
    for _i in 0usize..ASSUMPTION_SIZE {
        _cp = _cp * pk._e_gh_k[_i].pow(_s[_i]);
        println!("secret-enc: {:?}", into_dec(_cp).unwrap());
    }
    //Encrypt plaintext using derived key from secret
    let mut sha = Sha3::sha3_256();
    match encode(&_cp, Infinite) {
        Err(_) => return None,
        Ok(e) => {
            sha.input(e.to_hex().as_bytes());
            let mut key: [u8; 32] = [0; 32];
            sha.result(&mut key);
            let mut iv: [u8; 16] = [0; 16];
            rng.fill_bytes(&mut iv);
            println!("key: {:?}", &key);
            let ct = AbeCiphertext {
                _ct_0: _ct_0,
                _ct_y: _ct_i,
                _ct: encrypt_aes(plaintext, &key, &iv).ok().unwrap(),
                _iv: iv,
            };
            return Some(ct);
        }
    }
}

pub fn cpabe_decrypt(sk: &CpAbeSecretKey, ct: &AbeCiphertext) -> Option<Vec<u8>> {
    let mut num = Gt::one();
    let mut den = Gt::one();

    // TODO: add pruning check
    // i.e. if policy not satisfied by attributes return here

    for _i in 0usize..(ASSUMPTION_SIZE + 1) {
        let mut prod_num = G1::one(); // ct
        let mut prod_den = G1::one(); // sk

        for _j in 0..ct._ct_y.len() {
            prod_den = prod_den + sk._sk_y[_j][_i];
            prod_num = prod_num + ct._ct_y[_j][_i];
        }
        num = num * pairing(prod_num + sk._sk_t[_i], ct._ct_0[_i]);
        den = den * pairing(prod_den, sk._sk_0[_i]);
    }
    let _secret = num * den.inverse();
    println!("secret-dec: {:?}", into_dec(_secret).unwrap());
    // Decrypt plaintext using derived secret from abe scheme
    let mut sha = Sha3::sha3_256();
    match encode(&_secret, Infinite) {
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
    plaintext: &[u8],
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
pub extern "C" fn kpabe_secret_key_destroy(sk: *mut KpAbeSecretKey) {
    let _sk: Box<KpAbeSecretKey> = unsafe { transmute(sk) };
    // Drop reference for GC
}

#[no_mangle]
pub extern "C" fn kpabe_decrypt_native(sk: *mut KpAbeSecretKey, ct: *mut c_char) -> i32 {
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

pub fn hash_to(data: &[u8]) -> bn::G1 {
    /*let mut sha = Sha3::sha3_256();
    sha.input(data);
    let i = BigInt::parse_bytes(sha.result_str().as_bytes(), 16).unwrap();
    // TODO: check if there is a better (faster) hashToElement method
    return G1::one().mul(Fr::from_str(&i.to_str_radix(10)).unwrap());
    */
    return better_hash_to(data);
}

fn pop(input: &[u8]) -> &[u8; 64] {
    array_ref!(input, 0, 64)
}

pub fn better_hash_to(data: &[u8]) -> bn::G1 {
    let hash = blake2b(64, &[], data);
    return G1::one().mul(Fr::interpret(pop(hash.as_bytes())));
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
    use hash_string_to_element;
    use combine_string;
    use AbePolicy;
    use AbeCiphertext;
    use CpAbeSecretKey;
    use KpAbeSecretKey;
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
        not_matching.push_back(String::from("C"));
        not_matching.push_back(String::from("B"));

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
        let sk_matching: CpAbeSecretKey = cpabe_keygen(&msk, &matching).unwrap();
        // a cp-abe SK key NOT matching
        //let sk_not_matching: CpAbeSecretKey = cpabe_keygen(&msk, &not_matching).unwrap();

        // some assertions
        // TODO

        // and now decrypt again with mathcing sk
        let plaintext_matching: Vec<u8> = cpabe_decrypt(&sk_matching, &ct_cp).unwrap();

        // and now decrypt again without matching sk
        //let plaintext_not_matching: Vec<u8> = cpabe_decrypt(&sk_not_matching, &ct_cp).unwrap();

        println!(
            "plaintext_matching: {:?}",
            String::from_utf8(plaintext_matching).unwrap()
        );

        //println!(
        //    "plaintext_not_matching: {:?}",
        //    String::from_utf8(plaintext_not_matching).unwrap()
        //);
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
        let p1 = vec![0, 0, -1];
        let p2 = vec![1, 0, 1];
        let p3 = vec![0, -1, 0];
        let p4 = vec![1, 1, 0];
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
