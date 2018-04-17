#![allow(dead_code)]

#[macro_use]
extern crate serde_derive;

extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate num_bigint;
extern crate blake2_rfc;

use libc::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;

#[macro_use]
extern crate arrayref;

pub mod policy;
pub mod ac17;
pub mod aw11;
pub mod bsw;
pub mod lsw;
pub mod mke08;
pub mod bdabe;
pub mod tools;
pub mod secretsharing;

use ac17::*;
//#[doc = /**
// * AC17
// *
// */]

#[no_mangle]
pub extern "C" fn ac17kpabe_context_create() -> *mut Ac17Context {

    let (pk, msk) = ac17::setup();
    let _ctx = unsafe { transmute(Box::new(Ac17Context { _msk: msk, _pk: pk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn ac17kpabe_context_destroy(ctx: *mut Ac17Context) {
    let _ctx: Box<Ac17Context> = unsafe { transmute(ctx) };
    // Drop reference for GC
}

#[no_mangle]
pub extern "C" fn ac17kpabe_secret_key_create(
    ctx: *mut Ac17Context,
    policy: *mut c_char,
) -> *mut Ac17KpSecretKey {
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _ctx = unsafe { &mut *ctx };
    let sk = kp_keygen(&_ctx._msk, &pol).unwrap();
    let _sk = unsafe {
        transmute(Box::new(Ac17KpSecretKey {
            _policy: sk._policy.clone(),
            _sk: Ac17SecretKey {
                _k: sk._sk._k.clone(),
                _k_0: sk._sk._k_0.clone(),
                _k_p: Vec::new(),
            },
        }))
    };
    _sk
}

#[no_mangle]
pub extern "C" fn ac17kpabe_secret_key_destroy(sk: *mut Ac17KpSecretKey) {
    let _sk: Box<Ac17KpSecretKey> = unsafe { transmute(sk) };
    // Drop reference for GC
}
/*
#[no_mangle]
pub extern "C" fn ac17kpabe_encrypt_native(
    pk: *mut Ac17PublicKey,
    attributes: *mut Vec<String>,
    //data??,
) -> i32 {
    let _attr = unsafe { &mut *attributes };
    let mut attr_vec: Vec<_> = _attr.iter() // do NOT into_iter()
        .map(|arg| arg.to_string())
        .collect();
    let _pk = unsafe { &mut *pk };
    //conv data?? to [u8],
    let ct = ac17kp_encrypt(&_pk, &attr_vec, _data).unwrap();
    let _ct = unsafe {
        transmute(Box::new(Ac17KpCiphertext {
            _attr: ct._attr.clone(),
            _c_0: ct._c_0.clone(),
            _c: ct._c.clone(),
            _c_p: ct._c_p.clone(),
            _ct: ct._ct.clone(),
            _iv: ct._iv.clone(),
        }))
    };
    _ct
}
*/

#[no_mangle]
pub extern "C" fn ac17kpabe_decrypt_native(sk: *mut Ac17KpCiphertext, ct: *mut c_char) -> i32 {
    //TODO: Deserialize ct
    //TODO: Call abe_decrypt
    //TODO: serialize returned pt and store under pt
    return 1;
}

use bsw::*;
use aw11::*;
use lsw::*;
use mke08::*;
use tools::*;
use policy::*;
use secretsharing::*;

// TESTS:

#[cfg(test)]
mod tests {}
