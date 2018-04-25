use schemes::bdabe::*;
use std::ops::Deref;
use libc::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;

#[no_mangle]
pub extern "C" fn bdabe_context_create() -> *mut BdabeContext {
    let _ctx = unsafe { transmute(Box::new(setup())) };
    _ctx
}

#[no_mangle]
pub extern "C" fn bdabe_context_destroy(ctx: *mut BdabeContext) {
    let _ctx: Box<BdabeContext> = unsafe { transmute(ctx) };
    _ctx.deref();
}

#[no_mangle]
pub extern "C" fn bdabe_keygen(
    pk: *mut BdabePublicKey,
    ska: *mut BdabeSecretAuthorityKey,
    name: *mut c_char,
) -> *mut BdabeUserKey {
    let n = unsafe { &mut *name };
    let mut _name = unsafe { CStr::from_ptr(n) };
    let name = String::from(_name.to_str().unwrap());
    let _pk = unsafe { &*pk };
    let _ska = unsafe { &*ska };
    let _key = unsafe { transmute(Box::new(keygen(&_pk, &_ska, &name))) };
    _key
}

#[no_mangle]
pub extern "C" fn bdabe_keygen_destroy(sk: *mut BdabeUserKey) {
    let _sk: Box<BdabeUserKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn bdabe_authgen(
    ctx: *mut BdabeContext,
    name: *mut c_char,
) -> *mut BdabeSecretAuthorityKey {
    let n = unsafe { &mut *name };
    let _ctx = unsafe { &*ctx };
    let mut _name = unsafe { CStr::from_ptr(n) };
    let name = String::from(_name.to_str().unwrap());
    let _key = unsafe { transmute(Box::new(authgen(&_ctx._pk, &_ctx._mk, &name))) };
    _key
}

#[no_mangle]
pub extern "C" fn bdabe_authgen_destroy(sk: *mut BdabeSecretAuthorityKey) {
    let _sk: Box<BdabeSecretAuthorityKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn bdabe_request_attribute_pk(
    pk: *mut BdabePublicKey,
    attribute: *mut c_char,
    sk: *mut BdabeSecretAuthorityKey,
) -> *mut BdabePublicAttributeKey {
    let a = unsafe { &mut *attribute };
    let mut _attribute = unsafe { CStr::from_ptr(a) };
    let _a = String::from(_attribute.to_str().unwrap());
    let _pk = unsafe { &*pk };
    let _sk = unsafe { &*sk };
    let _key = unsafe { transmute(Box::new(request_attribute_pk(&_pk, &_sk, &_a).unwrap())) };
    _key
}

#[no_mangle]
pub extern "C" fn bdabe_encrypt(
    pk: *mut BdabePublicKey,
    pks: *mut Vec<BdabePublicAttributeKey>,
    policy: *mut c_char,
    data: *mut &[u8],
) -> *mut BdabeCiphertext {
    let _pks = unsafe { &*pks };
    let _pk = unsafe { &mut *pk };
    let _data = unsafe { &mut *data };
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _ct = unsafe { transmute(Box::new(encrypt(&_pk, &_pks, &pol, &_data).unwrap())) };
    _ct
}

#[no_mangle]
pub extern "C" fn bdabe_decrypt(
    pk: *mut BdabePublicKey,
    sk: *mut BdabeUserKey,
    ct: *mut BdabeCiphertext,
) -> Vec<u8> {
    let _sk = unsafe { &mut *sk };
    let _pk = unsafe { &mut *pk };
    let _ct = unsafe { &mut *ct };
    let pt = decrypt(&_pk, &_sk, &_ct).unwrap();
    pt
}
