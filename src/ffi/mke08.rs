use schemes::mke08::*;
use std::ops::Deref;
use libc::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;

#[no_mangle]
pub extern "C" fn mke08_context_create() -> *mut Mke08Context {
    let _ctx = unsafe { transmute(Box::new(setup())) };
    _ctx
}

#[no_mangle]
pub extern "C" fn mke08_context_destroy(ctx: *mut Mke08Context) {
    let _ctx: Box<Mke08Context> = unsafe { transmute(ctx) };
    _ctx.deref();
}

#[no_mangle]
pub extern "C" fn mke08_keygen(ctx: *mut Mke08Context, name: *mut c_char) -> *mut Mke08UserKey {
    let n = unsafe { &mut *name };
    let mut _name = unsafe { CStr::from_ptr(n) };
    let name = String::from(_name.to_str().unwrap());
    let _ctx = unsafe { &*ctx };
    let _key = unsafe { transmute(Box::new(keygen(&_ctx._pk, &_ctx._mk, &name))) };
    _key
}

#[no_mangle]
pub extern "C" fn mke08_keygen_destroy(sk: *mut Mke08UserKey) {
    let _sk: Box<Mke08UserKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn mke08_authgen(name: *mut c_char) -> *mut Mke08SecretAuthorityKey {
    let n = unsafe { &mut *name };
    let mut _name = unsafe { CStr::from_ptr(n) };
    let name = String::from(_name.to_str().unwrap());
    let _key = unsafe { transmute(Box::new(authgen(&name))) };
    _key
}

#[no_mangle]
pub extern "C" fn mke08_authgen_destroy(sk: *mut Mke08SecretAuthorityKey) {
    let _sk: Box<Mke08SecretAuthorityKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn mke08_request_authority_pk(
    ctx: *mut Mke08Context,
    attribute: *mut c_char,
    sk: *mut Mke08SecretAuthorityKey,
) -> *mut Mke08PublicAttributeKey {
    let a = unsafe { &mut *attribute };
    let mut _attribute = unsafe { CStr::from_ptr(a) };
    let attribute = String::from(_attribute.to_str().unwrap());
    let _ctx = unsafe { &*ctx };
    let _sk = unsafe { &*sk };
    let _key = unsafe {
        transmute(Box::new(
            request_authority_pk(&_ctx._pk, &attribute, &_sk).unwrap(),
        ))
    };
    _key
}

#[no_mangle]
pub extern "C" fn mke08_request_authority_sk(
    attribute: *mut c_char,
    sk: *mut Mke08SecretAuthorityKey,
    pku: *mut Mke08PublicUserKey,
) -> *mut Mke08SecretAttributeKey {
    let a = unsafe { &mut *attribute };
    let mut _attribute = unsafe { CStr::from_ptr(a) };
    let attribute = String::from(_attribute.to_str().unwrap());
    let _sk = unsafe { &*sk };
    let _pku = unsafe { &*pku };
    let _key = unsafe {
        transmute(Box::new(
            request_authority_sk(&attribute, &_sk, &_pku).unwrap(),
        ))
    };
    _key
}

#[no_mangle]
pub extern "C" fn mke08_encrypt(
    pk: *mut Mke08PublicKey,
    pks: *mut Vec<Mke08PublicAttributeKey>,
    policy: *mut c_char,
    data: *mut &[u8],
) -> *mut Mke08Ciphertext {
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
pub extern "C" fn mke08_decrypt(
    pk: *mut Mke08PublicKey,
    sk: *mut Mke08UserKey,
    ct: *mut Mke08Ciphertext,
) -> Vec<u8> {
    let _sk = unsafe { &mut *sk };
    let _pk = unsafe { &mut *pk };
    let _ct = unsafe { &mut *ct };
    let pt = decrypt(&_pk, &_sk, &_ct).unwrap();
    pt
}
