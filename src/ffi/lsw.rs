use schemes::lsw::*;
use std::ops::Deref;
use libc::*;
use bn::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;

#[no_mangle]
pub extern "C" fn lsw_context_create() -> *mut KpAbeContext {
    let _ctx = unsafe { transmute(Box::new(setup())) };
    _ctx
}

#[no_mangle]
pub extern "C" fn lsw_context_destroy(ctx: *mut KpAbeContext) {
    let _ctx: Box<KpAbeContext> = unsafe { transmute(ctx) };
    _ctx.deref();
}

#[no_mangle]
pub extern "C" fn lsw_keygen(ctx: *mut KpAbeContext, policy: *mut c_char) -> *mut KpAbeSecretKey {
    let p = unsafe { &mut *policy };
    let mut _pol = unsafe { CStr::from_ptr(p) };
    let pol = String::from(_pol.to_str().unwrap());
    let _ctx = unsafe { &*ctx };
    let _sk = unsafe { transmute(Box::new(keygen(&_ctx._pk, &_ctx._msk, &pol).unwrap())) };
    _sk
}

#[no_mangle]
pub extern "C" fn lsw_keygen_destroy(sk: *mut KpAbeSecretKey) {
    let _sk: Box<KpAbeSecretKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn lsw_encrypt(
    pk: *mut KpAbePublicKey,
    attributes: *mut Vec<String>,
    data: *mut &[u8],
) -> *mut KpAbeCiphertext {
    let _attr = unsafe { &mut *attributes };
    let attr_vec: Vec<_> = _attr.iter().map(|arg| arg.to_string()).collect();
    let _pk = unsafe { &*pk };
    let _data = unsafe { &mut *data };
    let _ct = unsafe { transmute(Box::new(encrypt(&_pk, &attr_vec, &_data.to_vec()).unwrap())) };
    _ct
}

#[no_mangle]
pub extern "C" fn lsw_decrypt(sk: *mut KpAbeSecretKey, ct: *mut KpAbeCiphertext) -> Vec<u8> {
    let _sk = unsafe { &mut *sk };
    let _ct = unsafe { &mut *ct };
    let pt = decrypt(&_sk, &_ct).unwrap();
    pt
}
