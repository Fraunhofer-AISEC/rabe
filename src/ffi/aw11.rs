use schemes::aw11::*;
use std::ops::Deref;
use libc::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;

#[no_mangle]
pub extern "C" fn aw11_context_create() -> *mut Aw11GlobalContext {
    let gk = setup();
    let _ctx = unsafe { transmute(Box::new(Aw11GlobalContext { _gk: gk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn aw11_context_destroy(ctx: *mut Aw11GlobalContext) {
    let _ctx: Box<Aw11GlobalContext> = unsafe { transmute(ctx) };
    _ctx.deref();
}

#[no_mangle]
pub extern "C" fn aw11_auth_keygen(
    gk: *mut Aw11GlobalContext,
    attributes: *mut Vec<String>,
) -> *mut Aw11Context {
    let _attr = unsafe { &mut *attributes };
    let attr_vec: Vec<_> = _attr.iter().map(|arg| arg.to_string()).collect();
    let _gk = unsafe { &*gk };
    let auth = authgen(&_gk._gk, &attr_vec).unwrap();
    let _sk = unsafe {
        transmute(Box::new(Aw11Context {
            _msk: auth.1.clone(),
            _pk: auth.0.clone(),
        }))
    };
    _sk
}

#[no_mangle]
pub extern "C" fn aw11_auth_keygen_destroy(sk: *mut Aw11Context) {
    let _sk: Box<Aw11Context> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn aw11_user_keygen(
    gk: *mut Aw11GlobalContext,
    ctx: *mut Aw11Context,
    name: *mut c_char,
    attributes: *mut Vec<String>,
) -> *mut Aw11SecretKey {
    let n = unsafe { &mut *name };
    let mut _name = unsafe { CStr::from_ptr(n) };
    let name = String::from(_name.to_str().unwrap());
    let _attr = unsafe { &mut *attributes };
    let attr_vec: Vec<_> = _attr.iter().map(|arg| arg.to_string()).collect();
    let _gk = unsafe { &*gk };
    let _ctx = unsafe { &*ctx };
    let sk = keygen(&_gk._gk, &_ctx._msk, &name, &attr_vec).unwrap();
    let _sk = unsafe {
        transmute(Box::new(Aw11SecretKey {
            _gid: sk._gid.clone(),
            _attr: sk._attr.clone(),
        }))
    };
    _sk
}

#[no_mangle]
pub extern "C" fn aw11_user_keygen_destroy(sk: *mut Aw11SecretKey) {
    let _sk: Box<Aw11SecretKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn aw11_add_attribute(
    gk: *mut Aw11GlobalContext,
    ctx: *mut Aw11Context,
    attribute: *mut c_char,
    sk: *mut Aw11SecretKey,
) {
    let a = unsafe { &mut *attribute };
    let mut _attribute = unsafe { CStr::from_ptr(a) };
    let attribute = String::from(_attribute.to_str().unwrap());
    let _gk = unsafe { &*gk };
    let _ctx = unsafe { &*ctx };
    let _sk = unsafe { &mut *sk };
    add_attribute(&_gk._gk, &_ctx._msk, &attribute, _sk);
}


#[no_mangle]
pub extern "C" fn aw11_encrypt(
    gk: *mut Aw11GlobalKey,
    pks: *mut Vec<Aw11PublicKey>,
    policy: *mut c_char,
    data: *mut &[u8],
) -> *mut Aw11Ciphertext {
    let p = unsafe { &mut *policy };
    let mut _pol = unsafe { CStr::from_ptr(p) };
    let pol = String::from(_pol.to_str().unwrap());
    let _pk = unsafe { &*pks };
    let pk_vec: Vec<_> = _pk.iter().map(|pk| pk.clone()).collect();
    let _gk = unsafe { &mut *gk };
    let _data = unsafe { &mut *data };
    let _ct = unsafe { transmute(Box::new(encrypt(&_gk, &pk_vec, &pol, &_data).unwrap())) };
    _ct
}

#[no_mangle]
pub extern "C" fn aw11_decrypt(
    gk: *mut Aw11GlobalKey,
    sk: *mut Aw11SecretKey,
    ct: *mut Aw11Ciphertext,
) -> Vec<u8> {
    let _sk = unsafe { &mut *sk };
    let _ct = unsafe { &mut *ct };
    let _gk = unsafe { &mut *gk };
    let pt = decrypt(&_gk, &_sk, &_ct).unwrap();
    pt
}
