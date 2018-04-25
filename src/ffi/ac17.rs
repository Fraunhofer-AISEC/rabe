use schemes::ac17::*;
use std::ops::Deref;
use libc::*;
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;

#[no_mangle]
pub extern "C" fn ac17_context_create() -> *mut Ac17Context {
    let (pk, msk) = setup();
    let _ctx = unsafe { transmute(Box::new(Ac17Context { _msk: msk, _pk: pk })) };
    _ctx
}

#[no_mangle]
pub extern "C" fn ac17_context_destroy(ctx: *mut Ac17Context) {
    let _ctx: Box<Ac17Context> = unsafe { transmute(ctx) };
    _ctx.deref();
}

#[no_mangle]
pub extern "C" fn ac17_cpkeygen(
    ctx: *mut Ac17Context,
    attributes: *mut Vec<String>,
) -> *mut Ac17CpSecretKey {
    let _attr = unsafe { &mut *attributes };
    let attr_vec: Vec<_> = _attr.iter().map(|arg| arg.to_string()).collect();
    let _ctx = unsafe { &mut *ctx };
    let sk = cp_keygen(&_ctx._msk, &attr_vec).unwrap();
    let _sk = unsafe {
        transmute(Box::new(Ac17CpSecretKey {
            _attr: sk._attr.clone(),
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
pub extern "C" fn ac17_cpkeygen_destroy(sk: *mut Ac17CpSecretKey) {
    let _sk: Box<Ac17CpSecretKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn ac17_cpencrypt(
    pk: *mut Ac17PublicKey,
    policy: *mut c_char,
    data: *mut &[u8],
) -> *mut Ac17CpCiphertext {
    let t = unsafe { &mut *policy };
    let mut _policy = unsafe { CStr::from_ptr(t) };
    let pol = String::from(_policy.to_str().unwrap());
    let _pk = unsafe { &mut *pk };
    let _data = unsafe { &mut *data };
    //conv data?? to [u8],
    let ct = cp_encrypt(&_pk, &pol, &_data).unwrap();
    let _ct = unsafe {
        transmute(Box::new(Ac17CpCiphertext {
            _policy: ct._policy.clone(),
            _ct: ct._ct.clone(),
        }))
    };
    _ct
}

#[no_mangle]
pub extern "C" fn ac17_cpdecrypt(sk: *mut Ac17CpSecretKey, ct: *mut Ac17CpCiphertext) -> Vec<u8> {
    let _sk = unsafe { &mut *sk };
    let _ct = unsafe { &mut *ct };
    let pt = cp_decrypt(&_sk, &_ct).unwrap();
    pt
}

#[no_mangle]
pub extern "C" fn ac17_kpkeygen(
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
pub extern "C" fn ac17_kp_keygen_destroy(sk: *mut Ac17KpSecretKey) {
    let _sk: Box<Ac17KpSecretKey> = unsafe { transmute(sk) };
    _sk.deref();
}

#[no_mangle]
pub extern "C" fn ac17_kpencrypt(
    pk: *mut Ac17PublicKey,
    attributes: *mut Vec<String>,
    data: *mut &[u8],
) -> *mut Ac17KpCiphertext {
    let _attr = unsafe { &mut *attributes };
    let attr_vec: Vec<_> = _attr.iter() // do NOT into_iter()
        .map(|arg| arg.to_string())
        .collect();
    let _pk = unsafe { &mut *pk };
    let _data = unsafe { &mut *data };
    //conv data?? to [u8],
    let ct = kp_encrypt(&_pk, &attr_vec, &_data).unwrap();
    let _ct = unsafe {
        transmute(Box::new(Ac17KpCiphertext {
            _attr: ct._attr.clone(),
            _ct: ct._ct.clone(),
        }))
    };
    _ct
}

#[no_mangle]
pub extern "C" fn ac17_kpdecrypt(sk: *mut Ac17KpSecretKey, ct: *mut Ac17KpCiphertext) -> Vec<u8> {
    let _sk = unsafe { &mut *sk };
    let _ct = unsafe { &mut *ct };
    let pt = kp_decrypt(&_sk, &_ct).unwrap();
    pt
}
