extern crate libc;

use self::libc::*;
use schemes::bsw::*;
use utils::policy::pest::PolicyLanguage;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::mem::transmute;
use std::string::String;
use std::slice;


/// A BSW ABE Context
#[derive(Serialize, Deserialize, PartialEq, Clone)]
#[repr(C)]
pub struct CpAbeContext {
    pub _msk: CpAbeMasterKey,
    pub _pk: CpAbePublicKey,
}

/// The BufferFfi is heap-allocated in Rust and returned to the calling C/C++
/// code. As a consequence, it is safer to wrap the heap pointer in a data
/// structure that we can re-construct when we have to free it. Note that
/// if you use this method you need to free the cipher text after:
///
/// ```cpp
/// BufferFfi* cipherText = nullptr;
///
/// ...
///
/// rabe_bsw_free_ciphertext(cipherText);
/// ```
#[repr(C)]
pub struct BufferFfi {
    data: *mut u8,
    len: usize,
}

#[no_mangle]
pub extern "C" fn rabe_bsw_context_create() -> *mut CpAbeContext {
    let (_pk, _msk) = setup();
    let ctx = Box::new(CpAbeContext {
            _pk,
            _msk,
    });

    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "C" fn rabe_bsw_context_destroy(ctx: *mut CpAbeContext) {
    if ctx.is_null() {
        return;
    }

    let _ctx: Box<CpAbeContext> = unsafe { Box::from_raw(ctx) };
    // Box will be de-allocated when it goes out of scope
}

#[no_mangle]
pub extern "C" fn rabe_bsw_keygen(
    ctx: *mut CpAbeContext,
    attributes: *const c_char,
) -> *mut CpAbeSecretKey {
    let _cstr = unsafe { CStr::from_ptr(attributes).to_str().unwrap() };
    let mut _attr_vec: Vec<&str> = _cstr.split(",").collect();
    let attrs_vec: &[&str] = &_attr_vec;

    let _ctx = unsafe { &*ctx };
    let sk = Box::new(keygen(&(_ctx._pk), &(_ctx._msk), &attrs_vec).unwrap());

    Box::into_raw(sk)
}

#[no_mangle]
pub extern "C" fn rabe_bsw_keygen_destroy(sk: *mut CpAbeSecretKey) {
    if sk.is_null() {
        return;
    }

    let _sk: Box<CpAbeSecretKey> = unsafe { Box::from_raw(sk) };
    // Box will be de-allocated when it goes out of scope
}

#[no_mangle]
pub extern "C" fn rabe_bsw_delegate(
    ctx: *mut CpAbeContext,
    sk: *mut CpAbeSecretKey,
    attributes: *mut Vec<String>,
) -> *mut CpAbeSecretKey {
    let _attr = unsafe { &mut *attributes };
    let attr_vec: Vec<_> = _attr.iter().map(|arg| arg.as_str()).collect();

    let _ctx = unsafe { &*ctx };
    let _sk = unsafe { &*sk };
    let _dsk = unsafe { transmute(Box::new(delegate(&_ctx._pk, &_sk, &attr_vec).unwrap())) };
    _dsk
}

#[no_mangle]
pub extern "C" fn rabe_bsw_encrypt(
    ctx: *mut std::ffi::c_void,
    policy: *mut c_char,
    policy_lang: *mut c_char,
    pt: *const u8,
    pt_len: usize,
    ct: *mut *mut BufferFfi,
) -> i32 {
    // Parse context
    if ctx.is_null() {
        return -1;
    }
    let _ctx = unsafe { &*(ctx as *mut CpAbeContext) };

    // Parse policy string
    let p = unsafe { &mut *policy };
    let _pol = unsafe { CStr::from_ptr(p) };
    let _pol_str = _pol.to_str();
    if _pol_str.is_err() {
        return -1;
    }
    let pol_tmp = _pol_str.unwrap().to_string();

    // Parse policy language
    let p_lang = unsafe { &mut *policy_lang };
    let mut _pol_lang = unsafe { CStr::from_ptr(p_lang) };
    let mut pol_lang_tmp = String::with_capacity(_pol_lang.to_bytes().len());
    let _pol_lang_str = match _pol_lang.to_str() {
        Ok(p) => p,
        Err(_) => return -1,
    };
    pol_lang_tmp.insert_str(0, _pol_lang_str);

    let _pol_enum : PolicyLanguage = match pol_lang_tmp.parse() {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // Parse plain-text
    let _slice = unsafe { slice::from_raw_parts(pt, pt_len) };
    let plaintext: Vec<u8> = _slice.to_vec();

    // Encrypt plaintext
    let _ct = match encrypt(&(_ctx._pk), &pol_tmp, _pol_enum, &plaintext) {
        Ok(ct) => ct,
        Err(_) => return -1,
    };

    let _ct_str = match serde_json::to_string(&_ct) {
        Ok(ser_str) => ser_str,
        Err(_) => return -1,
    };

    // Copy the serialized cipher-text into a heap-allocated buffer that we
    // pass to C/C++
    let mut data_vec = Vec::with_capacity(_ct_str.len() + 1);
    let size = _ct_str.len();
    data_vec.extend_from_slice(_ct_str.as_bytes());
    data_vec.push(0);

    // Create the BufferFfi struct
    let cipher_text = Box::new(BufferFfi {
        data: data_vec.as_mut_ptr(),
        len: size,
    });

    // Keep the Vec alive until we free it later
    std::mem::forget(data_vec);

    // Return the pointer to the struct
    unsafe {
        *ct = Box::into_raw(cipher_text);
    }
    0
}

#[no_mangle]
pub extern "C" fn rabe_bsw_free_buffer_ffi(buf: *mut BufferFfi) {
    if buf.is_null() {
        return;
    }

    unsafe {
        let _ = Box::from_raw(buf);
    }
}

#[no_mangle]
pub extern "C" fn rabe_bsw_decrypt_get_size(ct: *mut CpAbeCiphertext) -> u32 {
    let _ct = unsafe { &mut *ct };
    (_ct.data.len() as u32) - 16
}

#[no_mangle]
pub extern "C" fn rabe_bsw_decrypt(
    sk: *mut CpAbeSecretKey,
    ct: *mut u8,
    pt: *mut *mut BufferFfi,
) -> i32 {
    if sk.is_null() {
        return -1;
    }
    let _sk = unsafe { &mut *sk };

    // Parse cipher-text string
    let _ct_str = unsafe { CStr::from_ptr(ct as *mut c_char) };
    let ct_str = _ct_str.to_str();
    if ct_str.is_err() {
        // WARNING: we are failing here. cipher text is corrupted
        println!("rabe: error: cannot parse cipher-text to string");
        return -1;
    }

    let _serde_res = serde_json::from_str(ct_str.unwrap());
    if _serde_res.is_err() {
        println!("rabe: error: cannot parse cipher-text to struct");
        return -1;
    }
    let _ct: CpAbeCiphertext = _serde_res.unwrap();

    match decrypt(_sk, &_ct) {
        Ok(_pt) => {
            // Copy the plain-text into a heap-allocated buffer that we pass
            // to C/C++
            let mut data_vec = _pt.clone();
            let size = _pt.len();

            // Create the CipherText struct
            let plain_text = Box::new(BufferFfi {
                data: data_vec.as_mut_ptr(),
                len: size,
            });

            // Keep the Vec alive until we free it later
            std::mem::forget(data_vec);

            // Return the pointer to the struct
            unsafe {
                *pt = Box::into_raw(plain_text);
            }
            return 0;
        }
        Err(_) => return -1,
    }
}
