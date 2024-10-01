extern crate libc;

use self::libc::*;
use schemes::bsw::*;
use utils::policy::pest::PolicyLanguage;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::mem;
use std::mem::transmute;
use std::ops::Deref;
use std::string::String;
use std::{ptr, slice};


/// A BSW ABE Context
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct CpAbeContext {
    pub _msk: CpAbeMasterKey,
    pub _pk: CpAbePublicKey,
}

#[no_mangle]
pub extern "C" fn rabe_bsw_context_create() -> *mut CpAbeContext {
    let (_pk, _msk) = setup();
    let _ctx = unsafe {
        transmute(Box::new(CpAbeContext {
            _pk: _pk,
            _msk: _msk,
        }))
    };
    _ctx
}

#[no_mangle]
pub extern "C" fn rabe_bsw_context_destroy(ctx: *mut CpAbeContext) {
    let _ctx: Box<CpAbeContext> = unsafe { transmute(ctx) };
    let _context = _ctx.deref();
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
    let _sk = unsafe {
        transmute(Box::new(
            keygen(&(_ctx._pk), &(_ctx._msk), &attrs_vec).unwrap(),
        ))
    };
    _sk
}

#[no_mangle]
pub extern "C" fn rabe_bsw_keygen_destroy(sk: *mut CpAbeSecretKey) {
    let _sk: Box<CpAbeSecretKey> = unsafe { transmute(sk) };
    let _sk = _sk.deref();
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
    ctx: *mut CpAbeContext,
    policy: *mut c_char,
    pt: *mut u8,
    pt_len: u32,
    ct_buf: *mut *mut u8,
    ct_buf_len: *mut u32,
) -> i32 {
    let p = unsafe { &mut *policy };
    let mut _pol = unsafe { CStr::from_ptr(p) };
    let mut pol_tmp = String::with_capacity(_pol.to_bytes().len());
    let _pol_str = _pol.to_str();
    if let Err(_) = _pol_str {
        return -1;
    }
    pol_tmp.insert_str(0, _pol_str.unwrap());
    let _ctx = unsafe { &*ctx };
    let _slice = unsafe { slice::from_raw_parts(pt, pt_len as usize) };
    let mut _data_vec = Vec::new();
    _data_vec.extend_from_slice(_slice);
    /*
    let _res = encrypt(&(_ctx._pk), &pol_tmp, PolicyLanguage::JsonPolicy, &_data_vec);

    if let None = _res {
        return -1;
    }
    let _ct = _res.unwrap();
    */
    let _ct = match encrypt(&(_ctx._pk), &pol_tmp, PolicyLanguage::JsonPolicy, &_data_vec) {
        Ok(ct) => ct,
        Err(_) => return -1,
    };

    let _ct_str = match serde_json::to_string(&_ct) {
        Ok(ser_str) => ser_str,
        Err(_) => return -1,
    };

    /*
    let _ct_ser_str = serde_json::to_string(&_ct);
    if let Err(_) = _ct_ser_str {
        return -1;
    }
    let _ct_str = _ct_ser_str.unwrap();
    */

    unsafe {
        let _size = (_ct_str.len() + 1) as u32;
        *ct_buf = libc::malloc(_size as usize) as *mut u8;
        ptr::write_bytes(*ct_buf, 0, _size as usize);
        ptr::copy_nonoverlapping(_ct_str.as_ptr(), *ct_buf, _ct_str.len() as usize);

        ptr::copy_nonoverlapping(&_size, ct_buf_len, mem::size_of::<u32>());
    }
    0
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
    ct_len: u32,
    pt_buf: *mut *mut u8,
    pt_buf_len: *mut u32,
) -> i32 {
    let _sk = unsafe { &mut *sk };

    let mut _cstr = unsafe { CStr::from_ptr(ct as *mut c_char) };
    let _cstr_str = _cstr.to_str();
    if let Err(_) = _cstr_str {
        return -1;
    }
    assert!(_cstr_str.unwrap().len() == (ct_len - 1) as usize);
    let _serde_res = serde_json::from_str(_cstr_str.unwrap());
    if let Err(_) = _serde_res {
        return -1;
    }
    let _ct: CpAbeCiphertext = _serde_res.unwrap();

    match decrypt(_sk, &_ct) {
        Ok(_pt) => {
            unsafe {
                let _size = (_ct.data.len() as u32) - 16;
                *pt_buf = libc::malloc(_size as usize) as *mut u8;
                ptr::copy_nonoverlapping(&_pt.as_slice()[0], *pt_buf, _size as usize);
                ptr::copy_nonoverlapping(&_size, pt_buf_len, mem::size_of::<u32>());
            }
            return 0;
        }
        Err(_) => return -1,
    }
}
