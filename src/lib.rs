//! This is the documentation for the RABE library.
//!
//! * Developped by Georg Bramm, Martin Schanzenbach, Julian Schuette
//! * Type: encryption (attribute-based)
//! * Setting: bilinear groups (asymmetric), based on a modified bn library by zcash
//! * Date: 07/2020
//!
#![allow(dead_code)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate arrayref;
extern crate base64;
extern crate bincode;
extern crate blake2_rfc;
extern crate bn;
extern crate byteorder;
extern crate crypto;
extern crate libc;
extern crate num_bigint;
extern crate rand;
extern crate serde;
extern crate serde_json;
/// foriegn function interface
pub mod ffi;
/// implemented schemes
pub mod schemes;
/// various utilities
pub mod utils;