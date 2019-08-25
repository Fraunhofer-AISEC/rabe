//! This is the documentation for the RABE library.
//!
//! * Developped by Georg Bramm, Martin Schanzenbach
//! * Available from https://eprint.iacr.org/2017/807.pdf
//! * Type: encryption (attribute-based)
//! * Setting: bilinear groups (asymmetric), based on the bn library by zcash
//! * Date: 04/2018
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

pub mod ffi;
pub mod schemes;
pub mod utils;
