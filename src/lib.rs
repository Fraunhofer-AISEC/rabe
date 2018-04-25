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

#[macro_use]
extern crate arrayref;

pub mod utils;
pub mod schemes;
pub mod ffi;
