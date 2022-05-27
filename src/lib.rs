#![feature(int_roundings)]
//! rabe is a rust library implementing several Attribute Based Encryption (ABE) schemes using a modified version of the `bn` library of zcash (type-3 pairing / Baretto Naering curve). The modification of `bn` brings in `serde` or `borsh` instead of the deprecated `rustc_serialize`.
/// The standard serialization library is `serde`. If you want to use `borsh`, you need to specify it as feature.
///
/// For integration in distributed applications contact [us](mailto:info@aisec.fraunhofer.de).
///!
///! * Developped by Bramm, Schanzenbach, Schuette
#[allow(dead_code)]

#[cfg(feature = "borsh")]
extern crate borsh;
#[cfg(not(feature = "borsh"))]
extern crate serde;
extern crate serde_json;
extern crate bit_vec;
extern crate rabe_bn;
extern crate rand;
extern crate pest;
extern crate eax;
extern crate aes;
extern crate sha3;
#[macro_use]
extern crate pest_derive;
extern crate nalgebra;
extern crate gmorph;
extern crate num_bigint;

/// rabe schemes
pub mod schemes;
/// rabe library utilities
pub mod utils;
/// rabe error, that is used in the library
pub mod error;

