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
extern crate base64;
extern crate blake2_rfc;
extern crate rabe_bn;
extern crate byteorder;
extern crate libc;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate pest;
extern crate ccm;
extern crate aes;
extern crate sha3;
#[macro_use]
extern crate pest_derive;

/// implemented schemes
pub mod schemes;
/// various utilities
pub mod utils;

use std::{fmt::{
    Display,
    Result,
    Formatter
}, error::Error, cmp};
use pest::error::{Error as PestError, LineColLocation};
use utils::policy::pest::json::Rule as jsonRule;
use utils::policy::pest::human::Rule as humanRule;
use ccm::aead;

#[derive(Debug)]
pub struct RabeError {
    details: String,
}

impl RabeError {
    fn new(msg: &str) -> RabeError {
        RabeError { details: msg.to_string() }
    }
}

impl Display for RabeError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "RabeError: {}", self.details)
    }
}

impl Error for RabeError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl From<PestError<jsonRule>> for RabeError {
    fn from(error: PestError<jsonRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        RabeError::new(
            format!("Json Policy Error in line {}\n", line).as_ref()
        )
    }
}

impl From<PestError<humanRule>> for RabeError {
    fn from(error: PestError<humanRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        RabeError::new(
            format!("Json Policy Error in line {}\n", line).as_ref()
        )
    }
}

impl From<aead::Error> for RabeError {
    fn from(_error: aead::Error) -> Self {
        RabeError::new("Error during symmetric encryption or decryption!") // Aead's error is intentionally opaque, there is no more information in here
    }
}
