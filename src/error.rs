use std::{fmt::{
    Display,
    Result,
    Formatter
}, cmp};
use pest::error::{Error as PestError, LineColLocation};
use utils::policy::pest::json::Rule as jsonRule;
use utils::policy::pest::human::Rule as humanRule;
use std::array::TryFromSliceError;
use rabe_bn::FieldError;
#[cfg(not(feature = "borsh"))]
use serde::{Serialize, Deserialize};

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};

/// Simple, generic Error that is compose of a String
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(not(feature = "borsh"), derive(Serialize, Deserialize))]
pub struct RabeError {
    details: String,
}

impl RabeError {
    /// Creates a new Error
    pub fn new(msg: &str) -> RabeError {
        RabeError { details: msg.to_string() }
    }
}

impl Display for RabeError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Error: {}", self.details)
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
impl From<FieldError> for RabeError {
    fn from(error: FieldError) -> Self {
        // Aead's error is intentionally opaque, there is no more information in here
        match error {
            FieldError::InvalidSliceLength => RabeError::new("FieldError::InvalidSliceLength"),
            FieldError::InvalidU512Encoding => RabeError::new("FieldError::InvalidU512Encoding"),
            FieldError::NotMember => RabeError::new("FieldError::NotMember"),
        }
    }
}

impl From<TryFromSliceError> for RabeError {
    fn from(_error: TryFromSliceError) -> Self {
        RabeError::new(&_error.to_string())
    }
}

impl From<String> for RabeError {
    fn from(_error: String) -> Self {
        RabeError::new(_error.as_str())
    }
}