use utils::policy::pest::PolicyValue::{Object, Array, Number, Boolean};
use pest::{
    Parser,
    error::Error
};
use std::fmt;
use RabeError;

pub(crate) mod human;
pub(crate) mod json;

use self::json::JSONPolicyParser;
use self::human::HumanPolicyParser;

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
pub enum PolicyLanguage {
    JsonPolicy,
    HumanPolicy,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum PolicyType {
    And,
    Or,
    Leaf
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum PolicyValue<'a> {
    Object(Box<(&'a str, Option<PolicyValue<'a>>)>),
    Array(Vec<PolicyValue<'a>>),
    String(&'a str),
    Number(f64),
    Boolean(bool),
    Null,
}

pub fn parse(policy: &str, language: PolicyLanguage) -> Result<PolicyValue, RabeError> {
    use pest::iterators::Pair;
    match language {
        PolicyLanguage::JsonPolicy => {
            use utils::policy::pest::json::Rule::content;
            match JSONPolicyParser::parse(content, policy) {
                Ok(mut result) => Ok(json::parse(result.next().unwrap())),
                Err(e) => Err(e.into())
            }
        },
        PolicyLanguage::HumanPolicy => {
            use utils::policy::pest::human::Rule::content;
            match HumanPolicyParser::parse(content, policy) {
                Ok(mut result) => Ok(human::parse(result.next().unwrap())),
                Err(e) => Err(e.into())
            }
        }
    }
}