use pest::Parser;
use std::string::String;
use RabeError;

pub(crate) mod json;

use self::json::JSONPolicyParser;

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
    Object((PolicyType, Box<PolicyValue<'a>>)),
    Array(Vec<PolicyValue<'a>>),
    String(&'a str),
}

pub fn parse(policy: &str, language: PolicyLanguage) -> Result<PolicyValue, RabeError> {
    match language {
        PolicyLanguage::JsonPolicy => {
            use utils::policy::pest::json::Rule;
            match JSONPolicyParser::parse(Rule::content, policy) {
                Ok(mut result) => Ok(json::parse(result.next().unwrap())),
                Err(e) => Err(e.into())
            }
        },
        _ => Err(RabeError::new("unkown policy language"))
    }
}

pub fn serialize_policy(val: &PolicyValue, language: PolicyLanguage) -> String {
    use self::PolicyValue::*;
    match language {
        PolicyLanguage::JsonPolicy => {
            match val {
                Object(obj) => {
                    match obj.0 {
                        PolicyType::And => format!("{{\"name\": \"and\", {}}}", serialize_policy(obj.1.as_ref(), language)),
                        PolicyType::Or => format!("{{\"name\": \"or\", {}}}", serialize_policy(obj.1.as_ref(), language)),
                        PolicyType::Leaf => serialize_policy(&obj.1.as_ref(), language)
                    }
                },
                Array(a) => {
                    let contents: Vec<_> = a.iter().map(|val| serialize_policy(val, language)).collect();
                    format!("\"children\": [{}]", contents.join(", "))
                }
                String(s) => format!("{{\"name\": \"{}\"}}", s),
            }
        },
        _ => "unkown policy language".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_parsing() {
        let pol = String::from(r#"{"name": "A"}"#);
        let json: PolicyValue = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy);
        assert_eq!(serialized_json, pol);
    }

    #[test]
    fn test_children_parsing() {
        let pol = String::from(r#"{"name": "and", "children": [{"name": "B"}, {"name": "C"}]}"#);
        let json: PolicyValue = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json =serialize_policy(&json, PolicyLanguage::JsonPolicy);
        assert_eq!(serialized_json, pol);
    }
}