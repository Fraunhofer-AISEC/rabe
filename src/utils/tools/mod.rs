#[allow(dead_code)]
extern crate bn;
extern crate crypto;
extern crate num_bigint;
extern crate rand;
extern crate serde;
extern crate serde_json;

use bn::*;
use num_bigint::ToBigInt;
use std::collections::HashSet;
use utils::policy::pest::{PolicyLanguage, PolicyValue, parse, PolicyType};

pub fn is_negative(_attr: &String) -> bool {
    let first_char = &_attr[..1];
    return first_char == '!'.to_string();
}

pub fn usize_to_fr(_i: usize) -> Fr {
    let _i = _i.to_bigint().unwrap();
    return Fr::from_str(&_i.to_str_radix(10)).unwrap();
}

pub fn contains(data: &Vec<String>, value: &String) -> bool {
    let len = data.into_iter()
        .filter(|&i| i == value)
        .collect::<Vec<_>>()
        .len();
    return len >= 1;
}

// used to check if a set of attributes is a subset of another
pub fn is_subset(_subset: &Vec<String>, _attr: &Vec<String>) -> bool {
    let super_set: HashSet<_> = _attr.iter().cloned().collect();
    let sub_set: HashSet<_> = _subset.iter().cloned().collect();
    return sub_set.is_subset(&super_set);
}

// used to traverse / check policy tree
pub fn traverse_policy(_attr: &Vec<String>, _json: &PolicyValue, _type: PolicyType) -> bool {
    return (_attr.len() > 0) && match _json {
        PolicyValue::Null => false,
        PolicyValue::String(val) => (&_attr).into_iter().any(|x| x == val),
        PolicyValue::Boolean(b) => true,
        PolicyValue::Object(obj) => {
            return match obj.0.to_lowercase().as_str() {
                "and" => traverse_policy(_attr, &obj.1.as_ref().unwrap(), PolicyType::And),
                "or" => traverse_policy(_attr, &obj.1.as_ref().unwrap(), PolicyType::Or),
                _ => true,
            }
        },
        PolicyValue::Array(arrayref) => {
            return match _type {
                PolicyType::And => {
                    let mut ret = true;
                    for (i, obj) in arrayref.iter().enumerate() {
                        ret &= traverse_policy(_attr, obj, PolicyType::Leaf)
                    }
                    ret
                },
                PolicyType::Or => {
                    let mut ret = false;
                    for (i, obj) in arrayref.iter().enumerate() {
                        ret |= traverse_policy(_attr, obj, PolicyType::Leaf)
                    }
                    ret
                },
                _ => false,
            };
        },
        PolicyValue::Number(n) => true,
        _ => false
    };
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_traverse() {
        let policy_false = String::from(r#"joking-around?"#);
        let policy1 = String::from(r#"{"AND": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy2 = String::from(r#"{"OR": [{"ATT": "A"}, {"ATT": "B"}]}"#);
        let policy3 = String::from(
            r#"{"AND": [{"OR": [{"ATT": "C"}, {"ATT": "D"}]}, {"ATT": "B"}]}"#,
        );
        let mut _set0: Vec<String> = Vec::new();
        _set0.push(String::from("X"));
        _set0.push(String::from("Y"));

        let mut _set1: Vec<String> = Vec::new();
        _set1.push(String::from("A"));
        _set1.push(String::from("B"));

        let mut _set2: Vec<String> = Vec::new();
        _set2.push(String::from("C"));
        _set2.push(String::from("D"));

        let mut _set3: Vec<String> = Vec::new();
        _set3.push(String::from("A"));
        _set3.push(String::from("B"));
        _set3.push(String::from("C"));
        _set3.push(String::from("D"));

        assert_eq!(traverse_str(&_set1, &policyfalse), false);

        assert_eq!(traverse_str(&_set0, &policy1), false);
        assert_eq!(traverse_str(&_set1, &policy1), true);
        assert_eq!(traverse_str(&_set2, &policy1), false);
        assert_eq!(traverse_str(&_set3, &policy1), true);

        assert_eq!(traverse_str(&_set1, &policy2), true);
        assert_eq!(traverse_str(&_set2, &policy2), false);
        assert_eq!(traverse_str(&_set3, &policy2), true);

        assert_eq!(traverse_str(&_set1, &policy3), false);
        assert_eq!(traverse_str(&_set2, &policy3), false);
        assert_eq!(traverse_str(&_set3, &policy3), true);
    }
}
