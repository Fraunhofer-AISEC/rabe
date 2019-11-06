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

pub fn is_negative(_attr: &String) -> bool {
    let first_char = &_attr[..1];
    return first_char == '!'.to_string();
}

pub fn usize_to_fr(_i: usize) -> Fr {
    let _i = _i.to_bigint().unwrap();
    return Fr::from_str(&_i.to_str_radix(10)).unwrap();
}

pub fn string_to_json(policy: &String) -> Option<serde_json::Value> {
    match serde_json::from_str(policy) {
        Err(e) => {
            println!("string_to_json ERROR: {:?}", e);
            return None;
        }
        Ok(pol) => {
            return Some(pol);
        }
    }
}

pub fn contains(data: &Vec<(String)>, value: &String) -> bool {
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

pub fn traverse_str(_attr: &Vec<String>, _policy: &String) -> bool {
    match string_to_json(_policy) {
        None => return false,
        Some(_value) => return traverse_json(_attr, &_value),
    }
}

// used to traverse / check policy tree
pub fn traverse_json(_attr: &Vec<String>, _json: &serde_json::Value) -> bool {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return false;
    }
    if _attr.len() == 0 {
        println!("Error: No attributes in List!");
        return false;
    }
    // inner node or
    if _json["OR"].is_array() {
        let _num_terms = _json["OR"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = false;
            for _i in 0usize.._num_terms {
                ret = ret || traverse_json(_attr, &_json["OR"][_i]);
            }
            return ret;
        } else {
            println!("Error: Invalid policy (OR with just a single child).");
            return false;
        }
    }
    // inner node and
    else if _json["AND"].is_array() {
        let _num_terms = _json["AND"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = true;
            for _i in 0usize.._num_terms {
                ret = ret && traverse_json(_attr, &_json["AND"][_i]);
            }
            return ret;
        } else {
            println!("Error: Invalid policy (AND with just a single child).");
            return false;
        }
    }
    // leaf node
    else if _json["ATT"] != serde_json::Value::Null {
        match _json["ATT"].as_str() {
            Some(s) => {
                // check if ATT in _attr list
                return (&_attr).into_iter().any(|x| x == s);
            }
            None => {
                println!("Error: in attribute String");
                return false;
            }
        }
    }
    // error
    else {
        println!("Error: Policy invalid. No AND or OR found");
        return false;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_traverse() {
        let policyfalse = String::from(r#"joking-around?"#);
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
