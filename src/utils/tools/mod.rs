use crate::utils::policy::pest::{PolicyType, PolicyValue};
use crate::utils::secretsharing::node_index;
use rabe_bn::*;
use std::collections::HashSet;

pub fn is_negative(attr: &str) -> bool {
    let first_char = &attr[..1];
    first_char == '!'.to_string()
}

pub fn usize_to_fr(i: usize) -> Fr {
    Fr::from_str(&i.to_string()).unwrap()
}

pub fn contains(data: &[String], value: &String) -> bool {
    let len = data
        .iter()
        .filter(|&i| i == value)
        .collect::<Vec<_>>()
        .len();
    len >= 1
}

// used to check if a set of attributes is a subset of another
pub fn is_subset(subset: &[&str], attr: &[&str]) -> bool {
    let super_set: HashSet<_> = attr.iter().cloned().collect();
    let sub_set: HashSet<_> = subset.iter().cloned().collect();
    sub_set.is_subset(&super_set)
}

// used to traverse / check policy tree
pub fn traverse_policy(
    attr: &Vec<String>,
    policy_value: &PolicyValue,
    policy_type: PolicyType,
) -> bool {
    (!attr.is_empty())
        && match policy_value {
            PolicyValue::String(node) => (attr).iter().any(|x| x == node.0),
            PolicyValue::Object(obj) => {
                return match obj.0 {
                    PolicyType::And => traverse_policy(attr, obj.1.as_ref(), PolicyType::And),
                    PolicyType::Or => traverse_policy(attr, obj.1.as_ref(), PolicyType::Or),
                    _ => true,
                };
            }
            PolicyValue::Array(arrayref) => {
                return match policy_type {
                    PolicyType::And => {
                        let mut ret = true;
                        for obj in arrayref.iter() {
                            ret &= traverse_policy(attr, obj, PolicyType::Leaf)
                        }
                        ret
                    }
                    PolicyType::Or => {
                        let mut ret = false;
                        for obj in arrayref.iter() {
                            ret |= traverse_policy(attr, obj, PolicyType::Leaf)
                        }
                        ret
                    }
                    PolicyType::Leaf => false,
                };
            }
        }
}

pub fn get_value(_json: &PolicyValue) -> String {
    match _json {
        PolicyValue::String(node) => node_index(node),
        _ => "".to_string(),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::policy::pest::{PolicyLanguage, parse};

    #[test]
    fn test_traverse() {
        let policy_false = String::from(r#"what-the-heck?"#);
        let policy1 =
            String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}"#);
        let policy2 = String::from(r#"{"name": "or", "children": [{"name": "A"}, {"name": "B"}]}"#);
        let policy3 = String::from(
            r#"{"name": "and", "children": [{"name":"or", "children": [{"name": "C"}, {"name": "D"}]}, {"name": "B"}]}"#,
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

        assert_eq!(
            parse(policy_false.as_ref(), PolicyLanguage::JsonPolicy).is_ok(),
            false
        );

        match parse(policy1.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                assert_eq!(traverse_policy(&_set0, &pol, PolicyType::Leaf), false);
                assert_eq!(traverse_policy(&_set1, &pol, PolicyType::Leaf), true);
                assert_eq!(traverse_policy(&_set2, &pol, PolicyType::Leaf), false);
                assert_eq!(traverse_policy(&_set3, &pol, PolicyType::Leaf), true);
            }
            Err(e) => println!("test_traverse: could not parse policy1 {}", e),
        }

        match parse(policy2.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                assert_eq!(traverse_policy(&_set1, &pol, PolicyType::Leaf), true);
                assert_eq!(traverse_policy(&_set2, &pol, PolicyType::Leaf), false);
                assert_eq!(traverse_policy(&_set3, &pol, PolicyType::Leaf), true);
            }
            Err(e) => println!("test_traverse: could not parse policy2 {}", e),
        }

        match parse(policy3.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                assert_eq!(traverse_policy(&_set1, &pol, PolicyType::Leaf), false);
                assert_eq!(traverse_policy(&_set2, &pol, PolicyType::Leaf), false);
                assert_eq!(traverse_policy(&_set3, &pol, PolicyType::Leaf), true);
            }
            Err(e) => println!("test_traverse: could not parse policy3 {}", e),
        }
    }

    mod findings {
        use super::*;

        #[test]
        #[should_panic(expected = "end byte index 1 is out of bounds for string of length 0")]
        fn negative_attributes_read_leading_exclamation_point_and_panics() {
            assert!(is_negative(&String::from("!A")));
            assert!(is_negative(&String::from("!")));
            assert!(!is_negative(&String::from("A!")));
            assert!(!is_negative(&String::from("A")));
            assert!(is_negative(&String::new()));
            assert!(is_negative(&String::from("\u{e9}A")));
        }
    }
}
