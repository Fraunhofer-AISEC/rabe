use gmorph::Enc;
use rabe_bn::*;
use rand::Rng;
use schemes::labe::LabePublicKey;
use utils::{
    tools::{contains, usize_to_fr, get_value},
    policy::pest::{PolicyValue, PolicyLanguage, parse, PolicyType}
};
use crate::error::RabeError;

pub fn calc_coefficients(_json: &PolicyValue, _fr: i32, _type: Option<PolicyType>) -> Option<Vec<(String, i32)>> {
    let mut _result: Vec<(String, i32)> = Vec::new();
    return match _json {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => calc_coefficients(&obj.1.as_ref(), _fr, Some(PolicyType::And)),
                PolicyType::Or => calc_coefficients(&obj.1.as_ref(), _fr, Some(PolicyType::Or)),
                _ => {
                    _result.push((get_value(&obj.1), _fr));
                    return Some(_result);
                }
            }
        }
        PolicyValue::Array(children) => {
            match _type.unwrap() {
                PolicyType::And => {
                    let vec : Vec<i32> = (1i32..(children.len() + 1) as i32).collect();
                    let _this_coeff = recover_coefficients(vec);
                    for (i, child) in children.iter().enumerate() {
                        match calc_coefficients(&child, (_fr as f64 * _this_coeff[i]) as i32, None) {
                            None => return None,
                            Some(_res) => {
                                _result.extend(_res.iter().cloned());
                            }
                        }
                    }
                    Some(_result)
                },
                PolicyType::Or => {
                    let _this_coeff = recover_coefficients(vec![1i32]);
                    for child in children.iter() {
                        match calc_coefficients(&child, (_fr as f64 * _this_coeff[0]) as i32, None) {
                            None => return None,
                            Some(_res) => {
                                _result.extend(_res.iter().cloned());
                            }
                        }
                    }
                    Some(_result)
                }
                _ => None
            }
        }
        PolicyValue::String(str) => {
            _result.push((str.to_string(), _fr));
            return Some(_result);
        }
    };
}

// lagrange interpolation
pub fn recover_coefficients(_list: Vec<i32>) -> Vec<f64> {
    let mut _coeff: Vec<f64> = Vec::new();
    for i in _list.clone().into_iter() {
        let mut r = 1f64;
        for j in _list.clone().into_iter()  {
            if i != j {
                let term = (f64::from(0)-f64::from(j))/(f64::from(i)-f64::from(j));
                r = r * term;
            }
        }
        _coeff.push(r);
    }
    return _coeff;
}

pub fn gen_shares_policy(_secret: [u32; 4], _json: &PolicyValue, _type: Option<PolicyType>) -> Option<Vec<(String, [u32; 4])>> {
    let mut _result: Vec<(String, [u32; 4])> = Vec::new();
    let mut _k = 0;
    let mut _n = 0;
    match _json {
        PolicyValue::String(str) => {
            _result.push((str.to_string(), _secret));
            Some(_result)
        },
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => gen_shares_policy(_secret, &obj.1.as_ref(), Some(PolicyType::And)),
                PolicyType::Or => gen_shares_policy(_secret, &obj.1.as_ref(), Some(PolicyType::Or)),
                _ => gen_shares_policy(_secret, &obj.1.as_ref(), Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::Array(children) => {
            _n = children.len();
            match _type {
                Some(PolicyType::And) => {
                    _k = _n;
                },
                Some(PolicyType::Or) => {
                    _k = 1;
                }
                None => panic!("this should not happen =( Array is always AND or OR."),
                _ => panic!("this should not happen =( Array is always AND or OR.")
            }
            let shares = gen_shares(_secret, _k, _n);
            for _i in 0.._n {
                match gen_shares_policy(shares[_i + 1], &children[_i], None) {
                    None => panic!("Error in gen_shares_policy: Returned None."),
                    Some(_items) => {
                        _result.extend(_items.iter().cloned());
                    }
                }
            }
            Some(_result)
        }
    }
}

pub fn gen_shares(_secret: [u32; 4], _k: usize, _n: usize) -> Vec<[u32; 4]> {
    let mut _shares: Vec<[u32; 4]> = Vec::new();
    if _k <= _n {
        // random number generator
        let mut _rng = rand::thread_rng();
        // polynomial_numeric coefficients
        let mut _a: Vec<[u32; 4]> = Vec::new();
        for _i in 0.._k {
            if _i == 0 {
                _a.push(_secret);
            } else {
                _a.push(_rng.gen())
            }
        }
        for _i in 0..(_n + 1) {
            let _polynom = polynomial_numeric(_a.clone(), _i);
            _shares.push(_polynom);
        }
    }
    return _shares;
}

pub fn calc_pruned(_attr: &Vec<String>, _json: &PolicyValue, _type: Option<PolicyType>) -> Result<(bool, Vec<String>), RabeError> {
    let mut _emtpy_list: Vec<String> = Vec::new();
    match _json {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => calc_pruned(_attr, &obj.1.as_ref(), Some(PolicyType::And)),
                PolicyType::Or => calc_pruned(_attr, &obj.1.as_ref(), Some(PolicyType::Or)),
                _ => calc_pruned(_attr, &obj.1.as_ref(), Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::Array(children) => {
            let len = children.len();
            match _type {
                Some(PolicyType::And) => {
                    let mut _match: bool = true;
                    if len >= 2 {
                        for _i in 0usize..len {
                            let (_found, mut _list) = calc_pruned(_attr, &children[_i], None).unwrap();
                            _match = _match && _found;
                            if _match {
                                _emtpy_list.append(&mut _list);
                            }
                        }
                    } else {
                        panic!("Error: Invalid policy (AND with just a single child).");
                    }
                    if !_match {
                        _emtpy_list = Vec::new();
                    }
                    return Ok((_match, _emtpy_list));
                },
                Some(PolicyType::Or) => {
                    let mut _match: bool = false;
                    if len >= 2 {
                        for _i in 0usize..len {
                            let (_found, mut _list) = calc_pruned(_attr, &children[_i], None).unwrap();
                            _match = _match || _found;
                            if _match {
                                _emtpy_list.append(&mut _list);
                                break;
                            }
                        }
                        return Ok((_match, _emtpy_list));
                    } else {
                        panic!("Error: Invalid policy (OR with just a single child).")
                    }
                },
                _ => Err(RabeError::new("Error in calc_pruned: unknown array type!")),

            }
        },
        PolicyValue::String(str) => {
            if contains(_attr, &str.to_string()) {
                Ok((true, vec![str.to_string()]))
            } else {
                Ok((false, _emtpy_list))
            }
        }
    }
}

#[allow(dead_code)]
pub fn recover_secret(_shares: Vec<[u32; 4]>, _policy: &String) -> [u32; 4] {
    let policy = parse(_policy, PolicyLanguage::JsonPolicy).unwrap();
    let _coeff = calc_coefficients(&policy, 1, None).unwrap();
    print!("_policy: {:?} _coeff {:?}", _policy, &_coeff);
    let mut _secret = [0u32, 0u32, 0u32, 0u32];
    for (i, val) in _shares.into_iter().enumerate() {
        for j in 0..4 {
            let term = _coeff[i].1.wrapping_mul(val[j] as i32);
            _secret[j] = _secret[j].wrapping_add(term as u32);
        }
    }
    return _secret;
}

pub fn polynomial_numeric(_coeff: Vec<[u32; 4]>, _x: usize) -> [u32; 4] {
    let mut _share: [u32; 4] = [0, 0, 0, 0];
    for (i, c) in _coeff.into_iter().enumerate() {
        for j in 0..4 {
            _share[j] = _share[j].wrapping_add(c[j].wrapping_mul(_x.wrapping_pow(i as u32) as u32));
        }
    }
    return _share;
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use super::*;

    #[test]
    fn test_secret_sharing_or() {
        // OR
        let mut _rng = rand::thread_rng();
        let _secret:[u32; 4] = _rng.gen();
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 1, 3);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(K).unwrap());
        let mut _input: Vec<[u32; 4]> = Vec::new();
        _input.push(_shares[1]);
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"name":"or", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}]}"#),
        );
        assert!(_k == _reconstruct);
    }

    #[test]
    fn test_secret_sharing_and() {
        // AND
        let mut _rng = rand::thread_rng();
        let _secret= _rng.gen();
        println!("_random: {:?}", _secret);
        let mut _shares = gen_shares(_secret, 6, 6);
        let _k = _shares.remove(0);
        println!("_original_vec: {:?}", &_shares);
        let _reconstruct = recover_secret(
            _shares,
            &String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}, {"name": "D"}, {"name": "D"}]}"#),
        );
        println!("_reconstruct: {:?}", &_reconstruct);
        println!("_k: {:?}", _k);
        assert_eq!(_k, _reconstruct);
    }

    #[test]
    fn test_pruning() {
        // a set of two attributes
        let mut _attributes: Vec<String> = Vec::new();
        _attributes.push(String::from("3"));
        _attributes.push(String::from("4"));

        let pol1 = String::from(r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "1"}, {"name": "2"}]}, {"name": "and", "children": [{"name": "3"}, {"name": "4"}]}]}"#);
        let pol2 = String::from(r#"{"name": "or", "children": [{"name": "3"}, {"name": "and", "children": [{"name": "4"}, {"name": "5"}]}]}"#);
        let pol3 = String::from(r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "1"}, {"name": "4"}]}, {"name": "and", "children": [{"name": "3"}, {"name": "1"}]}]}"#);

        let _result1 = calc_pruned(
            &_attributes,
            &parse(pol1.as_ref(), PolicyLanguage::JsonPolicy).unwrap(),
            None
        );
        let _result2 = calc_pruned(
            &_attributes,
            &parse(pol2.as_ref(), PolicyLanguage::JsonPolicy).unwrap(),
            None
        );
        let _result3 = calc_pruned(
            &_attributes,
            &parse(pol3.as_ref(), PolicyLanguage::JsonPolicy).unwrap(),
            None
        );

        let (_match1, _list1) = _result1.unwrap();
        assert_eq!(_match1, true);
        assert!(_list1 == vec!["3".to_string(), "4".to_string()]);

        let (_match2, _list2) = _result2.unwrap();
        assert_eq!(_match2, true);
        assert!(_list2 == vec!["3".to_string()]);

        let (_match3, _list3) = _result3.unwrap();
        assert_eq!(_match3, false);
        assert_eq!(_list3.is_empty(), true);
    }
}
