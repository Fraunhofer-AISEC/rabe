use rabe_bn::*;
use rand::Rng;
use utils::{
    tools::{contains, usize_to_fr, get_value},
    policy::pest::{PolicyValue, PolicyLanguage, parse, PolicyType}
};
use crate::error::RabeError;

pub fn calc_coefficients(_json: &PolicyValue, _fr: Option<Fr>, _type: Option<PolicyType>) -> Option<Vec<(String, Fr)>> {
    let _coeff = _fr.unwrap_or(Fr::one());
    let mut _result: Vec<(String, Fr)> = Vec::new();
    return match _json {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => calc_coefficients(&obj.1.as_ref(), _fr, Some(PolicyType::And)),
                PolicyType::Or => calc_coefficients(&obj.1.as_ref(), _fr, Some(PolicyType::Or)),
                _ => {
                    _result.push((get_value(&obj.1), _coeff));
                    return Some(_result);
                }
            }
        }
        PolicyValue::Array(children) => {
            match _type.unwrap() {
                PolicyType::And => {
                    let mut _vec = vec![Fr::one()];
                    for _i in 1..children.len() {
                        let _prev = _vec[_i - 1].clone();
                        _vec.push(_prev + Fr::one());
                    }
                    let _this_coeff = recover_coefficients(_vec);
                    for (i, child) in children.iter().enumerate() {
                        match calc_coefficients(&child, Some(_coeff * _this_coeff[i]), None) {
                            None => return None,
                            Some(_res) => {
                                _result.extend(_res.iter().cloned());
                            }
                        }
                    }
                    Some(_result)
                },
                PolicyType::Or => {
                    let _this_coeff = recover_coefficients(vec![Fr::one()]);
                    for child in children.iter() {
                        match calc_coefficients(&child, Some(_coeff * _this_coeff[0]), None) {
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
            _result.push((str.to_string(), _coeff));
            return Some(_result);
        }
    };
}

// lagrange interpolation
pub fn recover_coefficients(_list: Vec<Fr>) -> Vec<Fr> {
    let mut _coeff: Vec<Fr> = Vec::new();
    for _i in _list.clone() {
        let mut _result = Fr::one();
        for _j in _list.clone() {
            if _i != _j {
                _result = _result * ((Fr::zero() - _j) * (_i - _j).inverse().unwrap());
            }
        }
        _coeff.push(_result);
    }
    return _coeff;
}

pub fn gen_shares_policy(_secret: Fr, _json: &PolicyValue, _type: Option<PolicyType>) -> Option<Vec<(String, Fr)>> {
    let mut _result: Vec<(String, Fr)> = Vec::new();
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

pub fn gen_shares(_secret: Fr, _k: usize, _n: usize) -> Vec<Fr> {
    let mut _shares: Vec<Fr> = Vec::new();
    if _k <= _n {
        // random number generator
        let mut _rng = rand::thread_rng();
        // polynomial coefficients
        let mut _a: Vec<Fr> = Vec::new();
        for _i in 0.._k {
            if _i == 0 {
                _a.push(_secret);
            } else {
                _a.push(_rng.gen())
            }
        }
        for _i in 0..(_n + 1) {
            let _polynom = polynomial(_a.clone(), usize_to_fr(_i));
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
pub fn recover_secret(_shares: Vec<Fr>, _policy: &String) -> Fr {
    let policy = parse(_policy, PolicyLanguage::JsonPolicy).unwrap();
    let _coeff = calc_coefficients(&policy, None, None).unwrap();
    let mut _secret = Fr::zero();
    for _i in 0usize.._shares.len() {
        _secret = _secret + (_coeff[_i].1 * _shares[_i]);
    }
    return _secret;
}

pub fn polynomial(_coeff: Vec<Fr>, _x: Fr) -> Fr {
    let mut _share = Fr::zero();
    for _i in 0usize.._coeff.len() {
        _share = _share + (_coeff[_i] * _x.pow(usize_to_fr(_i)));
    }
    return _share;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_secret_sharing_or() {
        // OR
        let mut _rng = rand::thread_rng();
        let _secret:Fr = _rng.gen();
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 1, 2);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(K).unwrap());
        let mut _input: Vec<Fr> = Vec::new();
        _input.push(_shares[1]);
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"name":"or", "children": [{"name": "A"}, {"name": "B"}]}"#),
        );
        assert!(_k == _reconstruct);
    }

    #[test]
    fn test_gen_shares_json() {
        // OR
        let _rng = &mut rand::thread_rng();
        let _secret:Fr = _rng.gen();
        let _policy = String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}]}"#);
        match parse(&_policy, PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                let _shares = gen_shares_policy(_secret, &pol, None).unwrap();
                let _coeff = calc_coefficients(&pol, Some(Fr::one()), None).unwrap();
                assert_eq!(_coeff.len(), _shares.len());
            },
            Err(e) => println!("test_gen_shares_json: could not parse policy {}", e)
        }
    }

    #[test]
    fn test_secret_sharing_and() {
        // AND
        let mut _rng = rand::thread_rng();
        let _secret:Fr = _rng.gen();
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(_secret, 2, 2);
        let _k = _shares[0];
        //println!("_original_secret: {:?}", into_dec(_k).unwrap());
        let mut _input: Vec<Fr> = Vec::new();
        _input.push(_shares[1]);
        _input.push(_shares[2]);
        //println!("_share1: {:?}", into_dec(_shares[1]).unwrap());
        //println!("_share2: {:?}", into_dec(_shares[2]).unwrap());
        let _reconstruct = recover_secret(
            _input,
            &String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}"#),
        );
        //println!("_reconstructed: {:?}", into_dec(_reconstruct).unwrap());
        assert!(_k == _reconstruct);
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
