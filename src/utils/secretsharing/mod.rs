use rabe_bn::*;
use rand::Rng;
use utils::{
    tools::{contains, usize_to_fr, get_value},
    policy::pest::{PolicyValue, PolicyLanguage, parse, PolicyType}
};
use crate::error::RabeError;

pub fn calc_coefficients(policy_value: &PolicyValue, coeff: Option<Fr>, mut coeff_list: Vec<(String, Fr)>, policy_type: Option<PolicyType>) -> Option<Vec<(String, Fr)>> {
    return match policy_value {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => calc_coefficients(&obj.1.as_ref(), coeff, coeff_list, Some(PolicyType::And) ),
                PolicyType::Or => calc_coefficients(&obj.1.as_ref(), coeff, coeff_list, Some(PolicyType::Or) ),
                _ => {
                    // Single attribute policy use case
                    coeff_list.push((get_value(&obj.1), coeff.unwrap()));
                    return Some(coeff_list);
                }
            }
        }
        PolicyValue::Array(children) => {
            match policy_type.unwrap() {
                PolicyType::And => {
                    let mut this_coeff_vec = vec![Fr::one()];
                    for _i in 1..children.len() {
                        let prev = this_coeff_vec[_i - 1].clone();
                        this_coeff_vec.push(prev + Fr::one());
                    }
                    let this_coeff = recover_coefficients(this_coeff_vec);
                    for (i, child) in children.iter().enumerate() {
                        match calc_coefficients(&child, Some(coeff.unwrap() * this_coeff[i]), coeff_list.clone(), None ) {
                            None => return None,
                            Some(res) => coeff_list = res
                        }
                    }
                    Some(coeff_list)
                },
                PolicyType::Or => {
                    let this_coeff = recover_coefficients(vec![Fr::one()]);
                    for child in children.iter() {
                        match calc_coefficients(&child, Some(coeff.unwrap() * this_coeff[0]), coeff_list.clone(), None ) {
                            None => return None,
                            Some(res) => coeff_list = res
                        }
                    }
                    Some(coeff_list)
                }
                _ => None
            }
        }
        PolicyValue::String(node) => {
            coeff_list.push((node_index(node), coeff.unwrap()));
            Some(coeff_list)
        }
    };
}

// lagrange interpolation
pub fn recover_coefficients(list: Vec<Fr>) -> Vec<Fr> {
    let mut coeff: Vec<Fr> = Vec::new();
    for _i in list.clone() {
        let mut result = Fr::one();
        for _j in list.clone() {
            if _i != _j {
                result = result * ((Fr::zero() - _j) * (_i - _j).inverse().unwrap());
            }
        }
        coeff.push(result);
    }
    return coeff;
}

pub fn node_index(node: &(&str, usize)) -> String {
    [node.0.to_string(), String::from("_"), node.1.to_string()].concat()
}
pub fn remove_index(node: &String) -> String {
    let parts: Vec<_> = node.split('_').collect();
    parts[0].to_string()
}

pub fn gen_shares_policy(secret: Fr, policy_value: &PolicyValue, policy_type: Option<PolicyType>) -> Option<Vec<(String, Fr)>> {
    let mut result: Vec<(String, Fr)> = Vec::new();
    let k;
    let n;
    match policy_value {
        PolicyValue::String(node) => {
            result.push((node_index(node), secret));
            Some(result)
        },
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => gen_shares_policy(secret, &obj.1.as_ref(), Some(PolicyType::And)),
                PolicyType::Or => gen_shares_policy(secret, &obj.1.as_ref(), Some(PolicyType::Or)),
                _ => gen_shares_policy(secret, &obj.1.as_ref(), Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::Array(children) => {
            n = children.len();
            match policy_type {
                Some(PolicyType::And) => {
                    k = n;
                },
                Some(PolicyType::Or) => {
                    k = 1;
                }
                None => panic!("this should not happen =( Array is always AND or OR."),
                _ => panic!("this should not happen =( Array is always AND or OR.")
            }
            let shares = gen_shares(secret, k, n);
            for _i in 0..n {
                match gen_shares_policy(shares[_i + 1], &children[_i], None) {
                    None => panic!("Error in gen_shares_policy: Returned None."),
                    Some(_items) => {
                        result.extend(_items.iter().cloned());
                    }
                }
            }
            Some(result)
        }
    }
}

pub fn gen_shares(secret: Fr, k: usize, n: usize) -> Vec<Fr> {
    let mut shares: Vec<Fr> = Vec::new();
    if k <= n {
        // random number generator
        let mut rng = rand::thread_rng();
        // polynomial coefficients
        let mut a: Vec<Fr> = Vec::new();
        a.push(secret);
        for _i in 1..k {
            a.push(rng.gen())
        }
        for i in 0..(n + 1) {
            let polynom = polynomial(a.clone(), usize_to_fr(i));
            shares.push(polynom);
        }
    }
    return shares;
}

pub fn calc_pruned(attr: &Vec<String>, policy_value: &PolicyValue, policy_type: Option<PolicyType>) -> Result<(bool, Vec<(String, String)>), RabeError> {
    let mut empty: Vec<(String, String)> = Vec::new();
    match policy_value {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => calc_pruned(attr, &obj.1.as_ref(), Some(PolicyType::And)),
                PolicyType::Or => calc_pruned(attr, &obj.1.as_ref(), Some(PolicyType::Or)),
                _ => calc_pruned(attr, &obj.1.as_ref(), Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::Array(children) => {
            let len = children.len();
            match policy_type {
                Some(PolicyType::And) => {
                    let mut policy_match: bool = true;
                    if len >= 2 {
                        for _i in 0usize..len {
                            let (_found, mut _list) = calc_pruned(attr, &children[_i], None).unwrap();
                            policy_match = policy_match && _found;
                            if policy_match {
                                empty.append(&mut _list);
                            }
                        }
                    } else {
                        panic!("Error: Invalid policy (AND with just a single child).");
                    }
                    if !policy_match.clone() {
                        empty = Vec::new();
                    }
                    return Ok((policy_match, empty));
                },
                Some(PolicyType::Or) => {
                    let mut _match: bool = false;
                    if len >= 2 {
                        for _i in 0usize..len {
                            let (_found, mut _list) = calc_pruned(attr, &children[_i], None).unwrap();
                            _match = _match || _found;
                            if _match {
                                empty.append(&mut _list);
                                break;
                            }
                        }
                        return Ok((_match, empty));
                    } else {
                        panic!("Error: Invalid policy (OR with just a single child).")
                    }
                },
                _ => Err(RabeError::new("Error in calc_pruned: unknown array type!")),
            }
        },
        PolicyValue::String(node) => {
            if contains(attr, &node.0.to_string()) {
                Ok((true, vec![(node.0.to_string(), node_index(node))]))
            } else {
                Ok((false, empty))
            }
        }
    }
}

#[allow(dead_code)]
pub fn recover_secret(_shares: Vec<Fr>, _policy: &String) -> Fr {
    let policy = parse(_policy, PolicyLanguage::JsonPolicy).unwrap();
    let mut coeff_list: Vec<(String, Fr)> = Vec::new();
    coeff_list = calc_coefficients(&policy, Some(Fr::one()), coeff_list, None).unwrap();
    let mut _secret = Fr::zero();
    for _i in 0usize.._shares.len() {
        _secret = _secret + (coeff_list[_i].1 * _shares[_i]);
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
        let mut rng = rand::thread_rng();
        let secret:Fr = rng.gen();
        //println!("_random: {:?}", into_dec(_secret).unwrap());
        let _shares = gen_shares(secret, 1, 2);
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
                let coeff_list: Vec<(String, Fr)> = Vec::new();
                let _coeff = calc_coefficients(&pol, Some(Fr::one()), coeff_list, None).unwrap();
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
        _attributes.push(String::from("A"));
        _attributes.push(String::from("B"));
        _attributes.push(String::from("C"));

        let pol1 = String::from(r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}, {"name": "and", "children": [{"name": "C"}, {"name": "D"}]}]}"#);
        let pol2 = String::from(r#"{"name": "or", "children": [{"name": "C"}, {"name": "and", "children": [{"name": "A"}, {"name": "E"}]}]}"#);
        let pol3 = String::from(r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "C"}]}, {"name": "and", "children": [{"name": "C"}, {"name": "A"}]}]}"#);

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
        assert!(_list1 == vec![("A".to_string(), "A_68".to_string()), ("B".to_string(), "B_83".to_string())]);

        let (_match2, _list2) = _result2.unwrap();
        assert_eq!(_match2, true);
        assert!(_list2 == vec![("C".to_string(), "C_39".to_string())]);

        let (_match3, _list3) = _result3.unwrap();
        assert_eq!(_match3, true);
        assert!(_list3 == vec![("A".to_string(), "A_68".to_string()), ("C".to_string(), "C_83".to_string())]);
    }
}
