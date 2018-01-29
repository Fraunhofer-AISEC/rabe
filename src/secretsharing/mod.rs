extern crate serde;
extern crate serde_json;
extern crate rand;

use bn::*;
use tools::{usize_to_fr, contains, flatten};

pub fn calc_pruned_str(_attr: &Vec<(String)>, _policy: &String) -> Option<(bool, Vec<(String)>)> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error in policy (could not parse json): {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            return required_attributes(_attr, &pol);
        }
    }
}


pub fn required_attributes(
    _attr: &Vec<(String)>,
    _json: &serde_json::Value,
) -> Option<(bool, Vec<(String)>)> {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return None;
    } else {
        let mut _match: bool = false;
        let mut _emtpy_list: Vec<(String)> = Vec::new();
        if _json["OR"].is_array() {
            let _num_terms = _json["OR"].as_array().unwrap().len();
            if _num_terms >= 2 {
                for _i in 0usize.._num_terms {
                    let (_found, mut _list) = required_attributes(_attr, &_json["OR"][_i]).unwrap();
                    _match = _match || _found;
                    if _match {
                        _emtpy_list.append(&mut _list);
                        break;
                    }
                }
                return Some((_match, _emtpy_list));
            } else {
                println!("Error: Invalid policy (OR with just a single child).");
                return None;
            }
        }
        // inner node
        else if _json["AND"].is_array() {
            let _num_terms = _json["AND"].as_array().unwrap().len();
            _match = true;
            if _num_terms >= 2 {
                for _i in 0usize.._num_terms {
                    let (_found, mut _list) = required_attributes(_attr, &_json["AND"][_i])
                        .unwrap();
                    _match = _match && _found;
                    if _match {
                        _emtpy_list.append(&mut _list);
                    }
                }

            } else {
                println!("Error: Invalid policy (OR with just a single child).");
                return None;
            }
            if !_match {
                _emtpy_list = Vec::new();
            }
            return Some((_match, _emtpy_list));

        }
        // leaf node
        else if _json["ATT"] != serde_json::Value::Null {
            match _json["ATT"].as_str() {
                Some(_s) => {
                    if contains(_attr, &_s.to_string()) {
                        return Some((true, vec![_s.to_string()]));
                    } else {
                        return Some((false, _emtpy_list));
                    }
                }
                None => {
                    println!("ERROR attribute value");
                    return None;
                }
            }
        } else {
            return None;
        }
    }
}

pub fn calc_coefficients_str(_policy: &String) -> Option<Vec<(String, Fr)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error in policy (could not parse json): {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            let mut _coeff: Vec<(String, Fr)> = Vec::new();
            calc_coefficients(&pol, &mut _coeff, Fr::one());
            return Some(_coeff);
        }
    }
}

pub fn calc_coefficients(
    _json: &serde_json::Value,
    _coeff_vec: &mut Vec<(String, Fr)>,
    _coeff: Fr,
) {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
    } else {
        // leaf node
        if _json["ATT"] != serde_json::Value::Null {
            match _json["ATT"].as_str() {
                Some(_s) => {
                    _coeff_vec.push((_s.to_string(), _coeff));
                }
                None => {
                    println!("ERROR attribute value");
                }
            }
        }
        // inner node
        else if _json["AND"].is_array() {
            let _this_coeff = recover_coefficients(vec![Fr::one(), (Fr::one() + Fr::one())]);
            calc_coefficients(&_json["AND"][0], _coeff_vec, _coeff * _this_coeff[0]);
            calc_coefficients(&_json["AND"][1], _coeff_vec, _coeff * _this_coeff[1]);
        }
        // inner node
        else if _json["OR"].is_array() {
            let _this_coeff = recover_coefficients(vec![Fr::one()]);
            calc_coefficients(&_json["OR"][0], _coeff_vec, _coeff * _this_coeff[0]);
            calc_coefficients(&_json["OR"][0], _coeff_vec, _coeff * _this_coeff[0]);
        }
    }
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

pub fn gen_shares_str(_secret: Fr, _policy: &String) -> Option<Vec<(String, Fr)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            return gen_shares_json(_secret, &pol);
        }
    }
}

pub fn gen_shares_json(_secret: Fr, _json: &serde_json::Value) -> Option<Vec<(String, Fr)>> {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return None;
    } else {
        let mut _k = 0;
        let mut _type = "";
        let mut _result: Vec<(String, Fr)> = Vec::new();
        // leaf node
        if _json["ATT"] != serde_json::Value::Null {
            match _json["ATT"].as_str() {
                Some(_s) => {
                    _result.push((_s.to_string(), _secret));
                    return Some(_result);
                }
                None => {
                    println!("ERROR attribute value");
                    return None;
                }
            }
        }
        // inner node
        else if _json["OR"].is_array() {
            _k = 1;
            _type = "OR";
        }
        // inner node
        else if _json["AND"].is_array() {
            _k = 2;
            _type = "AND";
        }
        let shares = gen_shares(_secret, _k, 2);
        let left = gen_shares_json(shares[0], &_json[_type][0]).unwrap();
        _result.extend(left);
        let right = gen_shares_json(shares[1], &_json[_type][1]).unwrap();
        _result.extend(right);
        return Some(_result);
    }
}

pub fn gen_shares(_secret: Fr, _k: usize, _n: usize) -> Vec<Fr> {
    let mut _shares: Vec<Fr> = Vec::new();
    if _k <= _n {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // polynomial coefficients
        let mut _a: Vec<Fr> = Vec::new();
        for _i in 0.._k {
            if _i == 0 {
                _a.push(_secret);
            } else {
                _a.push(Fr::random(_rng))
            }
        }
        for _i in 0..(_n + 1) {
            let _polynom = polynomial(_a.clone(), usize_to_fr(_i));
            _shares.push(_polynom);
        }
    }
    return _shares;
}

pub fn recover_secret(_shares: Vec<Fr>, _policy: &String) -> Fr {
    let _coeff = calc_coefficients_str(_policy).unwrap();
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
