extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rustc_serialize;

use mke08::Mke08PublicAttributeKey;
use std::string::String;
use bn::*;


pub struct AbePolicy {
    pub _m: Vec<Vec<i32>>,
    pub _pi: Vec<String>,
    pub _deg: usize,
}

pub struct DnfPolicy {
    pub _terms: Vec<(bn::Gt, bn::G1, bn::G2)>,
}

const ZERO: i32 = 0;
const PLUS: i32 = 1;
const MINUS: i32 = -1;

impl AbePolicy {
    pub fn from_string(_policy: &String) -> Option<AbePolicy> {
        match string_to_json(_policy) {
            None => {
                println!("Error parsing policy");
                return None;
            }
            Some(json) => {
                return json_to_msp(&json);
            }
        }
    }
    pub fn from_json(_json: &serde_json::Value) -> Option<AbePolicy> {
        json_to_msp(_json)
    }
}

impl DnfPolicy {
    pub fn from_string(_policy: &String, _pks: &Vec<Mke08PublicAttributeKey>) -> Option<DnfPolicy> {
        match string_to_json(_policy) {
            None => {
                println!("Error parsing policy");
                return None;
            }
            Some(json) => {
                return json_to_dnf(&json, _pks);
            }
        }
    }
    pub fn from_json(
        _json: &serde_json::Value,
        _pks: &Vec<Mke08PublicAttributeKey>,
    ) -> Option<DnfPolicy> {
        json_to_dnf(_json, _pks)
    }
    pub fn is_in_dnf(_policy: &String) -> bool {
        match string_to_json(_policy) {
            None => {
                return false;
            }
            Some(json) => {
                return policy_in_dnf(&json, false);
            }
        }
    }
}

fn lw(msp: &mut AbePolicy, p: &serde_json::Value, v: Vec<i32>) -> bool {
    let mut v_tmp_left = Vec::new();
    let mut v_tmp_right = v.clone();

    if *p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }
    // inner node
    if p["OR"].is_array() {
        if p["OR"].as_array().unwrap().len() < 2 {
            println!("Invalid policy. Number of arguments under OR < 2");
            return false;
        }
        let mut ret = true;
        for i in 0usize..p["OR"].as_array().unwrap().len() {
            ret = ret && lw(msp, &p["OR"][i], v.clone())
        }
        return ret;

    } else if p["AND"].is_array() {
        if p["AND"].as_array().unwrap().len() != 2 {
            println!("Invalid policy. Number of arguments under AND != 2");
            return false;
        }
        let left = &p["AND"][0];
        if left["OR"] != serde_json::Value::Null {
            println!("Invalid policy. Not in DNF");
            return false;
        }

        v_tmp_right.resize(msp._deg, ZERO);
        v_tmp_right.push(PLUS);
        v_tmp_left.resize(msp._deg, ZERO);
        v_tmp_left.push(MINUS);
        msp._deg += 1;
        return lw(msp, &p["AND"][0], v_tmp_right) && lw(msp, &p["AND"][1], v_tmp_left);

    }
    //Leaf
    else if p["ATT"] != serde_json::Value::Null {
        msp._m.insert(0, v_tmp_right);
        match p["ATT"].as_str() {
            Some(s) => msp._pi.insert(0, String::from(s)),
            None => println!("ERROR attribute value"),
        }
        return true;
    } else {
        println!("Policy invalid. No AND or OR found");
        return false;
    }
}

fn policy_in_dnf(p: &serde_json::Value, conjunction: bool) -> bool {
    if *p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }
    let mut ret = true;
    // inner node
    if p["OR"].is_array() {
        if conjunction {
            return false;
        } else {
            for i in 0usize..p["OR"].as_array().unwrap().len() {
                ret = ret && policy_in_dnf(&p["OR"][i], conjunction)
            }
        }
        return ret;

    } else if p["AND"].is_array() {
        for i in 0usize..p["AND"].as_array().unwrap().len() {
            ret = ret && policy_in_dnf(&p["AND"][i], conjunction)
        }
        return ret;
    }
    //Leaf
    else if p["ATT"] != serde_json::Value::Null {
        return true;
    } else {
        println!("Policy invalid. No AND or OR found");
        return false;
    }
}


fn dnf(
    dnfp: &mut DnfPolicy,
    _pks: &Vec<Mke08PublicAttributeKey>,
    p: &serde_json::Value,
    _index: usize,
) -> bool {
    if *p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }
    let mut ret = true;
    // inner node
    if p["OR"].is_array() {
        for i in 0usize..p["OR"].as_array().unwrap().len() {
            ret &= dnf(dnfp, _pks, &p["OR"][i], _index + i)
        }
        return ret;

    } else if p["AND"].is_array() {
        for i in 0usize..p["AND"].as_array().unwrap().len() {
            ret &= dnf(dnfp, _pks, &p["AND"][i], _index)
        }
        return ret;
    }
    //Leaf
    else if p["ATT"] != serde_json::Value::Null {
        match p["ATT"].as_str() {
            Some(s) => {
                let mut _current = dnfp._terms[_index];
                for pk in _pks.iter() {
                    if pk._str == s {
                        _current.0 = _current.0 * pk._gt;
                        _current.1 = _current.1 + pk._g1;
                        _current.2 = _current.2 + pk._g2;
                    }
                }
                dnfp._terms.insert(_index, _current);
            }
            None => {
                println!("ERROR attribute value");
                return false;
            }
        }
        return true;
    } else {
        println!("Policy invalid. No AND or OR found");
        return false;
    }
}


//#[doc = /**
// * BEWARE: policy must be in DNF!
// */]
pub fn json_to_msp(json: &serde_json::Value) -> Option<AbePolicy> {
    let mut v: Vec<i32> = Vec::new();
    let mut _values: Vec<Vec<i32>> = Vec::new();
    let mut _attributes: Vec<String> = Vec::new();
    let mut msp = AbePolicy {
        _m: _values,
        _pi: _attributes,
        _deg: 1,
    };

    v.push(PLUS);
    if lw(&mut msp, json, v) {
        for p in &mut msp._m {
            p.resize(msp._deg, ZERO);
        }
        msp._pi.reverse();
        return Some(msp);
    }
    return None;
}

pub fn string_to_json(policy: &String) -> Option<serde_json::Value> {
    match serde_json::from_str(policy) {
        Err(_) => {
            println!("Error parsing policy");
            return None;
        }
        Ok(pol) => {
            return Some(pol);
        }
    }
}

pub fn json_to_dnf(
    _json: &serde_json::Value,
    _pks: &Vec<Mke08PublicAttributeKey>,
) -> Option<DnfPolicy> {
    let mut _conjunctions: Vec<(bn::Gt, bn::G1, bn::G2)> = Vec::new();
    _conjunctions.push((Gt::one(), G1::zero(), G2::zero()));
    let mut dnfp = DnfPolicy { _terms: _conjunctions };
    if dnf(&mut dnfp, _pks, _json, 0) {
        return Some(dnfp);
    }
    return None;
}
