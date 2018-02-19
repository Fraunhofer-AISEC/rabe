extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rustc_serialize;

use std::string::String;

pub struct AbePolicy {
    pub _m: Vec<Vec<i32>>,
    pub _pi: Vec<String>,
    pub _deg: usize,
}

const ZERO: i32 = 0;
const PLUS: i32 = 1;
const MINUS: i32 = -1;

impl AbePolicy {
    pub fn from_string(_policy: &String) -> Option<AbePolicy> {
        string_to_msp(_policy)
    }
    pub fn from_json(_json: &serde_json::Value) -> Option<AbePolicy> {
        json_to_msp(_json)
    }
    pub fn is_DNF(_policy: &String) -> Option<bool> {
        is_in_dnf(_policy)
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

fn dnf(p: &serde_json::Value, nested: bool) -> Option<bool> {
    if *p == serde_json::Value::Null {
        println!("Error passed null!");
        return None;
    }
    // TODO
    return Some(true);
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

pub fn json_in_dnf(json: &serde_json::Value) -> Option<bool> {
    dnf(json, false)
}

pub fn string_to_msp(policy: &String) -> Option<AbePolicy> {
    match serde_json::from_str(policy) {
        Err(_) => {
            println!("Error parsing policy");
            return None;
        }
        Ok(pol) => {
            return json_to_msp(&pol);
        }
    }
}

pub fn is_in_dnf(policy: &String) -> Option<bool> {
    match serde_json::from_str(policy) {
        Err(_) => {
            println!("Error parsing policy");
            return None;
        }
        Ok(pol) => {
            return json_in_dnf(&pol);
        }
    }
}
