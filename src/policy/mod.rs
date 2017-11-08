extern crate serde;
extern crate serde_json;

extern crate bn;

use std::string::String;
use std::ops::Sub;
use std::ops::Add;
use bn::*;

pub struct AbePolicy {
    pub _m: Vec<Vec<i32>>,
    pub _pi: Vec<String>,
    pub _deg: usize,
}

fn lw(msp: &mut AbePolicy, p: &serde_json::Value, v: Vec<i32>) -> bool {
    let mut v_tmp_left = Vec::new();
    let mut v_tmp_right = v.clone();
    let _minus: i32 = -1;
    let _plus: i32 = 1;
    let _neutral: i32 = 0;

    if *p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }
    // inner node
    if p["OR"].is_array() {
        if p["OR"].as_array().unwrap().len() != 2 {
            println!("Invalid policy. Number of arguments under OR != 2");
            return false;
        }
        v_tmp_left = v.clone();

        return lw(msp, &p["OR"][0], v_tmp_right) && lw(msp, &p["OR"][1], v_tmp_left);
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

        v_tmp_right.resize(msp._deg, _neutral);
        v_tmp_right.push(_plus);
        v_tmp_left.resize(msp._deg, _neutral);
        v_tmp_left.push(_minus);
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

    v.push(1);
    if lw(&mut msp, json, v) {
        for p in &mut msp._m {
            p.resize(msp._deg, 0);
        }
        msp._pi.reverse();
        return Some(msp);
    }
    return None;
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
