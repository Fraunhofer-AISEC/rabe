extern crate serde;
extern crate serde_json;

extern crate bn;

use std::string::String;

pub struct AbePolicy {
    pub _m: Vec<Vec<bn::Fr>>,
    pub _pi: Vec<String>,
    pub _deg: usize,
}

fn lw(msp: &mut AbePolicy, p: &serde_json::Value, v: Vec<bn::Fr>) -> bool {
    let mut v_tmp_left = Vec::new();
    let mut v_tmp_right = v.clone();

    if *p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }

    //Leaf
    if p["ATT"] != serde_json::Value::Null {
        msp._m.insert(0, v_tmp_right);
        match p["ATT"].as_str() {
            Some(s) => msp._pi.insert(0, String::from(s)),
            None => println!("ERROR attribute value"),
        }
        return true;
    }


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
        msp._deg += 1;
        v_tmp_right.resize(msp._deg - 1, bn::Fr::zero());
        v_tmp_right.push(bn::Fr::one());
        v_tmp_left.resize(msp._deg - 1, bn::Fr::zero());
        v_tmp_left.push(-bn::Fr::one());

        return lw(msp, &p["AND"][0], v_tmp_right) && lw(msp, &p["AND"][1], v_tmp_left);

    } else {
        println!("Policy invalid. No AND or OR found");
        return false;
    }
}


//#[doc = /**
// * BEWARE: policy must be in DNF!
// */]
pub fn json_to_msp(json: &serde_json::Value) -> Option<AbePolicy> {
    let mut v: Vec<bn::Fr> = Vec::new();
    let mut _matrix: Vec<Vec<bn::Fr>> = Vec::new();
    let mut _attributes: Vec<String> = Vec::new();
    let mut msp = AbePolicy {
        _m: _matrix,
        _pi: _attributes,
        _deg: 1,
    };

    v.push(bn::Fr::one());
    if lw(&mut msp, json, v) {
        for p in &mut msp._m {
            p.resize(msp._deg, bn::Fr::zero());
        }
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
