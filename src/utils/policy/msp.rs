extern crate bn;
#[allow(dead_code)]
extern crate serde;
extern crate serde_json;

use std::string::String;
use utils::tools::string_to_json;

const ZERO: i32 = 0;
const PLUS: i32 = 1;
const MINUS: i32 = -1;

pub struct AbePolicy {
    pub _m: Vec<Vec<i32>>,
    pub _pi: Vec<String>,
    pub _deg: usize,
}

#[allow(dead_code)]
impl AbePolicy {
    /// Returns a new ABE policy based on a textual policy. The policy is generated using Lewo et al. conversion algorithm.
    ///
    /// # Arguments
    ///
    /// * `policy` - A policy in JSON format as String describing the policy
    pub fn new(_policy: &String) -> Option<AbePolicy> {
        AbePolicy::from_string(_policy)
    }

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
        let mut _ret = true;
        for _i in 0usize..p["OR"].as_array().unwrap().len() {
            _ret &= lw(msp, &p["OR"][_i], v.clone());
        }
        return _ret;
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_msp_from() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let mut _values: Vec<Vec<bn::Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let _zero = 0;
        let _plus = 1;
        let _minus = -1;
        let p1 = vec![_zero, _zero, _minus];
        let p2 = vec![_plus, _zero, _plus];
        let p3 = vec![_zero, _minus, _zero];
        let p4 = vec![_plus, _plus, _zero];
        let mut _msp_static = AbePolicy {
            _m: vec![p1, p2, p3, p4],
            _pi: vec![
                String::from("A"),
                String::from("B"),
                String::from("C"),
                String::from("D"),
            ],
            _deg: 3,
        };
        match AbePolicy::from_string(&policy) {
            None => assert!(false),
            Some(_msp) => {
                for i in 0..4 {
                    let p = &_msp._m[i];
                    let p_test = &_msp_static._m[i];
                    for j in 0..3 {
                        //println!("_mspg[{:?}][{:?}]: {:?}", i, j, p[j]);
                        //println!("_msps[{:?}][{:?}]: {:?}", i, j, p_test[j]);
                        assert!(p[j] == p_test[j]);
                    }
                    //println!("_pi[{:?}]{:?} _pi[{:?}]{:?}",i,_msp_static._pi[i],i,_msp._pi[i]);
                    assert!(_msp_static._pi[i] == _msp._pi[i]);
                }
                assert!(_msp_static._deg == _msp._deg);
            }
        }
    }
}
