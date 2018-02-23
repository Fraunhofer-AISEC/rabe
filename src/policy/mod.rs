#[allow(dead_code)]
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
    pub _terms: Vec<(Vec<(String)>, bn::Gt, bn::G1, bn::G2)>,
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
                ret &= policy_in_dnf(&p["OR"][i], conjunction)
            }
        }
        return ret;

    } else if p["AND"].is_array() {
        for i in 0usize..p["AND"].as_array().unwrap().len() {
            ret &= policy_in_dnf(&p["AND"][i], true)
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


// this calcluates the sum's of all AND terms in a MKE08 DNF policy
// and generates for each conjunction a random value R_j \in Z_p
fn dnf(
    _dnfp: &mut DnfPolicy,
    _pks: &Vec<Mke08PublicAttributeKey>,
    _p: &serde_json::Value,
    _index: usize,
) -> bool {

    if *_p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }
    let mut ret = true;
    // inner node
    if _p["OR"].is_array() {
        let len = _p["OR"].as_array().unwrap().len();
        for i in (0usize..len).rev() {
            ret &= dnf(_dnfp, _pks, &_p["OR"][len - i - 1], (i + _index))
        }
        return ret;

    } else if _p["AND"].is_array() {
        let len = _p["AND"].as_array().unwrap().len();
        for i in 0usize..len {
            ret &= dnf(_dnfp, _pks, &_p["AND"][i], _index)
        }
        return ret;
    }
    //Leaf
    else if _p["ATT"] != serde_json::Value::Null {
        match _p["ATT"].as_str() {
            Some(s) => {
                for pk in _pks.iter() {
                    if pk._str == s {
                        if _dnfp._terms.len() > _index {
                            _dnfp._terms[_index].0.push(s.to_string());
                            _dnfp._terms[_index] = (
                                _dnfp._terms[_index].0.clone(),
                                _dnfp._terms[_index].1 * pk._gt,
                                _dnfp._terms[_index].2 + pk._g1,
                                _dnfp._terms[_index].3 + pk._g2,
                            );
                        } else {
                            _dnfp._terms.push(
                                (vec![s.to_string()], pk._gt, pk._g1, pk._g2),
                            );
                        }
                    }
                }
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
            println!("Error parsing string as json");
            return None;
        }
        Ok(pol) => {
            return Some(pol);
        }
    }
}

// this calcluates the sum's of all conjunction terms in a MKE08 DNF policy ( see fn dnf() )
pub fn json_to_dnf(
    _json: &serde_json::Value,
    _pks: &Vec<Mke08PublicAttributeKey>,
) -> Option<DnfPolicy> {
    let mut _conjunctions: Vec<(Vec<(String)>, bn::Gt, bn::G1, bn::G2)> = Vec::new();
    let mut _attrs: Vec<(String)> = Vec::new();
    _conjunctions.push((_attrs, Gt::one(), G1::zero(), G2::zero()));
    let mut dnfp = DnfPolicy { _terms: _conjunctions };
    if dnf(&mut dnfp, _pks, _json, 0) {
        dnfp._terms.sort_by(|a, b| a.0.len().cmp(&b.0.len()));
        return Some(dnfp);
    }
    return None;
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_msp_from() {
        let policy = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
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

    #[test]
    fn test_dnf_from() {
        let policy_in_dnf1 = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}]}"#);
        let policy_in_dnf2 = String::from(r#"{"AND": [{"ATT": "C"}, {"ATT": "D"}]}"#);
        let policy_in_dnf3 = String::from(r#"{"OR": [{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"ATT": "C"}]}, {"AND": [{"ATT": "C"}, {"ATT": "B"}]}]}"#);
        let policy_not_dnf1 = String::from(r#"{"AND": [{"OR": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let policy_not_dnf2 = String::from(r#"{"OR": [{"AND": [{"OR": [{"ATT": "C"}, {"ATT": "D"}]}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        assert!(DnfPolicy::is_in_dnf(&policy_in_dnf1));
        assert!(DnfPolicy::is_in_dnf(&policy_in_dnf2));
        assert!(DnfPolicy::is_in_dnf(&policy_in_dnf3));
        assert!(!DnfPolicy::is_in_dnf(&policy_not_dnf1));
        assert!(!DnfPolicy::is_in_dnf(&policy_not_dnf2));

        let pk_a = Mke08PublicAttributeKey {
            _str: String::from("A"),
            _g1: G1::one(),
            _g2: G2::one(),
            _gt: Gt::one(),
        };

        let pk_b = Mke08PublicAttributeKey {
            _str: String::from("B"),
            _g1: G1::one(),
            _g2: G2::one(),
            _gt: Gt::one(),
        };

        let pk_c = Mke08PublicAttributeKey {
            _str: String::from("C"),
            _g1: G1::one(),
            _g2: G2::one(),
            _gt: Gt::one(),
        };

        let mut pks: Vec<Mke08PublicAttributeKey> = Vec::new();
        pks.push(pk_a);
        pks.push(pk_b);
        pks.push(pk_c);

        let policy1: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf1, &pks).unwrap();
        let policy2: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf2, &pks).unwrap();
        let policy3: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf3, &pks).unwrap();

        assert!(policy1._terms.len() == 2);
        assert!(policy2._terms.len() == 1);
        assert!(policy3._terms.len() == 3);
    }

}
