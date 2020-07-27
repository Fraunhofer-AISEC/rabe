extern crate bn;
#[allow(dead_code)]
extern crate serde;
extern crate serde_json;

use std::string::String;
use utils::policy::pest::{PolicyLanguage, PolicyValue, parse, PolicyType};
use RabeError;

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
    pub fn new(_policy: &String, _language: PolicyLanguage) -> Result<AbePolicy, RabeError> {
        AbePolicy::from_language(_policy, _language)
    }

    pub fn from_language(_content: &String, _language: PolicyLanguage) -> Result<AbePolicy, RabeError> {
        return match parse(_content, _language) {
            Ok(json) => json_to_msp(&json),
            Err(e) => Err(e),
        }
    }

    pub fn from_policy(_content: &PolicyValue) -> Result<AbePolicy, RabeError> {
        json_to_msp(_content)
    }
}

fn lw(msp: &mut AbePolicy, p: &PolicyValue, v: &Vec<i32>, _type: PolicyType) -> bool {
    let mut v_tmp_left = Vec::new();
    let mut v_tmp_right = v.clone();
    return match p {
        PolicyValue::Null => false,
        PolicyValue::Number(n) => true,
        PolicyValue::Boolean(b) => true,
        PolicyValue::String(attr) => {
            msp._m.insert(0, v_tmp_right);
            msp._pi.insert(0, attr.to_string());
            true
        },
        PolicyValue::Object(obj) => {
            match obj.0.to_lowercase().as_str() {
                "and" => lw(msp, &obj.1.as_ref().unwrap(), v, PolicyType::And),
                "or" => lw(msp, &obj.1.as_ref().unwrap(), v, PolicyType::Or),
                _ => lw(msp, &obj.1.as_ref().unwrap(), v, PolicyType::Leaf),
            }
        },
        PolicyValue::Array(policies) => {
            match _type {
                PolicyType::And => {
                    if policies.len() != 2 {
                        return false;
                    }
                    v_tmp_right.resize(msp._deg, ZERO);
                    v_tmp_right.push(PLUS);
                    v_tmp_left.resize(msp._deg, ZERO);
                    v_tmp_left.push(MINUS);
                    msp._deg += 1;
                    lw(msp, &policies[0], &v_tmp_right, PolicyType::Leaf) && lw(msp, &policies[1], &v_tmp_left, PolicyType::Leaf)
                },
                PolicyType::Or => {
                    let mut _ret = true;
                    for policy in policies {
                        _ret &= lw(msp, &policy, &v, PolicyType::Leaf);
                    }
                    return _ret;
                },
                PolicyType::Leaf => false
            }
        },
        _ => false
    };
}

//#[doc = /**
// * BEWARE: policy must be in DNF!
// */]
pub fn json_to_msp(p: &PolicyValue) -> Result<AbePolicy, RabeError> {
    let mut v: Vec<i32> = Vec::new();
    let mut _values: Vec<Vec<i32>> = Vec::new();
    let mut _attributes: Vec<String> = Vec::new();
    let mut msp = AbePolicy {
        _m: _values,
        _pi: _attributes,
        _deg: 1,
    };
    v.push(PLUS);
    if lw(&mut msp, p, &v, PolicyType::Leaf) {
        for p in &mut msp._m {
            p.resize(msp._deg, ZERO);
        }
        msp._pi.reverse();
        return Ok(msp);
    }
    return Err(RabeError::new(&"lw algorithm failed =("))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_msp_from() {
        let policy = String::from(r#"{name:"or", children:[{name:"and", children:[{name:"A"},{name:"B"}]},{name:"or", children:[{name:"C"},{name:"D"}]}]}"#);
        let mut _values: Vec<Vec<bn::Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let _zero = 0;
        let _plus = 1;
        let _minus = -1;
        let p1 = vec![_zero, _zero, _minus];
        let p2 = vec![_plus, _zero, _plus];
        let p3 = vec![_zero, _minus, _zero];
        let p4 = vec![_plus, _plus, _zero];
        match parse(policy.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
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
                match AbePolicy::from_policy(&pol).ok() {
                    None => assert!(false),
                    Some(_msp) => {
                        for i in 0..4 {
                            let p = &_msp._m[i];
                            let p_test = &_msp_static._m[i];
                            for j in 0..3 {
                                //println!("_mspg[{:?}][{:?}]: {:?}", i, j, p[j]);
                                //println!("_msps[{:?}][{:?}]: {:?}", i, j, p_test[j]);
                                assert_eq!(p[j], p_test[j]);
                            }
                            //println!("_pi[{:?}]{:?} _pi[{:?}]{:?}",i,_msp_static._pi[i],i,_msp._pi[i]);
                            assert_eq!(_msp_static._pi[i], _msp._pi[i]);
                        }
                        assert_eq!(_msp_static._deg, _msp._deg);
                    }
                }
            },
            Err(e) => panic!("could not parse policy")
        }

    }
}
