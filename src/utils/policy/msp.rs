use std::string::String;
use utils::policy::pest::{PolicyLanguage, PolicyValue, parse, PolicyType};
use crate::error::RabeError;
use std::fmt::{Display, Formatter, Result as FormatResult};

const ZERO: i8 = 0;
const PLUS: i8 = 1;
const MINUS: i8 = -1;


pub struct AbePolicy {
    pub _m: Vec<Vec<i8>>,
    pub _pi: Vec<String>,
    pub _c: usize,
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
            Ok(json) => calculate_msp(&json),
            Err(e) => Err(e),
        }
    }

    pub fn from_policy(_content: &PolicyValue) -> Result<AbePolicy, RabeError> {
        calculate_msp(_content)
    }
}

impl Display for AbePolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> FormatResult {
        let mut _pi_str = String::from("[");
        let mut _m_str = String::from("[");
        for attribute in &self._pi {
            _pi_str.push('"');
            _pi_str.push_str(&attribute);
            _pi_str.push('"');
            _pi_str.push(',');
        }
        _pi_str.pop();
        _pi_str.push(']');
        for row in &self._m {
            _m_str.push('(');
            for col in row {
                _m_str.push_str(&col.to_string());
                _m_str.push(',');
            }
            _m_str.pop();
            _m_str.push(')');
            _m_str.push(',');
        }
        _m_str.pop();
        _m_str.push(']');
        write!(f, "{{_m: {}, _pi: {}, _c: {}}}", _m_str, _pi_str, self._c)
    }
}


//#[doc = /**
// * BEWARE: policy must be in DNF!
// */]
pub fn calculate_msp(p: &PolicyValue) -> Result<AbePolicy, RabeError> {
    let mut v: Vec<i8> = Vec::new();
    let mut _values: Vec<Vec<i8>> = Vec::new();
    let mut _attributes: Vec<String> = Vec::new();
    let mut msp = AbePolicy {
        _m: _values,
        _pi: _attributes,
        _c: 1,
    };
    v.push(PLUS);
    if lw(&mut msp, p, &v, None) {
        for val in &mut msp._m {
            val.resize(msp._c, ZERO);
        }
        // permutate both _pi and _m according to _pi
        let permutation = permutation::sort(&msp._pi[..]);
        msp._pi = permutation.apply_slice(&msp._pi[..]);
        msp._m = permutation.apply_slice(&msp._m[..]);
        return Ok(msp);
    }
    return Err(RabeError::new("lewko waters algorithm failed =("))
}
/// Converting from Boolean Formulas to LSSS Matrices
/// Lewko Waters: "Decentralizing Attribute-Based Encryption" Appendix G
fn lw(msp: &mut AbePolicy, p: &PolicyValue, v: &Vec<i8>, _parent: Option<PolicyType>) -> bool {
    let mut v_tmp_left = Vec::new();
    let mut v_tmp_right = v.clone();
    return match p {
        PolicyValue::String(attr) => {
            msp._m.insert(0, v_tmp_right);
            msp._pi.insert(0, attr.to_string());
            true
        },
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => lw(msp, &obj.1.as_ref(), v, Some(PolicyType::And)),
                PolicyType::Or => lw(msp, &obj.1.as_ref(), v, Some(PolicyType::Or)),
                PolicyType::Leaf => lw(msp, &obj.1.as_ref(), v, Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::Array(policies) => {
            let len = policies.len();
            if len < 2 {
                panic!("lw: policy with just a single attribute is not allowed");
            }
            return match _parent {
                Some(PolicyType::Or) => {
                    let mut _ret = true;
                    for policy in policies {
                        _ret &= lw(msp, &policy, &v, Some(PolicyType::Or));
                    }
                    return _ret;
                },
                Some(PolicyType::And) => {
                    if len != 2 {
                        panic!("lw: Invalid policy. Number of arguments under AND != 2");
                    }
                    v_tmp_right.resize(msp._c, ZERO);
                    v_tmp_right.push(PLUS);
                    v_tmp_left.resize(msp._c, ZERO);
                    v_tmp_left.push(MINUS);
                    msp._c += 1;
                    lw(msp, &policies[0], &v_tmp_right, Some(PolicyType::And)) && lw(msp, &policies[1], &v_tmp_left, Some(PolicyType::And))
                },
                Some(PolicyType::Leaf) => false,
                None => false,
            }
        }
    };
}


#[cfg(test)]
mod tests {

    use super::*;
    use rabe_bn::Fr;

    #[test]
    fn test_msp_from() {
        let policy = String::from(r#"{name:"and", children:[{name:"A"}, {name:"or", "children":[{name:"D"}, {name:"and", "children":[{name:"B"},{name:"C"}]}]} ]}"#);
        let mut _values: Vec<Vec<Fr>> = Vec::new();
        let mut _attributes: Vec<String> = Vec::new();
        let _zero = 0;
        let _plus = 1;
        let _minus = -1;
        let p1 = vec![_plus, _plus, _zero];
        let p2 = vec![_zero, _minus, _plus];
        let p3 = vec![_zero, _zero, _minus];
        let p4 = vec![_zero, _minus, _zero];
        match parse(policy.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                let _msp_static = AbePolicy {
                    _m: vec![p1, p2, p3, p4],
                    _pi: vec![
                        String::from("A"),
                        String::from("B"),
                        String::from("C"),
                        String::from("D"),
                    ],
                    _c: 3,
                };
                match AbePolicy::from_policy(&pol).ok() {
                    None => assert!(false),
                    Some(_msp) => {
                        for i in 0..4 {
                            let p = &_msp._m[i];
                            let p_test = &_msp_static._m[i];
                            for j in 0..3 {
                                assert_eq!(p[j], p_test[j]);
                            }
                            //println!("_pi[{:?}]{:?} _pi[{:?}]{:?}",i,_msp_static._pi[i],i,_msp._pi[i]);
                            assert_eq!(_msp_static._pi[i], _msp._pi[i]);
                        }
                        assert_eq!(_msp_static._c, _msp._c);
                    }
                }
            },
            Err(e) => println!("test_msp_from: could not parse policy {}", e)
        }

    }
}
