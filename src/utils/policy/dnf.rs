use std::string::String;
use bn::{Group, Gt, G1, G2};
use crate::{
    RabeError,
    schemes::{
        mke08::*,
        bdabe::*
    },
};
use utils::policy::pest::{PolicyLanguage, PolicyValue, parse, PolicyType};
/// A DNF policy for the MKE08 scheme and the BDABE scheme
pub struct DnfPolicy {
    pub _terms: Vec<(Vec<String>, Gt, Gt, G1, G2)>,
}

#[allow(dead_code)]
impl DnfPolicy {
    /// Returns a new DNF policy based on a textual dnf policy.
    ///
    /// # Arguments
    ///
    /// * `policy` - A policy in JSON format as String describing the policy
    pub fn new() -> DnfPolicy {
        DnfPolicy { _terms: Vec::new() }
    }

    pub fn from_string<K: PublicAttributeKey>(
        _policy: &String,
        _pks: &Vec<K>,
        _language: PolicyLanguage
    ) -> Result<DnfPolicy, RabeError> {
        return match parse(_policy, _language) {
            Err(e) => Err(e),
            Ok(_pol) => {
                json_to_dnf(&_pol, _pks)
            }
        }
    }

    pub fn from_json(
        _json: &PolicyValue,
        _pks: &Vec<Mke08PublicAttributeKey>,
    ) -> Result<DnfPolicy, RabeError> {
        json_to_dnf(_json, _pks)
    }
}

/// A generic Public Attribute Key (PKA) for the MKE08 scheme and the BDABE scheme
pub trait PublicAttributeKey {
    // Instance method signatures; these will return a string.
    fn _str(&self) -> String {
        String::from("undefined")
    }
    fn _g1(&self) -> G1 {
        G1::one()
    }
    fn _g2(&self) -> G2 {
        G2::one()
    }
    fn _gt1(&self) -> Gt {
        Gt::one()
    }
    fn _gt2(&self) -> Gt {
        Gt::one()
    }
}

impl PublicAttributeKey for Mke08PublicAttributeKey {
    fn _str(&self) -> String {
        self._str.clone()
    }
    fn _g1(&self) -> G1 {
        self._g1
    }
    fn _g2(&self) -> G2 {
        self._g2
    }
    fn _gt1(&self) -> Gt {
        self._gt1
    }
    fn _gt2(&self) -> Gt {
        self._gt2
    }
}

impl PublicAttributeKey for BdabePublicAttributeKey {
    fn _str(&self) -> String {
        self._str.clone()
    }
    fn _g1(&self) -> G1 {
        self._a1
    }
    fn _g2(&self) -> G2 {
        self._a2
    }
    fn _gt1(&self) -> Gt {
        self._a3
    }
}

// this calcluates the sum's of all AND terms in a Bdabe DNF policy
pub fn dnf<K: PublicAttributeKey>(
    _dnfp: &mut DnfPolicy,
    _pks: &Vec<K>,
    _p: &PolicyValue,
    _i: usize,
) -> bool {
    if *_p == PolicyValue::Null {
    }
    let mut ret = true;
    // inner node
    return match _p {
        PolicyValue::Null => {
            false
        },
        PolicyValue::Array(nodes) => {
            for (i, value) in nodes.iter().enumerate() {
                ret = ret && dnf(_dnfp, _pks, &value, i + _i)
            }
            ret
        },
        PolicyValue::Object(obj) => {
            for pak in _pks.iter() {
                if pak._str() == obj.0 {
                    if _dnfp._terms.len() > _i {
                        _dnfp._terms[_i].0.push(pak._str().to_string());
                        _dnfp._terms[_i] = (
                            _dnfp._terms[_i].0.clone(),
                            _dnfp._terms[_i].1 * pak._gt1(),
                            _dnfp._terms[_i].2 * pak._gt2(),
                            _dnfp._terms[_i].3 + pak._g1(),
                            _dnfp._terms[_i].4 + pak._g2(),
                        );
                    } else {
                        _dnfp._terms.push((
                            vec![pak._str().to_string()],
                            pak._gt1(),
                            pak._gt2(),
                            pak._g1(),
                            pak._g2(),
                        ));
                    }
                }
            }
            true
        }
        _ => false
    }
}

// this calcluates the sum's of all conjunction terms in a Bdabe DNF policy ( see fn dnf() )
pub fn json_to_dnf<K: PublicAttributeKey>(
    _p: &PolicyValue,
    _pks: &Vec<K>,
) -> Result<DnfPolicy, RabeError> {
    let mut dnfp = DnfPolicy::new();
    if dnf(&mut dnfp, _pks, _p, 0) {
        dnfp._terms.sort_by(|a, b| a.0.len().cmp(&b.0.len()));
        Ok(dnfp)
    }
    else {
        panic!("Error in json_to_dnf: could not parse policy as DNF")
    }
}

pub fn policy_in_dnf(p: &PolicyValue, conjunction: bool, policy: Option<PolicyType>) -> bool {
    return match p {
        PolicyValue::Null => panic!("Error in policy_in_dnf: passed null!"),
        PolicyValue::Number(num) => true,
        PolicyValue::Object(obj) => {
            match obj.0.to_lowercase().as_str() {
                "and" => policy_in_dnf(&obj.1.as_ref().unwrap(), conjunction, Some(PolicyType::And)),
                "or" => policy_in_dnf(&obj.1.as_ref().unwrap(), conjunction, Some(PolicyType::Or)),
                _ => policy_in_dnf(&obj.1.as_ref().unwrap(), conjunction, Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::String(str) => true,
        PolicyValue::Array(children) => {
            let mut ret = true;
            let len = children.len();
            match policy {
                Some(PolicyType::And) => {
                    for i in 0usize..len {
                        ret &= policy_in_dnf(&children[i], true, None)
                    }
                    ret
                },
                Some(PolicyType::Or) => {
                    if conjunction {
                        ret = false;
                    } else {
                        for i in 0usize..len {
                            ret &= policy_in_dnf(&children[i], conjunction, None)
                        }
                    }
                    ret
                },
                _ => panic!("Error in policy_in_dnf: Array without parent AND or OR should not happen!"),
            }
        },
        PolicyValue::Boolean(bol) => true,
        _ => panic!("Error in policy_in_dnf: Unkown PolicyValue."),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_dnf_from() {
        let policy_in_dnf1 = String::from(r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}, {"name": "and", "children":  [{"name": "A"}, {"name": "C"}]}]}"#);
        let policy_in_dnf2 = String::from(r#"{"name": "and", "children": [{"name": "C"}, {"name": "D"}]}"#);
        let policy_in_dnf3 = String::from(r#"{"name": "or", "children": [{"name": "C"}, {"name": "and",  "children": [{"name": "A"}, {"name": "C"}]}, {"name" :"and",  "children": [{"name": "A"}, {"name": "D"}]}]}"#);
        let policy_not_dnf1 = String::from(r#"{"name": "and", "children": [{"name": "or",  "children":: [{"name": "A"}, {"name": "B"}]}, {"name": "and",  "children": [{"name": "C"}, {"name": "D"}]}]}"#);
        let policy_not_dnf2 = String::from(r#"{"name": "or", "children":  [{"name": "and",  "children": [{"name": "or",  "children": [{"name": "C"}, {"name": "D"}]}, {"name": "B"}]}, {"name": "and",  "children": [{"name": "C"}, {"name": "D"}]}]}"#);
        match parse(policy_in_dnf1.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(policy_in_dnf(&pol, false, Some(PolicyType::Leaf))),
            Err(e) => panic!("could not parse policy_in_dnf1")
        }
        match parse(policy_in_dnf2.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(policy_in_dnf(&pol, false, Some(PolicyType::Leaf))),
            Err(e) => panic!("could not parse policy_in_dnf2")
        }
        match parse(policy_in_dnf3.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(policy_in_dnf(&pol, false, Some(PolicyType::Leaf))),
            Err(e) => panic!("could not parse policy_in_dnf3")
        }

        match parse(policy_not_dnf1.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(!policy_in_dnf(&pol, false, Some(PolicyType::Leaf))),
            Err(e) => panic!("could not parse policy_not_dnf1")
        }
        match parse(policy_not_dnf2.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(!policy_in_dnf(&pol, false, Some(PolicyType::Leaf))),
            Err(e) => panic!("could not parse policy_not_dnf2")
        }

        let pk_a = BdabePublicAttributeKey {
            _str: String::from("A"),
            _a1: G1::one(),
            _a2: G2::one(),
            _a3: Gt::one(),
        };

        let pk_b = BdabePublicAttributeKey {
            _str: String::from("B"),
            _a1: G1::one(),
            _a2: G2::one(),
            _a3: Gt::one(),
        };

        let pk_c = BdabePublicAttributeKey {
            _str: String::from("C"),
            _a1: G1::one(),
            _a2: G2::one(),
            _a3: Gt::one(),
        };

        let mut pks: Vec<BdabePublicAttributeKey> = Vec::new();
        pks.push(pk_a);
        pks.push(pk_b);
        pks.push(pk_c);

        let policy1: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf1, &pks, PolicyLanguage::JsonPolicy).unwrap();
        let policy2: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf2, &pks, PolicyLanguage::JsonPolicy).unwrap();
        let policy3: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf3, &pks, PolicyLanguage::JsonPolicy).unwrap();

        assert_eq!(policy1._terms.len(), 2);
        assert_eq!(policy2._terms.len(), 1);
        assert_eq!(policy3._terms.len(), 3);
    }

}
