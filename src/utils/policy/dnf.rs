use std::string::String;
use rabe_bn::{Group, Gt, G1, G2};
use crate::{
    error::RabeError,
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

    pub fn from_policy<K: PublicAttributeKey>(
        _json: &PolicyValue,
        _pks: &Vec<K>,
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
    _parent: Option<&PolicyType>
) -> bool {
    let mut ret = true;
    // inner node
    return match _p {
        PolicyValue::String(_s) => {
            for pak in _pks.iter() {
                if pak._str() == *_s {
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
        },
        PolicyValue::Array(children) => {
            return match _parent {
                Some(PolicyType::And) => {
                    for child in children {
                        ret = ret && dnf(_dnfp, _pks, &child, _i, Some(&PolicyType::And))
                    }
                    ret
                },
                Some(PolicyType::Or) => {
                    for (i, child) in children.iter().enumerate() {
                        ret = ret && dnf(_dnfp, _pks, &child, i + _i, Some(&PolicyType::Or))
                    }
                    ret
                },
                _ => false,
            }
        },
        PolicyValue::Object(obj) => {
            return match _parent {
                None => dnf(_dnfp, _pks, &obj.1, _i, Some(&obj.0)),
                Some(PolicyType::Leaf) => dnf(_dnfp, _pks, &obj.1, _i, Some(&PolicyType::Leaf)),
                Some(PolicyType::Or) => {
                    match &obj.0 {
                        PolicyType::And => dnf(_dnfp, _pks, &obj.1, _i, Some(&PolicyType::And)),
                        _ => false,
                    }
                }
                Some(PolicyType::And) => {
                    match &obj.0 {
                        PolicyType::Leaf => dnf(_dnfp, _pks, &obj.1, _i, Some(&PolicyType::Leaf)),
                        _ => false,
                    }
                }
            }
        }
    }
}

// this calcluates the sum's of all conjunction terms in a Bdabe DNF policy ( see fn dnf() )
pub fn json_to_dnf<K: PublicAttributeKey>(
    _p: &PolicyValue,
    _pks: &Vec<K>,
) -> Result<DnfPolicy, RabeError> {
    let mut dnfp = DnfPolicy::new();
    if dnf(&mut dnfp, _pks, _p, 0, None) {
        dnfp._terms.sort_by(|a, b| a.0.len().cmp(&b.0.len()));
        Ok(dnfp)
    }
    else {
        Err(RabeError::new("Error in json_to_dnf: could not parse policy as DNF"))
    }
}

pub fn policy_in_dnf(pol: &PolicyValue, conjunction: bool, parent: Option<PolicyType>) -> bool {
    return match pol {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And=> policy_in_dnf(&obj.1.as_ref(), true, Some(PolicyType::And)),
                PolicyType::Or => policy_in_dnf(&obj.1.as_ref(), conjunction, Some(PolicyType::Or)),
                PolicyType::Leaf => policy_in_dnf(&obj.1.as_ref(), conjunction, Some(PolicyType::Leaf)),
            }
        },
        PolicyValue::String(_str) => true,
        PolicyValue::Array(children) => {
            let mut ret = true;
            match parent {
                Some(PolicyType::And) => {
                    for child in children {
                        ret &= policy_in_dnf(&child, true, Some(PolicyType::And))
                    }
                    return ret;
                },
                Some(PolicyType::Or) => {
                    if conjunction {
                        return false;
                    } else {
                        for child in children {
                            ret &= policy_in_dnf(&child, conjunction, Some(PolicyType::Or))
                        }
                    }
                    return ret;
                },
                _ => {
                    println!("policy_in_dnf: policy is not in DNF! Array without parent AND or OR.");
                    false
                },
            }
        }
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
            Ok(pol) => assert!(policy_in_dnf(&pol, false, None)),
            Err(e) => println!("could not parse policy_in_dnf1 {}", e)
        }
        match parse(policy_in_dnf2.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(policy_in_dnf(&pol, false, None)),
            Err(e) => println!("could not parse policy_in_dnf2 {}", e)
        }
        match parse(policy_in_dnf3.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(policy_in_dnf(&pol, false, None)),
            Err(e) => println!("could not parse policy_in_dnf3 {}", e)
        }

        match parse(policy_not_dnf1.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(!policy_in_dnf(&pol, false, None)),
            Err(e) => println!("could not parse policy_not_dnf1 (this is intended): {}", e)
        }
        match parse(policy_not_dnf2.as_ref(), PolicyLanguage::JsonPolicy) {
            Ok(pol) => assert!(!policy_in_dnf(&pol, false, None)),
            Err(e) => println!("could not parse policy_not_dnf2 (this is intended): {}", e)
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
