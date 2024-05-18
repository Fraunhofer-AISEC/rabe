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
    pub terms: Vec<(Vec<String>, Gt, Gt, G1, G2)>,
}

#[allow(dead_code)]
impl DnfPolicy {
    /// Returns a new DNF policy based on a textual dnf policy.
    ///
    /// # Arguments
    ///
    /// * `policy` - A policy in JSON format as String describing the policy
    pub fn new() -> DnfPolicy {
        DnfPolicy { terms: Vec::new() }
    }

    pub fn from_string<K: PublicAttributeKey>(
        policy: &str,
        pks: &[&K],
        language: PolicyLanguage
    ) -> Result<DnfPolicy, RabeError> {
        return match parse(policy, language) {
            Err(e) => Err(e),
            Ok(_pol) => {
                json_to_dnf(&_pol, pks)
            }
        }
    }

    pub fn from_policy<K: PublicAttributeKey>(
        json: &PolicyValue,
        pks: &[&K],
    ) -> Result<DnfPolicy, RabeError> {
        json_to_dnf(json, pks)
    }
}

/// A generic Public Attribute Key (PKA) for the MKE08 scheme and the BDABE scheme
pub trait PublicAttributeKey {
    // Instance method signatures; these will return a string.
    fn attr(&self) -> String {
        String::from("undefined")
    }
    fn g1(&self) -> G1 {
        G1::one()
    }
    fn g2(&self) -> G2 {
        G2::one()
    }
    fn gt1(&self) -> Gt {
        Gt::one()
    }
    fn gt2(&self) -> Gt {
        Gt::one()
    }
}

impl PublicAttributeKey for Mke08PublicAttributeKey {
    fn attr(&self) -> String {
        self.attr.clone()
    }
    fn g1(&self) -> G1 {
        self.g1
    }
    fn g2(&self) -> G2 {
        self.g2
    }
    fn gt1(&self) -> Gt {
        self.gt1
    }
    fn gt2(&self) -> Gt {
        self.gt2
    }
}

impl PublicAttributeKey for BdabePublicAttributeKey {
    fn attr(&self) -> String {
        self.attr.clone()
    }
    fn g1(&self) -> G1 {
        self.a1
    }
    fn g2(&self) -> G2 {
        self.a2
    }
    fn gt1(&self) -> Gt {
        self.a3
    }
}

// this calcluates the sum's of all AND terms in a Bdabe DNF policy
pub fn dnf<K: PublicAttributeKey>(
    dnf_policy: &mut DnfPolicy,
    pks: &[&K],
    policy_value: &PolicyValue,
    i: usize,
    parent: Option<&PolicyType>
) -> bool {
    let mut ret = true;
    // inner node
    return match policy_value {
        PolicyValue::String(_s) => {
            for pak in pks.iter() {
                if pak.attr() == *_s.0 {
                    if dnf_policy.terms.len() > i.clone() {
                        dnf_policy.terms[i.clone()].0.push(pak.attr().to_string());
                        dnf_policy.terms[i.clone()] = (
                            dnf_policy.terms[i.clone()].0.clone(),
                            dnf_policy.terms[i.clone()].1 * pak.gt1(),
                            dnf_policy.terms[i.clone()].2 * pak.gt2(),
                            dnf_policy.terms[i.clone()].3 + pak.g1(),
                            dnf_policy.terms[i.clone()].4 + pak.g2(),
                        );
                    } else {
                        dnf_policy.terms.push((
                            vec![pak.attr().to_string()],
                            pak.gt1(),
                            pak.gt2(),
                            pak.g1(),
                            pak.g2(),
                        ));
                    }
                }
            }
            true
        },
        PolicyValue::Array(children) => {
            return match parent {
                Some(PolicyType::And) => {
                    for child in children {
                        ret = ret && dnf(dnf_policy, pks, &child, i.clone(), Some(&PolicyType::And))
                    }
                    ret
                },
                Some(PolicyType::Or) => {
                    for (i, child) in children.iter().enumerate() {
                        ret = ret && dnf(dnf_policy, pks, &child, i.clone() + i.clone(), Some(&PolicyType::Or))
                    }
                    ret
                },
                _ => false,
            }
        },
        PolicyValue::Object(obj) => {
            return match parent {
                None => dnf(dnf_policy, pks, &obj.1, i, Some(&obj.0)),
                Some(PolicyType::Leaf) => dnf(dnf_policy, pks, &obj.1, i, Some(&PolicyType::Leaf)),
                Some(PolicyType::Or) => {
                    match &obj.0 {
                        PolicyType::And => dnf(dnf_policy, pks, &obj.1, i, Some(&PolicyType::And)),
                        _ => false,
                    }
                }
                Some(PolicyType::And) => {
                    match &obj.0 {
                        PolicyType::Leaf => dnf(dnf_policy, pks, &obj.1, i, Some(&PolicyType::Leaf)),
                        _ => false,
                    }
                }
            }
        }
    }
}

// this calcluates the sum's of all conjunction terms in a Bdabe DNF policy ( see fn dnf() )
pub fn json_to_dnf<K: PublicAttributeKey>(
    policy_value: &PolicyValue,
    pks: &[&K],
) -> Result<DnfPolicy, RabeError> {
    let mut dnfp = DnfPolicy::new();
    if dnf(&mut dnfp, pks, policy_value, 0, None) {
        dnfp.terms.sort_by(|a, b| a.0.len().cmp(&b.0.len()));
        Ok(dnfp)
    }
    else {
        Err(RabeError::new("Error in json_to_dnf: could not parse policy as DNF"))
    }
}

pub fn policy_in_dnf(
    policy_value: &PolicyValue,
    conjunction: bool,
    parent: Option<PolicyType>
) -> bool {
    return match policy_value {
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
            attr: String::from("A"),
            a1: G1::one(),
            a2: G2::one(),
            a3: Gt::one(),
        };

        let pk_b = BdabePublicAttributeKey {
            attr: String::from("B"),
            a1: G1::one(),
            a2: G2::one(),
            a3: Gt::one(),
        };

        let pk_c = BdabePublicAttributeKey {
            attr: String::from("C"),
            a1: G1::one(),
            a2: G2::one(),
            a3: Gt::one(),
        };

        let pk_d = BdabePublicAttributeKey {
            attr: String::from("D"),
            a1: G1::one(),
            a2: G2::one(),
            a3: Gt::one(),
        };

        let pks: Vec<&BdabePublicAttributeKey> = vec![&pk_a, &pk_b, &pk_c, &pk_d];

        let policy1: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf1, &pks.as_slice(), PolicyLanguage::JsonPolicy).unwrap();
        let policy2: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf2, &pks.as_slice(), PolicyLanguage::JsonPolicy).unwrap();
        let policy3: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf3, &pks.as_slice(), PolicyLanguage::JsonPolicy).unwrap();

        assert_eq!(policy1.terms.len(), 3);
        assert_eq!(policy2.terms.len(), 1);
        assert_eq!(policy3.terms.len(), 5);
    }

}
