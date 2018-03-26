#[allow(dead_code)]
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rustc_serialize;

use std::string::String;
use tools::{string_to_json, into_hex};
use mke08::*;
use bdabe::*;
use bn::*;

/// A DNF policy for the MKE08 scheme and the BDABE scheme
pub struct DnfPolicy {
    pub _terms: Vec<(Vec<(String)>, bn::Gt, bn::Gt, bn::G1, bn::G2)>,
}


impl DnfPolicy {
    /// Returns a new DNF policy based on a textual dnf policy.
    ///
    /// # Arguments
    ///
    /// * `policy` - A policy in JSON format as String describing the policy
    pub fn new() -> DnfPolicy {
        let _empty: Vec<(Vec<(String)>, bn::Gt, bn::Gt, bn::G1, bn::G2)> = Vec::new();
        DnfPolicy { _terms: _empty }
    }

    pub fn from_string<K: PublicAttributeKey>(
        _policy: &String,
        _pks: &Vec<K>,
    ) -> Option<DnfPolicy> {
        match string_to_json(_policy) {
            None => {
                println!("Error parsing policy");
                return None;
            }
            Some(_j) => {
                return json_to_dnf(&_j, _pks);
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

/// A generic Public Attribute Key (PKA) for the MKE08 scheme and the BDABE scheme
pub trait PublicAttributeKey {
    // Instance method signatures; these will return a string.
    fn _str(&self) -> String {
        String::from("undefined")
    }
    fn _g1(&self) -> bn::G1 {
        G1::one()
    }
    fn _g2(&self) -> bn::G2 {
        G2::one()
    }
    fn _gt1(&self) -> bn::Gt {
        Gt::one()
    }
    fn _gt2(&self) -> bn::Gt {
        Gt::one()
    }
    // Traits can provide default method definitions.
    fn print(&self) {
        println!(
            "{} represented by g1:{}, g2:{}, gt1:{}, gt2:{}",
            self._str(),
            into_hex(self._g1()).unwrap(),
            into_hex(self._g2()).unwrap(),
            into_hex(self._gt1()).unwrap(),
            into_hex(self._gt2()).unwrap(),
        );
    }
}

impl PublicAttributeKey for Mke08PublicAttributeKey {
    fn _str(&self) -> String {
        self._str.clone()
    }
    fn _g1(&self) -> bn::G1 {
        self._g1
    }
    fn _g2(&self) -> bn::G2 {
        self._g2
    }
    fn _gt1(&self) -> bn::Gt {
        self._gt1
    }
    fn _gt2(&self) -> bn::Gt {
        self._gt2
    }
}

impl PublicAttributeKey for BdabePublicAttributeKey {
    fn _str(&self) -> String {
        self._str.clone()
    }
    fn _g1(&self) -> bn::G1 {
        self._a1
    }
    fn _g2(&self) -> bn::G2 {
        self._a2
    }
    fn _gt1(&self) -> bn::Gt {
        self._a3
    }
}

fn get_pka_str(key: &PublicAttributeKey) -> String {
    key._str()
}

pub fn policy_in_dnf(p: &serde_json::Value, conjunction: bool) -> bool {
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


// this calcluates the sum's of all AND terms in a Bdabe DNF policy
pub fn dnf<K: PublicAttributeKey>(
    _dnfp: &mut DnfPolicy,
    _pks: &Vec<K>,
    _p: &serde_json::Value,
    _i: usize,
) -> bool {

    if *_p == serde_json::Value::Null {
        println!("Error passed null!");
        return false;
    }
    let mut ret = true;
    // inner node
    if _p["OR"].is_array() {
        let len = _p["OR"].as_array().unwrap().len();
        for i in 0usize..len {
            ret = ret && dnf(_dnfp, _pks, &_p["OR"][i], (i + _i))
        }
        return ret;

    } else if _p["AND"].is_array() {
        let len = _p["AND"].as_array().unwrap().len();
        for i in 0usize..len {
            ret = ret && dnf(_dnfp, _pks, &_p["AND"][i], _i)
        }
        return ret;
    }
    //Leaf
    else if _p["ATT"] != serde_json::Value::Null {
        match _p["ATT"].as_str() {
            Some(_s) => {
                for pak in _pks.iter() {
                    if pak._str() == _s {
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


// this calcluates the sum's of all conjunction terms in a Bdabe DNF policy ( see fn dnf() )
pub fn json_to_dnf<K: PublicAttributeKey>(
    _json: &serde_json::Value,
    _pks: &Vec<K>,
) -> Option<DnfPolicy> {
    let mut dnfp = DnfPolicy::new();
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
    fn test_dnf_from() {
        let policy_in_dnf1 = String::from(r#"{"OR": [{"AND": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}]}"#);
        let policy_in_dnf2 = String::from(r#"{"AND": [{"ATT": "C"}, {"ATT": "D"}]}"#);
        let policy_in_dnf3 = String::from(r#"{"OR": [{"ATT": "C"}, {"AND": [{"ATT": "A"}, {"ATT": "C"}]}, {"AND": [{"ATT": "A"}, {"ATT": "D"}]}]}"#);
        let policy_not_dnf1 = String::from(r#"{"AND": [{"OR": [{"ATT": "A"}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        let policy_not_dnf2 = String::from(r#"{"OR": [{"AND": [{"OR": [{"ATT": "C"}, {"ATT": "D"}]}, {"ATT": "B"}]}, {"AND": [{"ATT": "C"}, {"ATT": "D"}]}]}"#);
        assert!(DnfPolicy::is_in_dnf(&policy_in_dnf1));
        assert!(DnfPolicy::is_in_dnf(&policy_in_dnf2));
        assert!(DnfPolicy::is_in_dnf(&policy_in_dnf3));
        assert!(!DnfPolicy::is_in_dnf(&policy_not_dnf1));
        assert!(!DnfPolicy::is_in_dnf(&policy_not_dnf2));

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

        let policy1: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf1, &pks).unwrap();
        let policy2: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf2, &pks).unwrap();
        let policy3: DnfPolicy = DnfPolicy::from_string(&policy_in_dnf3, &pks).unwrap();

        assert!(policy1._terms.len() == 2);
        assert!(policy2._terms.len() == 1);
        assert!(policy3._terms.len() == 3);

    }

}
