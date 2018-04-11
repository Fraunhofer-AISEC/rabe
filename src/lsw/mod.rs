extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate num_bigint;
extern crate blake2_rfc;

use std::string::String;
use bn::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use bincode::*;
use rand::Rng;
use policy::msp::AbePolicy;
use tools::*;
use std::ops::Neg;
use secretsharing::{gen_shares_str, calc_coefficients_str};

//////////////////////////////////////////////////////
// LSW KP-ABE structs
//////////////////////////////////////////////////////
#[derive(Serialize, Deserialize, PartialEq)]
pub struct KpAbePublicKey {
    _g_g1: bn::G1,
    _g_g2: bn::G2,
    _g_g1_b: bn::G1,
    _g_g1_b2: bn::G1,
    _h_g1_b: bn::G1,
    _e_gg_alpha: bn::Gt,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct KpAbeMasterKey {
    _alpha1: bn::Fr,
    _alpha2: bn::Fr,
    _b: bn::Fr,
    _h_g1: bn::G1,
    _h_g2: bn::G2,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct KpAbeSecretKey {
    _policy: String,
    _d_i: Vec<(bn::G1, bn::G2, bn::G1, bn::G1, bn::G1)>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct KpAbeCiphertext {
    _attr: Vec<(String)>,
    _e1: bn::Gt,
    _e2: bn::G2,
    _e3: Vec<(bn::G1)>,
    _e4: Vec<(bn::G1)>,
    _e5: Vec<(bn::G1)>,
    _ct: Vec<u8>,
}

//////////////////////////////////////////
// LSW KP-ABE on type-3
//////////////////////////////////////////

// SETUP

pub fn kpabe_setup() -> (KpAbePublicKey, KpAbeMasterKey) {
    // random number generator
    let _rng = &mut rand::thread_rng();
    // generate random alpha1, alpha2 and b
    let _alpha1 = Fr::random(_rng);
    let _alpha2 = Fr::random(_rng);
    let _alpha = _alpha1 * _alpha2;
    let _b = Fr::random(_rng);
    let _g_g1 = G1::random(_rng);
    let _g_g2 = G2::random(_rng);
    let _h_g1 = G1::random(_rng);
    let _h_g2 = G2::random(_rng);
    let _g1_b = _g_g1 * _b;
    // calculate the pairing between g1 and g2^alpha
    let _e_gg_alpha = pairing(_g_g1, _g_g2).pow(_alpha);
    // set values of PK
    let _pk = KpAbePublicKey {
        _g_g1: _g_g1,
        _g_g2: _g_g2,
        _g_g1_b: _g1_b,
        _g_g1_b2: _g1_b * _b,
        _h_g1_b: _h_g1 * _b,
        _e_gg_alpha: _e_gg_alpha,
    };
    // set values of MSK
    let _msk = KpAbeMasterKey {
        _alpha1: _alpha1,
        _alpha2: _alpha2,
        _b: _b,
        _h_g1: _h_g1,
        _h_g2: _h_g2,
    };
    // return PK and MSK
    return (_pk, _msk);
}

// KEYGEN

pub fn kpabe_keygen(
    pk: &KpAbePublicKey,
    msk: &KpAbeMasterKey,
    policy: &String,
) -> Option<KpAbeSecretKey> {
    // random number generator
    let _rng = &mut rand::thread_rng();
    //let _attr_list = get_attribute_list(policy).unwrap();
    let _shares = gen_shares_str(msk._alpha1, policy).unwrap();

    let mut _d: Vec<(bn::G1, bn::G2, bn::G1, bn::G1, bn::G1)> = Vec::new();
    let mut _d_i: (bn::G1, bn::G2, bn::G1, bn::G1, bn::G1) =
        (G1::zero(), G2::zero(), G1::zero(), G1::zero(), G1::zero());

    for (_i, _share) in _shares.iter().enumerate() {
        let _r = Fr::random(_rng);
        let mut _sum = Fr::zero();
        if !is_negative(&_share.0) {
            _d_i.0 = (pk._g_g1 * (msk._alpha2 * _share.1)) +
                (blake2b_hash_g1(pk._g_g1, &_share.0) * _r);
            _d_i.1 = pk._g_g2 * _r;
        } else {
            _d_i.2 = (pk._g_g1 * (msk._alpha2 * _share.1)) + (pk._g_g1_b2 * _r);
            _d_i.3 = pk._g_g1_b * (blake2b_hash_fr(&_share.0) * _r) + (msk._h_g1 * _r);
            _d_i.4 = pk._g_g1 * _r.neg();
        }
        _d.push(_d_i);
    }
    return Some(KpAbeSecretKey {
        _policy: policy.clone(),
        _d_i: _d,
    });
}

pub fn kpabe_encrypt(
    pk: &KpAbePublicKey,
    _attributes: &Vec<String>,
    _plaintext: &[u8],
) -> Option<KpAbeCiphertext> {
    if _attributes.is_empty() || _plaintext.is_empty() {
        return None;
    } else {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // e3,4,5 vectors
        let mut _e3: Vec<(bn::G1)> = Vec::new();
        let mut _e4: Vec<(bn::G1)> = Vec::new();
        let mut _e5: Vec<(bn::G1)> = Vec::new();
        // random secret
        let _s = Fr::random(_rng);
        // sx vector
        let mut _sx: Vec<(bn::Fr)> = Vec::new();
        _sx.push(_s);
        for _i in 0usize.._attributes.len() {
            _sx.push(Fr::random(_rng));
            _sx[0] = _sx[0] - _sx[_i];
        }
        for _i in 0usize.._attributes.len() {
            _e3.push(blake2b_hash_g1(pk._g_g1, &_attributes[_i]) * _s);
            _e4.push(pk._g_g1_b * _sx[_i]);
            _e5.push(
                (pk._g_g1_b2 * (_sx[_i] * blake2b_hash_fr(&_attributes[_i]))) +
                    (pk._h_g1_b * _sx[_i]),
            );
        }
        // random message
        let _msg = pairing(G1::random(_rng), G2::random(_rng));
        let _e1 = (pk._e_gg_alpha.pow(_s)) * _msg;
        let _e2 = pk._g_g2 * _s;
        //Encrypt plaintext using derived key from secret
        return Some(KpAbeCiphertext {
            _attr: _attributes.clone(),
            _e1: _e1,
            _e2: _e2,
            _e3: _e3,
            _e4: _e4,
            _e5: _e5,
            _ct: encrypt_symmetric(&_msg, &_plaintext.to_vec()).unwrap(),
        });

    }
}

pub fn kpabe_decrypt(sk: &KpAbeSecretKey, ct: &KpAbeCiphertext) -> Option<Vec<u8>> {
    if traverse_str(&ct._attr, &sk._policy) == false {
        println!("Error: attributes in ct do not match policy in sk.");
        return None;
    } else {
        let mut _prod_t = Gt::one();
        let mut _coeff: Vec<(String, bn::Fr)> = calc_coefficients_str(&sk._policy).unwrap();
        for _i in 0usize.._coeff.len() {
            if is_negative(&_coeff[_i].0) {
                //TODO !
                let mut _sum_e4 = G2::one();
                let mut _sum_e5 = G2::one();
                for _i in 0usize.._coeff.len() {}
                _prod_t = _prod_t *
                    (pairing(sk._d_i[_i].2, ct._e2) *
                         (pairing(sk._d_i[_i].3, _sum_e4) * pairing(sk._d_i[_i].4, _sum_e5))
                             .inverse())
                        .pow(_coeff[_i].1);
            } else {
                _prod_t = _prod_t *
                    (pairing(sk._d_i[_i].0, ct._e2) * pairing(ct._e3[_i], sk._d_i[_i].1).inverse())
                        .pow(_coeff[_i].1);
            }

        }
        let _msg = ct._e1 * _prod_t.inverse();
        // Decrypt plaintext using derived secret from cp-abe scheme
        return decrypt_symmetric(&_msg, &ct._ct);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /*
TODO: FIX MULTIPLE ATTRIBUTES !!!!
    #[test]
    fn test_kp_abe_and() {
        // setup scheme
        let (pk, msk) = kpabe_setup();
        // a set of two attributes matching the policy
        let mut att_matching: Vec<String> = Vec::new();
        att_matching.push(String::from("A"));
        att_matching.push(String::from("B"));
        att_matching.push(String::from("C"));

        // our plaintext
        let plaintext = String::from("dance like no one's watching, encrypt like everyone is!")
            .into_bytes();

        // our policy
        let policy = String::from(r#"{"OR": [{"ATT": "C"}, {"ATT": "B"}]}"#);
        //let policy = String::from(r#"{"ATT": "A"}"#);

        // kp-abe ciphertext
        let ct_kp_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_matching, &plaintext)
            .unwrap();

        // kp-abe ciphertext
        //let ct_kp_not_matching: KpAbeCiphertext = kpabe_encrypt(&pk, &att_not_matching, &plaintext)
        //    .unwrap();

        // a kp-abe SK key
        let sk: KpAbeSecretKey = kpabe_keygen(&pk, &msk, &policy).unwrap();

        // and now decrypt again with mathcing sk
        let _matching = kpabe_decrypt(&sk, &ct_kp_matching);
        match _matching {
            None => println!("KP-ABE: Cannot decrypt"),
            Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        }

        // and now decrypt again without matching sk
        //let _not_matching = kpabe_decrypt(&sk, &ct_kp_not_matching);
        //match _not_matching {
        //    None => println!("KP-ABE: Cannot decrypt"),
        //    Some(x) => println!("KP-ABE: Result: {}", String::from_utf8(x).unwrap()),
        //}
    }
*/

}
