extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate bn;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate bincode;
extern crate rustc_serialize;
extern crate num_bigint;
extern crate blake2_rfc;

use std::string::String;


//////////////////////////////////////////////////////
// LSE KP-ABE structs
//////////////////////////////////////////////////////
#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbePublicKey {
    _g_g1: bn::G1,
    _g_g2: bn::G2,
    _g_g1_b: bn::G1,
    _g_g1_b2: bn::G1,
    _h_g1_b: bn::G1,
    _e_gg_alpha: bn::Gt,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbeMasterKey {
    _alpha1: bn::Fr,
    _alpha2: bn::Fr,
    _b: bn::Fr,
    _h_g1: bn::G1,
    _h_g2: bn::G2,
}

pub struct KpAbeSecretKey {
    _policy: String,
    _d_i: Vec<(bn::G1, bn::G2, bn::G1, bn::G1, bn::G1)>,
}

#[derive(RustcEncodable, RustcDecodable, PartialEq)]
pub struct KpAbeCiphertext {
    _attr: Vec<(String)>,
    _e1: bn::Gt,
    _e2: bn::G2,
    _e3: Vec<(bn::G1)>,
    _e4: Vec<(bn::G1)>,
    _e5: Vec<(bn::G1)>,
    _ct: Vec<u8>,
    _iv: [u8; 16],
}


/*

//////////////////////////////////////////
// LSW KP-ABE on type-3
//////////////////////////////////////////

// TODO : fix bug in coeff reconstruction

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
    // an msp policy from the given String
    let msp: AbePolicy = AbePolicy::from_string(&policy).unwrap();
    let _secret = msk._alpha1;
    let _shares = gen_shares_str(_secret, policy).unwrap();
    let mut _d: Vec<(bn::G1, bn::G2, bn::G1, bn::G1, bn::G1)> = Vec::new();
    let mut _d_i: (bn::G1, bn::G2, bn::G1, bn::G1, bn::G1) =
        (G1::zero(), G2::zero(), G1::zero(), G1::zero(), G1::zero());
    for _x in 0usize..msp._pi.len() {
        let _r = Fr::random(_rng);
        let mut _sum = Fr::zero();
        if is_negative(&msp._pi[_x]) {
            _d_i.2 = (pk._g_g1 * (msk._alpha2 * _shares[_x].1)) + (pk._g_g1_b2 * _r);
            _d_i.3 = pk._g_g1_b * (blake2b_hash_fr(&_shares[_x].0) * _r) + (msk._h_g1 * _r);
            _d_i.4 = pk._g_g1 * _r.neg();
        } else {
            _d_i.0 = (pk._g_g1 * (msk._alpha2 * _shares[_x].1)) +
                (blake2b_hash_g1(pk._g_g1, &_shares[_x].0) * _r);
            _d_i.1 = pk._g_g2 * _r;
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
    attributes: &Vec<String>,
    plaintext: &[u8],
) -> Option<KpAbeCiphertext> {
    if attributes.is_empty() || plaintext.is_empty() {
        return None;
    } else {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // e3,4,5 vectors
        let mut _e3: Vec<(bn::G1)> = Vec::new();
        let mut _e4: Vec<(bn::G1)> = Vec::new();
        let mut _e5: Vec<(bn::G1)> = Vec::new();
        // random message
        let _msg = Gt::one();
        println!("_pt: {:?}", into_dec(_msg).unwrap());
        // random secret
        let _s = Fr::random(_rng);
        // sx vector
        let mut _sx: Vec<(bn::Fr)> = Vec::new();
        _sx.push(_s);
        for _i in 0usize..attributes.len() {
            _sx.push(Fr::random(_rng));
            _sx[0] = _sx[0] - _sx[_i];
        }
        for _i in 0usize..attributes.len() {
            _e3.push(blake2b_hash_g1(pk._g_g1, &attributes[_i]) * _s);
            _e4.push(pk._g_g1_b * _sx[_i]);
            _e5.push(
                (pk._g_g1_b2 * (_sx[_i] * blake2b_hash_fr(&attributes[_i]))) +
                    (pk._h_g1_b * _sx[_i]),
            );
        }
        let _e1 = (pk._e_gg_alpha.pow(_s)) * _msg;
        let _e2 = pk._g_g2 * _s;
        //Encrypt plaintext using derived key from secret
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let mut iv: [u8; 16] = [0; 16];
                _rng.fill_bytes(&mut iv);
                let _ct = KpAbeCiphertext {
                    _attr: attributes.clone(),
                    _e1: _e1,
                    _e2: _e2,
                    _e3: _e3,
                    _e4: _e4,
                    _e5: _e5,
                    _ct: encrypt_aes(&plaintext, &key, &iv).ok().unwrap(),
                    _iv: iv,
                };
                return Some(_ct);
            }
        }
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
            let mut _z = Gt::one();
            if is_negative(&_coeff[_i].0) {
                let _sum_e4 = G2::zero();
                let _sum_e5 = G2::zero();

            //_z = pairing(sk._d_i[_i].2, ct._e2) *
            //    (pairing(sk._d_i[_i].3, _sum_e4) * pairing(sk._d_i[_i].4, _sum_e5)).inverse();
            } else {
                _z = pairing(sk._d_i[_i].0, ct._e2) * pairing(ct._e3[_i], sk._d_i[_i].1).inverse();
            }
            println!(
                "DEC_coeff[{:?}]: {:?}",
                _coeff[_i].0,
                into_dec(_coeff[_i].1).unwrap()
            );
            _prod_t = _prod_t * _z.pow(_coeff[_i].1);
        }
        let _msg = ct._e1 * _prod_t.inverse();
        println!("_pt: {:?}", into_dec(_msg).unwrap());
        // Decrypt plaintext using derived secret from cp-abe scheme
        let mut sha = Sha3::sha3_256();
        match encode(&_msg, Infinite) {
            Err(_) => return None,
            Ok(e) => {
                sha.input(e.to_hex().as_bytes());
                let mut key: [u8; 32] = [0; 32];
                sha.result(&mut key);
                let aes = decrypt_aes(&ct._ct[..], &key, &ct._iv).ok().unwrap();
                return Some(aes);
            }
        }
    }
}

*/
