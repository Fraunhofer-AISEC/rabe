extern crate bn;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate crypto;
extern crate blake2_rfc;
extern crate num_bigint;

use rustc_serialize::Encodable;
use num_bigint::{ToBigInt, BigInt};
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use blake2_rfc::blake2b::blake2b;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::encode;
use rustc_serialize::hex::ToHex;

pub fn is_negative(_attr: &String) -> bool {
    let first_char = &_attr[..1];
    return first_char == '!'.to_string();
}

pub fn calc_coefficients_str(_policy: &String) -> Option<Vec<(String, bn::Fr)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error in policy (could not parse as json): {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            let mut _coeff: Vec<(String, bn::Fr)> = Vec::new();
            calc_coefficients(&pol, &mut _coeff, bn::Fr::one());
            return Some(_coeff);
        }
    }
}

pub fn calc_coefficients(
    _json: &serde_json::Value,
    _coeff_vec: &mut Vec<(String, bn::Fr)>,
    _coeff: bn::Fr,
) {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
    } else {
        // leaf node
        if _json["ATT"] != serde_json::Value::Null {
            _coeff_vec.push((_json["ATT"].to_string(), _coeff));
        }
        // inner node
        else if _json["AND"].is_array() {
            let _this_coeff =
                recover_coefficients(vec![bn::Fr::one(), (bn::Fr::one() + bn::Fr::one())]);
            calc_coefficients(&_json["AND"][0], _coeff_vec, _coeff * _this_coeff[0]);
            calc_coefficients(&_json["AND"][1], _coeff_vec, _coeff * _this_coeff[1]);
        }
        // inner node
        else if _json["OR"].is_array() {
            let _this_coeff = recover_coefficients(vec![bn::Fr::one()]);
            calc_coefficients(&_json["OR"][0], _coeff_vec, _coeff * _this_coeff[0]);
            calc_coefficients(&_json["OR"][0], _coeff_vec, _coeff * _this_coeff[0]);
        }
    }
}

// lagrange interpolation
pub fn recover_coefficients(_list: Vec<bn::Fr>) -> Vec<bn::Fr> {
    let mut _coeff: Vec<bn::Fr> = Vec::new();
    for _i in _list.clone() {
        let mut _result = bn::Fr::one();
        for _j in _list.clone() {
            if _i != _j {
                _result = _result * ((bn::Fr::zero() - _j) * (_i - _j).inverse().unwrap());
            }
        }
        _coeff.push(_result);
    }
    return _coeff;
}

pub fn usize_to_fr(_i: usize) -> bn::Fr {
    let _i = _i.to_bigint().unwrap();
    return bn::Fr::from_str(&_i.to_str_radix(10)).unwrap();
}

pub fn gen_shares_str(_secret: bn::Fr, _policy: &String) -> Option<Vec<(String, bn::Fr)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            return gen_shares_json(_secret, &pol);
        }
    }
}

pub fn gen_shares_json(
    _secret: bn::Fr,
    _json: &serde_json::Value,
) -> Option<Vec<(String, bn::Fr)>> {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return None;
    } else {
        let mut _k = 0;
        let mut _type = "";
        let mut _result: Vec<(String, bn::Fr)> = Vec::new();
        // leaf node
        if _json["ATT"] != serde_json::Value::Null {
            match _json["ATT"].as_str() {
                Some(_s) => {
                    _result.push((_s.to_string(), _secret));
                    return Some(_result);
                }
                None => {
                    println!("ERROR attribute value");
                    return None;
                }
            }
        }
        // inner node
        else if _json["OR"].is_array() {
            _k = 1;
            _type = "OR";
        }
        // inner node
        else if _json["AND"].is_array() {
            _k = 2;
            _type = "AND";
        }
        let shares = gen_shares(_secret, _k, 2);
        let left = gen_shares_json(shares[0], &_json[_type][0]).unwrap();
        _result.extend(left);
        let right = gen_shares_json(shares[1], &_json[_type][1]).unwrap();
        _result.extend(right);
        return Some(_result);
    }
}

pub fn gen_shares(_secret: bn::Fr, _k: usize, _n: usize) -> Vec<bn::Fr> {
    let mut _shares: Vec<bn::Fr> = Vec::new();
    if _k <= _n {
        // random number generator
        let _rng = &mut rand::thread_rng();
        // polynomial coefficients
        let mut _a: Vec<bn::Fr> = Vec::new();
        for _i in 0.._k {
            if _i == 0 {
                _a.push(_secret);
            } else {
                _a.push(bn::Fr::random(_rng))
            }
        }
        for _i in 0..(_n + 1) {
            let _polynom = polynomial(_a.clone(), usize_to_fr(_i));
            _shares.push(_polynom);
        }
    }
    return _shares;
}

pub fn recover_secret(_shares: Vec<bn::Fr>, _policy: &String) -> bn::Fr {
    let _coeff = calc_coefficients_str(_policy).unwrap();
    let mut _secret = bn::Fr::zero();
    for _i in 0usize.._shares.len() {
        _secret = _secret + (_coeff[_i].1 * _shares[_i]);
    }
    return _secret;
}

pub fn polynomial(_coeff: Vec<bn::Fr>, _x: bn::Fr) -> bn::Fr {
    let mut _share = bn::Fr::zero();
    for _i in 0usize.._coeff.len() {
        _share = _share + (_coeff[_i] * _x.pow(usize_to_fr(_i)));
    }
    return _share;
}


pub fn traverse_str(_attr: &Vec<(String)>, _policy: &String) -> bool {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return false;
        }
        Ok(pol) => {
            return traverse_json(_attr, &pol);
        }
    }
}
// used to traverse / check policy tree
pub fn traverse_json(_attr: &Vec<(String)>, _json: &serde_json::Value) -> bool {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
        return false;
    }
    if _attr.len() == 0 {
        println!("Error: No attributes in List!");
        return false;
    }
    // inner node or
    if _json["OR"].is_array() {
        let _num_terms = _json["OR"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = false;
            for _i in 0usize.._num_terms {
                ret = ret || traverse_json(_attr, &_json["OR"][_i]);
            }
            return ret;
        } else {
            println!("Error: Invalid policy (OR with just a single child).");
            return false;
        }
    }
    // inner node and
    else if _json["AND"].is_array() {
        let _num_terms = _json["AND"].as_array().unwrap().len();
        if _num_terms >= 2 {
            let mut ret = true;
            for _i in 0usize.._num_terms {
                ret = ret && traverse_json(_attr, &_json["AND"][_i]);
            }
            return ret;
        } else {
            println!("Error: Invalid policy (AND with just a single child).");
            return false;
        }
    }
    // leaf node
    else if _json["ATT"] != serde_json::Value::Null {
        match _json["ATT"].as_str() {
            Some(s) => {
                // check if ATT in _attr list
                return (&_attr).into_iter().any(|v| v == &s);
            }
            None => {
                println!("Error: in attribute String");
                return false;
            }
        }
    }
    // error
    else {
        println!("Error: Policy invalid. No AND or OR found");
        return false;
    }
}

/////////////////////////////////////////////////////////////////////
// HASH TO GROUP FUNTIONS
/////////////////////////////////////////////////////////////////////

// used to hash to G1
pub fn blake2b_hash_g1(g: bn::G1, data: &String) -> bn::G1 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * bn::Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to G2
pub fn blake2b_hash_g2(g: bn::G2, data: &String) -> bn::G2 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * bn::Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to Fr
pub fn blake2b_hash_fr(data: &String) -> bn::Fr {
    let hash = blake2b(64, &[], data.as_bytes());
    return bn::Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// Helper functions from here on used by CP and KP
pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| e.to_hex())
}

pub fn into_dec<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| {
        BigInt::parse_bytes(e.to_hex().as_bytes(), 16)
            .unwrap()
            .to_str_radix(10)
    })
}

pub fn combine_two_strings(text: &String, j: usize) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    return _combined.to_string();
}

pub fn combine_three_strings(text: &String, j: usize, t: usize) -> String {
    let mut _combined: String = text.to_owned();
    _combined.push_str(&j.to_string());
    _combined.push_str(&t.to_string());
    return _combined.to_string();
}


// AES functions from here on

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
pub fn decrypt_aes(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    return Ok(final_result);
}

pub fn encrypt_aes(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
