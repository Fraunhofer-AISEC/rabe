#[allow(dead_code)]

extern crate bn;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate crypto;
extern crate blake2_rfc;
extern crate num_bigint;

use rustc_serialize::{Encodable, Decodable};
use num_bigint::{ToBigInt, BigInt};
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use blake2_rfc::blake2b::blake2b;
use bincode::SizeLimit::Infinite;
use bincode::rustc_serialize::{encode, decode};
use rustc_serialize::hex::{FromHex, ToHex};
use bn::*;
use std::collections::HashSet;
use aw11::{Aw11PublicKey, Aw11MasterKey, Aw11SecretKey, Aw11Ciphertext};
use mke08::Mke08SecretAttributeKey;

pub fn is_negative(_attr: &String) -> bool {
    let first_char = &_attr[..1];
    return first_char == '!'.to_string();
}

pub fn usize_to_fr(_i: usize) -> Fr {
    let _i = _i.to_bigint().unwrap();
    return Fr::from_str(&_i.to_str_radix(10)).unwrap();
}

pub fn get_attribute_list(_policy: &String) -> Option<Vec<(String)>> {
    match serde_json::from_str(_policy) {
        Err(_) => {
            println!("Error parsing policy {:?}", _policy);
            return None;
        }
        Ok(pol) => {
            let mut _list: Vec<(String)> = Vec::new();
            get_attribute_list_json(&pol, &mut _list);
            return Some(_list);
        }
    }
}

pub fn get_attribute_list_json(_json: &serde_json::Value, _list: &mut Vec<(String)>) {
    if *_json == serde_json::Value::Null {
        println!("Error: passed null as json!");
    }
    // leaf node
    if _json["ATT"] != serde_json::Value::Null {
        match _json["ATT"].as_str() {
            Some(_s) => {
                _list.push(String::from(_s));
            }
            None => {
                println!("Error: in attribute String");
            }
        }
    }
    // inner node
    else if _json["OR"].is_array() {
        let _num_terms = _json["OR"].as_array().unwrap().len();
        if _num_terms >= 2 {
            for _i in 0usize.._num_terms {
                get_attribute_list_json(&_json["OR"][_i], _list);
            }
        } else {
            println!("Error: Invalid policy (OR with just a single child).");
        }
    }
    // inner node
    else if _json["AND"].is_array() {
        let _num_terms = _json["AND"].as_array().unwrap().len();
        if _num_terms >= 2 {
            for _i in 0usize.._num_terms {
                get_attribute_list_json(&_json["AND"][_i], _list);
            }
        } else {
            println!("Error: Invalid policy (AND with just a single child).");
        }
    }
    // error
    else {
        println!("Error: Policy invalid. No AND or OR found");
    }
}

pub fn traverse_str(_attr: &Vec<String>, _policy: &String) -> bool {
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

pub fn is_satisfiable(_conjunction: &Vec<String>, _sk: &Vec<Mke08SecretAttributeKey>) -> bool {
    let mut ret = true;
    for _attr in _conjunction {
        match _sk.into_iter().find(|&x| x._str == *_attr) {
            None => {
                ret &= false;
            }
            Some(_attr_sk) => {
                ret &= true;
            }
        }
    }
    ret
}

pub fn calc_satisfiable(
    _conjunction: &Vec<String>,
    _sk: &Vec<Mke08SecretAttributeKey>,
) -> (bn::G1, bn::G2) {
    let mut ret: (bn::G1, bn::G2) = (G1::one(), G2::one());
    for _attr in _conjunction {
        match _sk.into_iter().find(|&x| x._str == *_attr) {
            None => {}
            Some(_attr_sk) => {
                ret = (ret.0 + _attr_sk._g1, ret.1 + _attr_sk._g2);
            }
        }
    }
    ret
}

pub fn flatten_mke08(_sk_a: &Vec<Mke08SecretAttributeKey>) -> Vec<String> {
    let mut tmp: Vec<(String)> = Vec::new();
    for _term in _sk_a.iter() {
        tmp.push(_term._str.to_string());
    }
    tmp
}

pub fn flatten(data: &Vec<(String, bn::G1, bn::G2)>) -> Vec<String> {
    data.iter()
        .map(|triple| {
            let (_s, _g1, _g2) = triple.clone();
            _s
        })
        .collect::<Vec<_>>()
}

pub fn contains(data: &Vec<(String)>, value: &String) -> bool {
    let len = data.into_iter()
        .filter(|&i| i == value)
        .collect::<Vec<_>>()
        .len();
    return len >= 1;
}

// used to check if a set of attributes is a subset of another
pub fn is_subset(_subset: &Vec<String>, _attr: &Vec<String>) -> bool {
    let super_set: HashSet<_> = _attr.iter().cloned().collect();
    let sub_set: HashSet<_> = _subset.iter().cloned().collect();
    return sub_set.is_subset(&super_set);
}

// used to traverse / check policy tree
pub fn traverse_json(_attr: &Vec<String>, _json: &serde_json::Value) -> bool {
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
                return (&_attr).into_iter().any(|x| x == s);
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

// AW11 Scheme functions

pub fn aw11_attr_from_pk(_pk: &Aw11PublicKey, _a: &String) -> Option<(String, usize)> {
    for (_i, _attr) in _pk._attr.iter().enumerate() {
        if _attr.0 == _a.to_string() {
            return Some((_attr.0.clone(), _i));
        }
    }
    return None;
}

pub fn aw11_attr_from_msk(_sk: &Aw11MasterKey, _a: &String) -> Option<(String, usize)> {
    for (_i, _attr) in _sk._attr.iter().enumerate() {
        if _attr.0 == _a.to_string() {
            return Some((_attr.0.clone(), _i));
        }
    }
    return None;
}

pub fn aw11_attr_from_sk(_sk: &Aw11SecretKey, _a: &String) -> Option<(String, G1, G2)> {
    for (_i, _attr) in _sk._attr.iter().enumerate() {
        if _attr.0 == _a.to_string() {
            return Some((_attr.clone()));
        }
    }
    return None;
}

pub fn aw11_attr_from_ct(
    _ct: &Aw11Ciphertext,
    _a: &String,
) -> Option<(String, Gt, G1, G1, G2, G2)> {
    for (_i, _attr) in _ct._c.iter().enumerate() {
        if _attr.0 == _a.to_string() {
            return Some((_attr.clone()));
        }
    }
    return None;
}



pub fn aw11_get_coefficient(_a: &String, _coeffs: &Vec<(String, Fr)>) -> Option<Fr> {
    for (_i, _attr) in _coeffs.iter().enumerate() {
        if _attr.0 == _a.to_string() {
            return Some((_attr.clone().1));
        }
    }
    return None;
}

// MSK08 functions
pub fn from_authority(_attr: &String, _authority: &String) -> bool {
    let split = _attr.split(":");
    let vec: Vec<&str> = split.collect();
    if vec[0] == _attr {
        return true;
    }
    return false;
}

pub fn is_eligible(_attr: &String, _user: &String) -> bool {
    // TODO !!!!
    // Implement some logic to determine which user is able to own which attribute
    return true;
}




/////////////////////////////////////////////////////////////////////
// HASH TO GROUP FUNTIONS
/////////////////////////////////////////////////////////////////////

// used to hash to G1
pub fn blake2b_hash_g1(g: bn::G1, data: &String) -> bn::G1 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to G2
pub fn blake2b_hash_g2(g: bn::G2, data: &String) -> bn::G2 {
    let hash = blake2b(64, &[], data.as_bytes());
    return g * Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// used to hash to Fr
pub fn blake2b_hash_fr(data: &String) -> Fr {
    let hash = blake2b(64, &[], data.as_bytes());
    return Fr::interpret(array_ref![hash.as_ref(), 0, 64]);
}

// Helper functions from here on used by CP and KP
pub fn into_hex<S: Encodable>(obj: S) -> Option<String> {
    encode(&obj, Infinite).ok().map(|e| e.to_hex())
}

pub fn from_hex<S: Decodable>(s: &str) -> Option<S> {
    let s = s.from_hex().unwrap();

    decode(&s).ok()
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
