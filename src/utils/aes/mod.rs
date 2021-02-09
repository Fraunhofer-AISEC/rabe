// use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
// use crypto::digest::Digest;
// use crypto::sha3::Sha3;
// use crypto::{aes, blockmodes, buffer, symmetriccipher};

use sha3::{Sha3_256, Digest};
use aes::Aes256;
use ccm::{self, aead::{NewAead, AeadInPlace}};
use ccm::aead::generic_array::GenericArray;

use rand::{Rng, thread_rng};
use std::convert::TryInto;
use RabeError;

/// Key Encapsulation Mechanism (Encryption Function)
pub fn encrypt_symmetric<T: std::fmt::Display>(_msg: &T, _plaintext: &Vec<u8>) -> Result<Vec<u8>, RabeError> {
    let mut rng = thread_rng();
    let key = kdf(_msg);
    let iv: [u8; 13] = rng.gen();

    //  key length 256 bit,  tag size 16 byte,  nonce size 13 bytes
    let ccm: ccm::Ccm<Aes256, ccm::consts::U16, ccm::consts::U13> = ccm::Ccm::new(&key);
    let mut res: Vec<u8> = _plaintext.clone();
    ccm.encrypt_in_place(&GenericArray::from(iv), &[], &mut res)?;
    res.splice(0..0, iv.iter().cloned()); // add IV at the beginning
    Ok(res)
}

/// Key Encapsulation Mechanism (Decryption Function)
pub fn decrypt_symmetric<T: std::fmt::Display>(_msg: &T, _iv_ct: &Vec<u8>) -> Result<Vec<u8>, RabeError> {
    let mut data = _iv_ct.clone().split_off(13);
    let iv: [u8; 13] = match _iv_ct[..13].try_into() {
        Ok(iv) => iv,
        Err(_) => return Err(RabeError{ details: String::from("Error extracting IV from ciphertext: Expected an IV of 13 bytes")}), // this REALLY shouldn't happen.
    };
    let key = kdf(_msg);

    let ccm: ccm::Ccm<Aes256, ccm::consts::U16, ccm::consts::U13> = ccm::Ccm::new(&key);
    ccm.decrypt_in_place(&GenericArray::from(iv), &[], &mut data)?;
    Ok(data)
}

/// Key derivation function - turns anything implementing the `Display` trait into a key for AES-256
fn kdf<G: std::fmt::Display>(inp: &G) -> GenericArray<u8, ccm::consts::U32> {
    let mut hasher = Sha3_256::new();
    hasher.update(inp.to_string().into_bytes());
    hasher.finalize()
}

#[cfg(tests)]
mod tests {
    use super::*;
    #[test]
    fn correctness_test() {
        let key = "7h15 15 4 v3ry 53cr37 k3y";
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!").into_bytes();
        let ciphertext = encrypt_symmetric(&key, &plaintext).unwrap();
        assert_eq!(decrypt_symmetric(&key, &ciphertext).unwrap(), plaintext);
    }
}