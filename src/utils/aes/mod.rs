use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead};

use crate::error::RabeError;
use std::convert::TryInto;
use rand::thread_rng;
use rand::Rng;

/// Key Encapsulation Mechanism (AES-256 Encryption Function)
pub fn encrypt_symmetric<G: std::convert::Into<Vec<u8>>>(_msg: G, _plaintext: &Vec<u8>) -> Result<Vec<u8>, RabeError> {
    let mut rng = thread_rng();
    // 256bit key hashed/derived from _msg G
    let kdf = kdf(_msg);
    let key = Key::from_slice(kdf.as_slice());
    let cipher = Aes256Gcm::new(key);
    // 96bit random noise
    let nonce_vec: Vec<u8> = (0..12).into_iter().map(|_| rng.gen()).collect(); // 12*u8 = 96 Bit
    let nonce = Nonce::from_slice(nonce_vec.as_ref());
    match cipher.encrypt(nonce, _plaintext.as_ref()) {
        Ok(mut ct) => {
            ct.splice(0..0, nonce.iter().cloned()); // first 12 bytes are nonce i.e. [nonce|ciphertext]
            Ok(ct)
        }
        Err(e) => Err(RabeError::new(&format!("encryption error: {:?}", e.to_string())))
    }
}

/// Key Encapsulation Mechanism (AES-256 Decryption Function)
pub fn decrypt_symmetric<G: std::convert::Into<Vec<u8>>>(_msg: G, _nonce_ct: &Vec<u8>) -> Result<Vec<u8>, RabeError> {
    let ciphertext = _nonce_ct.clone().split_off(12); // 12*u8 = 96 Bit
    let nonce_vec: [u8; 12] = match _nonce_ct[..12].try_into() { // first 12 bytes are nonce i.e. [nonce|ciphertext]
        Ok(iv) => iv,
        Err(_) => return Err(RabeError::new("Error extracting IV from ciphertext: Expected an IV of 16 bytes")), // this REALLY shouldn't happen.
    };
    // 256bit key hashed/derived from _msg G
    let kdf = kdf(_msg);
    let key = Key::from_slice(kdf.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_vec.as_ref());
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(data) => Ok(data),
        Err(e) => Err(RabeError::new(&format!("decryption error: {:?}", e.to_string())))
    }
}

/// Key derivation function - turns anything implementing the `Into<Vec<u8>` trait into a key for AES-256
fn kdf<T: std::convert::Into<Vec<u8>>>(data: T) -> Vec<u8> {
    use sha3::{
        Digest,
        Sha3_256
    };
    let mut hasher = Sha3_256::new();
    hasher.update(data.into());
    hasher.finalize().to_vec()
}

mod tests {

    #[test]
    fn correctness_test1() {
        use crate::utils::aes::{encrypt_symmetric, decrypt_symmetric};
        let key = "7h15 15 4 v3ry 53cr37 k3ysdfsfsdfsdfdsfdsf1";
        let plaintext =
            String::from("dance like no one's watching, encrypt like everyone is!");
        let ciphertext = encrypt_symmetric(key, &plaintext.clone().into_bytes()).unwrap();
        let reconstruct = decrypt_symmetric(key, &ciphertext).unwrap();
        assert_eq!(plaintext.into_bytes(), reconstruct);
    }
}
