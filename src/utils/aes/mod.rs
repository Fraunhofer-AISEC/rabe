#[allow(dead_code)]

extern crate bn;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate crypto;

use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use rand::{Rng, thread_rng};
use bincode::serialize;

/// Key Encapsulation Mechanism (Encryption Function)
pub fn encrypt_symmetric(_msg: &bn::Gt, _plaintext: &Vec<u8>) -> Option<Vec<u8>> {
    let mut _key: [u8; 32] = [0; 32];
    let mut _iv: Vec<u8> = vec![0; 16];
    let mut _ret: Vec<u8> = Vec::new();
    let mut _sha = Sha3::sha3_256();
    let mut _rng = thread_rng();
    match serialize(&_msg) {
        Err(_) => return None,
        Ok(_serialized_msg) => {
            _sha.input(&_serialized_msg);
            _sha.result(&mut _key);
            _rng.fill_bytes(&mut _iv);
            _ret.append(&mut _iv.clone());
            let mut encrypted_data = encrypt_aes(&_plaintext, &_key, &_iv).ok().unwrap();
            _ret.append(&mut encrypted_data);
            return Some(_ret);
        }
    }
}
/// Key Encapsulation Mechanism (Decryption Function)
pub fn decrypt_symmetric(_msg: &bn::Gt, _iv_ct: &Vec<u8>) -> Option<Vec<u8>> {
    let mut _key: [u8; 32] = [0; 32];
    let mut _iv = _iv_ct.clone();
    let _data = _iv.split_off(16);
    let mut _sha = Sha3::sha3_256();
    let mut _rng = thread_rng();
    match serialize(&_msg) {
        Err(_) => return None,
        Ok(_serialized_msg) => {
            _sha.input(&_serialized_msg);
            _sha.result(&mut _key);
            let decrypted_data = decrypt_aes(&_data, &_key, &_iv).ok().unwrap();
            return Some(decrypted_data);
        }
    }
}


// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
fn encrypt_aes(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> ::std::result::Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {

    // Create an encryptor instance of the best performing
    // type available for the platform.
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

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
fn decrypt_aes(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> ::std::result::Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
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

    Ok(final_result)
}
