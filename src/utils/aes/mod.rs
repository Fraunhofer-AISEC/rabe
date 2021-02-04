use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use rand::{RngCore, thread_rng};
use RabeError;

/// Key Encapsulation Mechanism (Encryption Function)
pub fn encrypt_symmetric<T: std::fmt::Display>(_msg: &T, _plaintext: &Vec<u8>) -> Result<Vec<u8>, RabeError> {
    let mut _key: [u8; 32] = [0; 32];
    let mut _iv: Vec<u8> = vec![0; 16];
    let mut _ret: Vec<u8> = Vec::new();
    let mut _rng = thread_rng();
    let vec: Vec<u8> = _msg.to_string().into_bytes();
    //println!("aes key: {:?}", vec.to_ascii_lowercase());
    let mut _sha = Sha3::sha3_256();
    _sha.input(&vec);
    let key = _sha.result_str();
    //println!("sha key: {:?}", key);
    _rng.fill_bytes(&mut _iv);
    _ret.append(&mut _iv.clone());
    _ret.append(&mut encrypt_aes(&_plaintext, &key.into_bytes(), &_iv).ok().unwrap());
    return Ok(_ret);
}
/// Key Encapsulation Mechanism (Decryption Function)
pub fn decrypt_symmetric<T: std::fmt::Display>(_msg: &T, _iv_ct: &Vec<u8>) -> Result<Vec<u8>, RabeError> {
    let mut _key: [u8; 32] = [0; 32];
    let mut _iv = _iv_ct.clone();
    let _data = _iv.split_off(16);
    let vec: Vec<u8> = _msg.to_string().into_bytes();
    //println!("aes key: {:?}", vec.to_ascii_lowercase());
    let mut _sha = Sha3::sha3_256();
    _sha.input(&vec);
    let key = _sha.result_str();
    //println!("sha key: {:?}", key);
    return decrypt_aes(&_data, &key.into_bytes(), &_iv);
}

/// Decrypts a buffer with the given key and iv using AES-256/CBC/Pkcs encryption.
///
/// This function is very similar to encrypt(), so, please reference
/// comments in that function. In non-example code, if desired, it is possible to
/// share much of the implementation using closures to hide the operation
/// being performed. However, such code would make this example less clear.
/// Encrypt a buffer with the given key and iv using
/// AES-256/CBC/Pkcs encryption.
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
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

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

/// Decrypts a buffer with the given key and iv using AES-256/CBC/Pkcs encryption.
///
/// This function is very similar to encrypt(), so, please reference
/// comments in that function. In non-example code, if desired, it is possible to
/// share much of the implementation using closures to hide the operation
/// being performed. However, such code would make this example less clear.
fn decrypt_aes(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> ::std::result::Result<Vec<u8>, RabeError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
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
