#pragma once

#ifndef __faasm
#include <cstddef>
#include <cstdint>
#endif
#include <vector>

extern "C" {
void aes256gcm_encrypt(const uint8_t* keyPtr,
                       size_t keySize,
                       const uint8_t* noncePtr,
                       size_t nonceSize,
                       const uint8_t* plainTextPtr,
                       size_t plainTextSize,
                       uint8_t* cipherTextPtr,
                       size_t cipherTextSize);

void aes256gcm_decrypt(const uint8_t* keyPtr,
                       size_t keySize,
                       const uint8_t* noncePtr,
                       size_t nonceSize,
                       const uint8_t* cipherTextPtr,
                       size_t cipherTextSize,
                       uint8_t* plainTextPtr,
                       size_t plainTextSize);
}

namespace tless::aes256gcm {
std::vector<uint8_t> encrypt(std::vector<uint8_t> key, std::vector<uint8_t> nonce, std::vector<uint8_t> plainText);

std::vector<uint8_t> decrypt(std::vector<uint8_t> key, std::vector<uint8_t> nonce, std::vector<uint8_t> cipherText);
}
