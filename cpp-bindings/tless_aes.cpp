#include "tless_aes.h"

#define NONCE_SIZE 12
#define AUTH_SIZE 16

namespace tless::aes256gcm {
std::vector<uint8_t> encrypt(std::vector<uint8_t> key,
                             std::vector<uint8_t> nonce,
                             std::vector<uint8_t> plainText)
{
    size_t cipherTextSize = AUTH_SIZE + NONCE_SIZE + plainText.size();
    std::vector<uint8_t> cipherText(cipherTextSize);

    aes256gcm_encrypt(
        key.data(),
        key.size(),
        nonce.data(),
        nonce.size(),
        plainText.data(),
        plainText.size(),
        cipherText.data(),
        cipherText.size());

    return cipherText;
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> key,
                             std::vector<uint8_t> nonce,
                             std::vector<uint8_t> cipherText)
{
    size_t plainTextSize = cipherText.size() - AUTH_SIZE - NONCE_SIZE;
    std::vector<uint8_t> plainText(plainTextSize);

    aes256gcm_decrypt(
        key.data(),
        key.size(),
        nonce.data(),
        nonce.size(),
        cipherText.data(),
        cipherText.size(),
        plainText.data(),
        plainText.size());

    return plainText;
}
}
