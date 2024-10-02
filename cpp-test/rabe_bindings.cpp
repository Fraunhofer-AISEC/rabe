#include "test.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

// API
// encrypt
// decrypt
// keyGen

namespace tless {
static std::string join(const std::vector<std::string>& vec, const std::string& delimiter) {
    std::ostringstream result;
    for (size_t i = 0; i < vec.size(); ++i) {
        result << vec[i];

        if (i != vec.size() - 1) {
            result << delimiter;
        }

    }
    return result.str();
}

void CpAbeContextWrapper::createKeys()
{
    // Create the context
    this->_ctx = rabe_bsw_context_create();
}

// TODO: make this fetch from the internet instead
bool CpAbeContextWrapper::fetchKeys()
{
    std::ifstream inputFile("/tmp/context", std::ios::binary | std::ios::ate);

    if (!inputFile) {
        std::cerr << "Failed to open file!" << std::endl;
        return false;
    }

    auto fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

    uint8_t* buffer = (uint8_t*) malloc(fileSize);
    if (!inputFile.read(reinterpret_cast<char*>(buffer), fileSize)) {
        std::cerr << "Failed to read file!" << std::endl;
        free(buffer);
        return false;
    }

    _ctx = (CpAbeContext*) buffer;
    this->externalContext = true;

    return true;
}

std::vector<uint8_t> CpAbeContextWrapper::cpAbeEncrypt(
    const std::string& policy,
    const std::string& plainText)
{
    std::vector<uint8_t> vec(plainText.begin(), plainText.end());
    return this->cpAbeEncrypt(policy, vec);
}

std::vector<uint8_t> CpAbeContextWrapper::cpAbeEncrypt(
    const std::string& policy,
    const std::vector<uint8_t>& plainText)
{
    BufferFfi* cipherText = nullptr;
    int ret = rabe_bsw_encrypt(this->_ctx,
                               policy.c_str(),
                               this->policyLanguage.c_str(),
                               plainText.data(),
                               plainText.size(),
                               &cipherText);

    if (ret != 0 || cipherText == nullptr) {
        if (cipherText != nullptr) {
            rabe_bsw_free_buffer_ffi(cipherText);
        }

        std::cerr << "Encryption failed!" << std::endl;
        return std::vector<uint8_t>();
    }

    // Return the cipher-text in a new object that the C++ code controls, and
    // free the heap-allocated Rust object. Also, make sure our vector is
    // null-terminated as we will need it to re-parse it for decryption
    std::vector<uint8_t> cipherTextVec(cipherText->size);
    std::memcpy(cipherTextVec.data(), cipherText->data, cipherTextVec.size());
    cipherTextVec.push_back('\0');
    rabe_bsw_free_buffer_ffi(cipherText);

    return cipherTextVec;
}

std::vector<uint8_t> CpAbeContextWrapper::cpAbeDecrypt(
    const std::vector<std::string>& attributes,
    const std::vector<uint8_t>& cipherText)
{
    // In general, we throw away these keys. We could consider caching them
    // for better performance
    CpAbeSecretKey* secretKey = nullptr;
    auto joinedAttributes = join(attributes, ",");
    secretKey = rabe_bsw_keygen(this->_ctx, joinedAttributes.c_str());

    if (secretKey == nullptr) {
        std::cerr << "Key generation for decryption failed!" << std::endl;
        return std::vector<uint8_t>();
    }

    // Decrypt ciphertext
    BufferFfi* plainText = nullptr;
    int ret = rabe_bsw_decrypt(secretKey, cipherText.data(), cipherText.size(), &plainText);
    if (ret != 0 || plainText == nullptr) {
        if (plainText != nullptr) {
            std::cerr << "here?" << std::endl;
            rabe_bsw_free_buffer_ffi(plainText);
        }

        rabe_bsw_keygen_destroy(secretKey);

        std::cerr << "Decryption failed! Cipher size: " << cipherText.size() << std::endl;
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> plainTextVec(plainText->size);
    memcpy(plainTextVec.data(), plainText->data, plainText->size);

    rabe_bsw_free_buffer_ffi(plainText);
    rabe_bsw_keygen_destroy(secretKey);

    return plainTextVec;
}
}

int main()
{
    // TODO: try get by calling setup instead of file
    auto& ctx = tless::CpAbeContextWrapper::get();

    // Prepare encryption
    std::string plainText = "dance like no one's watching, encrypt like everyone is!";
    std::string policy = "\"A\" and \"B\"";
    auto cipherText = ctx.cpAbeEncrypt(policy, plainText);

    // Prepare decryption
    std::vector<std::string> attributes = {"A", "B"};
    auto actualPlainText = ctx.cpAbeDecrypt(attributes, cipherText);

    // Compare
    std::string actualPlainTextStr;
    actualPlainTextStr.assign(reinterpret_cast<char*>(actualPlainText.data()), actualPlainText.size());
    if (plainText != actualPlainTextStr) {
        std::cerr << "Encryption/decryption test failed!" << std::endl;
        return -1;
    }

    std::cout << "Encryption worked!" << std::endl;
    return 0;
}

/*
int main()
{
    // Create the context
    CpAbeContext* ctx = rabe_bsw_context_create();

    if (ctx == nullptr) {
        std::cerr << "Failed to create context!" << std::endl;
        return -1;
    }

    std::string plainText = "dance like no one's watching, encrypt like everyone is!";
    std::string policy = "\"A\" and \"B\"";
    std::string policyLanguage = "HumanPolicy";

    BufferFfi* cipherText = nullptr;
    int ret = rabe_bsw_encrypt(ctx,
                               policy.c_str(),
                               policyLanguage.c_str(),
                               reinterpret_cast<const uint8_t*>(plainText.c_str()),
                               plainText.size(),
                               &cipherText);
    if (ret != 0 || cipherText == nullptr) {
        std::cerr << "Falied to encrypt cipher text!" << std::endl;
        return -1;
    }

    std::cout << "Managed to encrypt cipher text!" << std::endl;

    // Comma-separated list of attributes to generate our decryption key
    std::string attributes = "A,B";
    CpAbeSecretKey* secretKey = nullptr;
    secretKey = rabe_bsw_keygen(ctx, attributes.c_str());

    if (secretKey == nullptr) {
        std::cerr << "Failed to generate decryption key" << std::endl;
    }
    std::cout << "Managed to generate decryption key" << std::endl;

    // Decrypt ciphertext
    BufferFfi* actualPlainText = nullptr;
    ret = rabe_bsw_decrypt(secretKey, cipherText->data, cipherText->size, &actualPlainText);
    if (ret != 0 || actualPlainText == nullptr) {
        std::cerr << "Failed to decrypt cipher text" << std::endl;
    }

    std::cout << "Plain Text Size: " << plainText.size() << std::endl;
    std::cout << "Actual Plain Text Size: " << actualPlainText->size << std::endl;

    std::string actualPlainTextStr;
    actualPlainTextStr.assign(reinterpret_cast<char*>(actualPlainText->data), actualPlainText->size);

    std::cout << "Plain Text: " << plainText << std::endl;
    std::cout << "Actual Plain Text: " << actualPlainTextStr << std::endl;

    if (actualPlainTextStr == plainText) {
        std::cout << "Decryption succeeded!!! YAS" << std::endl;
    }

    // Destroy the secret key
    rabe_bsw_keygen_destroy(secretKey);

    // Clean-up buffers
    std::cout << "Cipher size: " << cipherText->size << std::endl;
    rabe_bsw_free_buffer_ffi(cipherText);
    std::cout << "Managed to free cipher-text" << std::endl;

    rabe_bsw_free_buffer_ffi(actualPlainText);
    std::cout << "Managed to free plain-text" << std::endl;

    // Destroy the context
    rabe_bsw_context_destroy(ctx);

    return 0;
}
*/
