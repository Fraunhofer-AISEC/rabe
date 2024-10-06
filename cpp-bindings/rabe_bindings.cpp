#include "rabe_bindings.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

namespace tless::abe {
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
bool CpAbeContextWrapper::fetchKeys(const ContextFetchMode& fetchMode)
{
    if (fetchMode == ContextFetchMode::FromTmpFile) {
        // WARNING: we are using an INSECURE test context here
        std::ifstream inputFile("./test_context.data", std::ios::binary | std::ios::ate);

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
    }

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
    int ret = rabe_bsw_decrypt(secretKey, cipherText.data(), &plainText);
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

/*
int main()
{
    auto& ctx = tless::abe::CpAbeContextWrapper::get(tless::abe::ContextFetchMode::Create);

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
*/
