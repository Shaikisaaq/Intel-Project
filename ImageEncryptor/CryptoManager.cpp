#include "CryptoManager.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdexcept>
#include <vector>
#include <random>
#include <iostream>
#include "CertificateManager.h"

// Function to generate a random AES key
std::string generateRandomKey(size_t length) {
    static const char charset[] = "0123456789abcdef";
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    std::string key;

    for (size_t i = 0; i < length; ++i) {
        key += charset[dist(rng)];
    }

    return key;
}

std::vector<unsigned char> CryptoManager::encrypt(const std::vector<unsigned char>& data) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string key = generateRandomKey(16); // Generate 16 bytes key for AES-128
    std::string iv = generateRandomKey(16);  // Generate 16 bytes IV for AES-128
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> encrypted(data.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    encrypted.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    //gentrating certificate
    std::string certFile = "C:/Users/isaaq/source/repos/ImageEncryptor/certificate.pem";
    std::string keyFile = "C:/Users/isaaq/source/repos/ImageEncryptor/private_key.pem";
    CertificateManager::generateCertificate(certFile, keyFile);
    std::cout << "Certificate generated successfully." << std::endl;

    std::cout << "Key: " << key << std::endl;
    std::cout << "IV: " << iv << std::endl;

    return encrypted;
}

std::vector<unsigned char> CryptoManager::decrypt(const std::vector<unsigned char>& data) {
    std::string key, iv;
    std::cout << "enter the key:";
    std::cin >> key;
    std::cout << "enter the iv:";
    std::cin >> iv;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> decrypted(data.size());
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;

    decrypted.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return decrypted;
}
