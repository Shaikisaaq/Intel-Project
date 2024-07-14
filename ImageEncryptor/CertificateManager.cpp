#include "CertificateManager.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <stdexcept>
#include <memory>

void CertificateManager::generateCertificate(const std::string& certFile, const std::string& keyFile) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        throw std::runtime_error("Failed to create EVP_PKEY");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to initialize keygen");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set RSA keygen bits");
    }

    EVP_PKEY* rsa_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &rsa_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to generate RSA key");
    }

    EVP_PKEY_CTX_free(ctx);

    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(rsa_pkey);
        throw std::runtime_error("Failed to create X509");
    }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, rsa_pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"ImageEncryptor", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"ImageEncryptor", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, rsa_pkey, EVP_sha256())) {
        EVP_PKEY_free(rsa_pkey);
        X509_free(x509);
        throw std::runtime_error("Failed to sign X509 certificate");
    }

    FILE* f = nullptr;
    if (fopen_s(&f, certFile.c_str(), "wb") != 0 || !f) {
        EVP_PKEY_free(rsa_pkey);
        X509_free(x509);
        throw std::runtime_error("Failed to open certificate file for writing");
    }

    PEM_write_X509(f, x509);
    fclose(f);

    if (fopen_s(&f, keyFile.c_str(), "wb") != 0 || !f) {
        EVP_PKEY_free(rsa_pkey);
        X509_free(x509);
        throw std::runtime_error("Failed to open key file for writing");
    }

    PEM_write_PrivateKey(f, rsa_pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    EVP_PKEY_free(rsa_pkey);
    X509_free(x509);
}
