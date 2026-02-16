/*
 * certificates_ffi.cpp
 *
 * Implementation of certificate loading and management FFI functions.
 */

#define GLOG_USE_GLOG_EXPORT

// Include bridge first to get rust:: types
#include "fizz_rs/src/bridge.rs.h"
#include "ffi/certificates_ffi.h"
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/protocol/Certificate.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <folly/ssl/OpenSSLPtrTypes.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

// Helper function to convert PEM string to EVP_PKEY
static folly::ssl::EvpPkeyUniquePtr pemToKey(const std::string& pem) {
    folly::ssl::BioUniquePtr bio(BIO_new_mem_buf(pem.data(), pem.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        throw std::runtime_error("Failed to read private key from PEM");
    }

    return folly::ssl::EvpPkeyUniquePtr(key);
}

// Helper function to convert EVP_PKEY to PEM string
static std::string keyToPem(EVP_PKEY* key) {
    folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO");
    }

    if (PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

// Helper function to convert PEM string to X509
static folly::ssl::X509UniquePtr pemToCert(const std::string& pem) {
    folly::ssl::BioUniquePtr bio(BIO_new_mem_buf(pem.data(), pem.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for certificate");
    }

    X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
        throw std::runtime_error("Failed to read certificate from PEM");
    }

    return folly::ssl::X509UniquePtr(cert);
}

// Helper function to convert X509 to PEM string
static std::string certToPem(X509* cert) {
    folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO");
    }

    if (PEM_write_bio_X509(bio.get(), cert) != 1) {
        throw std::runtime_error("Failed to write certificate to BIO");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

// Helper function to read file contents
static std::string readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + path);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Helper to convert public key to DER hex string
static std::string publicKeyToDerHex(EVP_PKEY* key) {
    unsigned char* derBuf = nullptr;
    int derLen = i2d_PUBKEY(key, &derBuf);
    if (derLen < 0) {
        throw std::runtime_error("Failed to encode public key to DER");
    }

    std::stringstream ss;
    for (int i = 0; i < derLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(derBuf[i]);
    }

    OPENSSL_free(derBuf);
    return ss.str();
}

// ============================================================================
// Certificate Loading Functions
// ============================================================================

CertificateData load_certificate_from_pem(rust::Str cert_pem, rust::Str key_pem) {
    try {
        std::string cert_str(cert_pem.data(), cert_pem.size());
        std::string key_str(key_pem.data(), key_pem.size());

        // Parse certificate and key
        auto cert = pemToCert(cert_str);
        auto key = pemToKey(key_str);

        // Get signature schemes
        auto keyType = fizz::openssl::CertUtils::getKeyType(key);
        auto sigSchemes = fizz::openssl::CertUtils::getSigSchemes(keyType);

        rust::Vec<uint16_t> schemes;
        for (const auto& scheme : sigSchemes) {
            schemes.push_back(static_cast<uint16_t>(scheme));
        }

        CertificateData data;
        data.cert_pem = std::move(cert_str);
        data.key_pem = std::move(key_str);
        data.sig_schemes = std::move(schemes);

        return data;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load certificate from PEM: " + std::string(e.what()));
    }
}

CertificateData load_certificate_from_file(rust::Str cert_path, rust::Str key_path) {
    try {
        std::string cert_path_str(cert_path.data(), cert_path.size());
        std::string key_path_str(key_path.data(), key_path.size());

        std::string cert_pem = readFile(cert_path_str);
        std::string key_pem = readFile(key_path_str);

        return load_certificate_from_pem(
            rust::Str(cert_pem.data(), cert_pem.size()),
            rust::Str(key_pem.data(), key_pem.size()));
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load certificate from files: " + std::string(e.what()));
    }
}

rust::Vec<uint16_t> get_certificate_sig_schemes(const CertificateData& cert_data) {
    return cert_data.sig_schemes;
}

rust::String certificate_to_pem(const CertificateData& cert_data) {
    return rust::String(cert_data.cert_pem);
}

// ============================================================================
// Certificate-Only Loading Functions (No Private Key)
// ============================================================================

CertificatePublic load_certificate_public_from_pem(rust::Str cert_pem) {
    try {
        std::string cert_str(cert_pem.data(), cert_pem.size());

        // Parse certificate only
        auto cert = pemToCert(cert_str);

        // Extract the public key from the certificate to determine key type
        auto pubkey = X509_get_pubkey(cert.get());
        if (!pubkey) {
            throw std::runtime_error("Failed to extract public key from certificate");
        }

        auto keyType = fizz::openssl::CertUtils::getKeyType(
            folly::ssl::EvpPkeyUniquePtr(pubkey));
        auto sigSchemes = fizz::openssl::CertUtils::getSigSchemes(keyType);

        rust::Vec<uint16_t> schemes;
        for (const auto& scheme : sigSchemes) {
            schemes.push_back(static_cast<uint16_t>(scheme));
        }

        CertificatePublic data;
        data.cert_pem = std::move(cert_str);
        data.sig_schemes = std::move(schemes);

        return data;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load certificate from PEM: " + std::string(e.what()));
    }
}

CertificatePublic load_certificate_public_from_file(rust::Str cert_path) {
    try {
        std::string cert_path_str(cert_path.data(), cert_path.size());
        std::string cert_pem = readFile(cert_path_str);

        return load_certificate_public_from_pem(
            rust::Str(cert_pem.data(), cert_pem.size()));
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load certificate from file: " + std::string(e.what()));
    }
}

// ============================================================================
// Private Key Operations
// ============================================================================

std::unique_ptr<FizzPrivateKey> load_private_key_from_pem(rust::Str key_pem) {
    try {
        std::string key_str(key_pem.data(), key_pem.size());
        auto key = pemToKey(key_str);

        auto fizzKey = std::make_unique<FizzPrivateKey>();
        fizzKey->key = std::move(key);
        return fizzKey;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load private key from PEM: " + std::string(e.what()));
    }
}

std::unique_ptr<FizzPrivateKey> generate_ec_p256_keypair() {
    try {
        // Generate EC P-256 key
        folly::ssl::EvpPkeyCtxUniquePtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            throw std::runtime_error("Failed to initialize keygen");
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
            throw std::runtime_error("Failed to set curve to P-256");
        }

        EVP_PKEY* key = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &key) <= 0) {
            throw std::runtime_error("Failed to generate EC key");
        }

        auto fizzKey = std::make_unique<FizzPrivateKey>();
        fizzKey->key = folly::ssl::EvpPkeyUniquePtr(key);
        return fizzKey;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to generate EC P-256 keypair: " + std::string(e.what()));
    }
}

rust::String private_key_to_pem(const FizzPrivateKey& key) {
    try {
        std::string pem = keyToPem(key.key.get());
        return rust::String(pem);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to convert private key to PEM: " + std::string(e.what()));
    }
}

rust::String get_public_key_der(const FizzPrivateKey& key) {
    try {
        std::string der = publicKeyToDerHex(key.key.get());
        return rust::String(der);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to get public key DER: " + std::string(e.what()));
    }
}
