/*
 * CredentialManager.cpp
 *
 * Implementation of delegated credential management for the sidecar.
 */

#include "CredentialManager.h"
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/Serialization.h>
#include <fizz/protocol/CertificateVerifier.h>
#include <folly/ssl/OpenSSLCertUtils.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include <sstream>
#include <iomanip>
#include <iostream>

namespace sidecar {

CredentialManager::CredentialManager(
    std::shared_ptr<fizz::SelfCert> parentCert,
    folly::ssl::EvpPkeyUniquePtr parentKey,
    std::chrono::seconds validitySeconds)
    : parentCert_(std::move(parentCert)),
      parentKey_(std::move(parentKey)),
      validitySeconds_(validitySeconds) {

    // Verify that the parent certificate has the necessary extensions
    // for delegated credentials
    try {
        fizz::extensions::DelegatedCredentialUtils::checkExtensions(
            parentCert_->getX509());
    } catch (const std::exception& e) {
        throw std::runtime_error(
            "Parent certificate does not support delegated credentials: " +
            std::string(e.what()));
    }
}

std::shared_ptr<ServiceCredential> CredentialManager::generateCredentialForService(
    const std::string& serviceName) {

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we already have a valid credential for this service
    auto it = credentials_.find(serviceName);
    if (it != credentials_.end()) {
        auto now = std::chrono::system_clock::now();
        if (now < it->second->expiresAt) {
            // Return existing valid credential
            return it->second;
        }
        // Credential expired, generate new one
    }

    // Generate a new private key for the delegated credential
    auto credKey = generateCredentialPrivateKey();

    // Determine signature schemes
    auto parentKeyType = fizz::openssl::CertUtils::getKeyType(parentKey_);
    auto parentSigSchemes = fizz::openssl::CertUtils::getSigSchemes(parentKeyType);
    auto credKeyType = fizz::openssl::CertUtils::getKeyType(credKey);
    auto credSigSchemes = fizz::openssl::CertUtils::getSigSchemes(credKeyType);

    if (parentSigSchemes.empty() || credSigSchemes.empty()) {
        throw std::runtime_error("No valid signature schemes available");
    }

    // Use the first available signature scheme for each
    auto parentSigScheme = parentSigSchemes[0];
    auto credSigScheme = credSigSchemes[0];

    // [DIAGNOSTIC] Log signature schemes being used
    std::cout << "[CredentialManager] Generating credential for service: " << serviceName << std::endl;
    std::cout << "  Parent key type: " << static_cast<int>(parentKeyType) << std::endl;
    std::cout << "  Parent signature schemes available: ";
    for (const auto& scheme : parentSigSchemes) {
        std::cout << static_cast<uint16_t>(scheme) << " ";
    }
    std::cout << std::endl;
    std::cout << "  Selected parent sig scheme (credential_scheme): "
              << static_cast<uint16_t>(parentSigScheme) << std::endl;
    std::cout << "  Credential key type: " << static_cast<int>(credKeyType) << std::endl;
    std::cout << "  Credential signature schemes available: ";
    for (const auto& scheme : credSigSchemes) {
        std::cout << static_cast<uint16_t>(scheme) << " ";
    }
    std::cout << std::endl;
    std::cout << "  Selected cred sig scheme (expected_verify_scheme): "
              << static_cast<uint16_t>(credSigScheme) << std::endl;

    // Generate the delegated credential
    auto credential = fizz::extensions::DelegatedCredentialUtils::generateCredential(
        parentCert_,
        parentKey_,
        credKey,
        parentSigScheme,
        credSigScheme,
        fizz::CertificateVerifyContext::ServerDelegatedCredential,
        validitySeconds_);

    // Store the public key in DER format before moving anything
    std::string publicKeyDer = publicKeyToDer(credKey);

    // Convert private key to PEM format before moving
    folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO");
    }

    EVP_PKEY* keyPtr = credKey.get();
    if (PEM_write_bio_PrivateKey(bio.get(), keyPtr, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    std::string keyPEM(mem->data, mem->length);

    // Generate PEM using Fizz's serialization (pass credential by move)
    std::string credentialPEM = fizz::extensions::generateDelegatedCredentialPEM(
        fizz::extensions::DelegatedCredentialMode::Server,
        std::move(credential),
        keyPEM);

    // Re-generate the credential since we moved it
    auto credential2 = fizz::extensions::DelegatedCredentialUtils::generateCredential(
        parentCert_,
        parentKey_,
        credKey,
        parentSigScheme,
        credSigScheme,
        fizz::CertificateVerifyContext::ServerDelegatedCredential,
        validitySeconds_);

    // [DIAGNOSTIC] Self-verify the credential signature immediately after generation
    std::cout << "[CredentialManager] Self-verifying credential signature..." << std::endl;
    try {
        // Prepare the signature buffer (what was signed)
        auto certDer = folly::ssl::OpenSSLCertUtils::derEncode(*parentCert_->getX509());
        auto signatureBuffer = fizz::extensions::DelegatedCredentialUtils::prepareSignatureBuffer(
            credential2, std::move(certDer));

        // Create a peer certificate from parent cert to verify signature
        auto peerCert = fizz::openssl::CertUtils::makePeerCert(parentCert_->getX509());

        // Verify the credential signature using parent cert's public key
        peerCert->verify(
            credential2.credential_scheme,
            fizz::CertificateVerifyContext::ServerDelegatedCredential,
            signatureBuffer->coalesce(),
            credential2.signature->coalesce());

        std::cout << "  ✓ Credential signature verified successfully" << std::endl;
        std::cout << "  ✓ Parent cert can verify credential signed with scheme "
                  << static_cast<uint16_t>(credential2.credential_scheme) << std::endl;

        // [DIAGNOSTIC] Log public key details
        std::cout << "  Public key length: " << credential2.public_key->computeChainDataLength() << " bytes" << std::endl;
        std::cout << "  Credential valid_time: " << credential2.valid_time << " seconds" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "  ✗ CRITICAL: Credential signature verification FAILED: "
                  << e.what() << std::endl;
        std::cerr << "  ✗ This credential will fail during TLS handshake!" << std::endl;
        throw std::runtime_error("Credential self-verification failed: " + std::string(e.what()));
    }

    // Create ServiceCredential structure
    auto serviceCredential = std::make_shared<ServiceCredential>();
    serviceCredential->serviceName = serviceName;
    serviceCredential->credential = std::move(credential2);
    serviceCredential->publicKeyDer = publicKeyDer;
    serviceCredential->signatureScheme = credSigScheme;
    serviceCredential->credentialPEM = std::move(credentialPEM);

    // Move the private key into the structure
    serviceCredential->credentialPrivateKey = std::move(credKey);

    // Set timestamps
    auto now = std::chrono::system_clock::now();
    serviceCredential->createdAt = now;
    serviceCredential->expiresAt = now + validitySeconds_;

    // Store in map
    credentials_[serviceName] = serviceCredential;

    return serviceCredential;
}

std::shared_ptr<ServiceCredential> CredentialManager::getCredential(
    const std::string& serviceName) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = credentials_.find(serviceName);
    if (it != credentials_.end()) {
        // Check if credential is still valid
        auto now = std::chrono::system_clock::now();
        if (now < it->second->expiresAt) {
            return it->second;
        }
        // Expired, remove it
        credentials_.erase(it);
    }

    return nullptr;
}

std::string CredentialManager::getPublicVerificationInfo(
    const std::string& serviceName) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = credentials_.find(serviceName);
    if (it == credentials_.end()) {
        return "";
    }

    auto& cred = it->second;

    // Create a JSON-like response with public verification information
    std::ostringstream json;
    json << "{\n";
    json << "  \"serviceName\": \"" << cred->serviceName << "\",\n";
    json << "  \"validTime\": " << cred->credential.valid_time << ",\n";
    json << "  \"expectedVerifyScheme\": "
         << static_cast<uint16_t>(cred->credential.expected_verify_scheme) << ",\n";
    json << "  \"publicKeyDer\": \"" << cred->publicKeyDer << "\",\n";

    // Convert expiration time to timestamp
    auto expiresTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
        cred->expiresAt.time_since_epoch()).count();
    json << "  \"expiresAt\": " << expiresTimestamp << "\n";
    json << "}";

    return json.str();
}

bool CredentialManager::hasCredential(const std::string& serviceName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return credentials_.find(serviceName) != credentials_.end();
}

void CredentialManager::cleanupExpiredCredentials() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    auto it = credentials_.begin();

    while (it != credentials_.end()) {
        if (now >= it->second->expiresAt) {
            it = credentials_.erase(it);
        } else {
            ++it;
        }
    }
}

folly::ssl::EvpPkeyUniquePtr CredentialManager::generateCredentialPrivateKey() {
    // Generate a P-256 EC key for the delegated credential
    // Note: Must match parent certificate key type due to Fizz library limitation
    folly::ssl::EvpPkeyUniquePtr pkey(EVP_PKEY_new());
    folly::ssl::EcGroupUniquePtr group(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    folly::ssl::EcKeyUniquePtr ecKey(EC_KEY_new());

    if (!pkey || !group || !ecKey) {
        throw std::runtime_error("Failed to create key structures");
    }

    EC_GROUP_set_asn1_flag(group.get(), OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_UNCOMPRESSED);

    if (EC_KEY_set_group(ecKey.get(), group.get()) != 1) {
        throw std::runtime_error("Failed to set EC group");
    }

    if (EC_KEY_generate_key(ecKey.get()) != 1) {
        throw std::runtime_error("Failed to generate EC key");
    }

    if (EVP_PKEY_set1_EC_KEY(pkey.get(), ecKey.get()) != 1) {
        throw std::runtime_error("Failed to assign EC key to EVP_PKEY");
    }

    return pkey;
}

std::string CredentialManager::getCredentialPEM(const std::string& serviceName) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = credentials_.find(serviceName);
    if (it == credentials_.end()) {
        return "";
    }

    // Return the cached PEM that was generated during credential creation
    return it->second->credentialPEM;
}

std::string CredentialManager::publicKeyToDer(
    const folly::ssl::EvpPkeyUniquePtr& pkey) {

    int derLen = i2d_PUBKEY(pkey.get(), nullptr);
    if (derLen < 0) {
        throw std::runtime_error("Failed to get DER length");
    }

    std::vector<unsigned char> derData(derLen);
    unsigned char* derPtr = derData.data();

    if (i2d_PUBKEY(pkey.get(), &derPtr) < 0) {
        throw std::runtime_error("Failed to convert public key to DER");
    }

    // Convert to hex string for easier transmission
    std::ostringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (unsigned char byte : derData) {
        hexStream << std::setw(2) << static_cast<int>(byte);
    }

    return hexStream.str();
}

} // namespace sidecar
