/*
 * CredentialManager.h
 *
 * Manages delegated credential generation and storage for the sidecar.
 * Maintains a mapping of service names to their corresponding delegated credentials.
 */

#pragma once

#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/Types.h>
#include <fizz/protocol/Certificate.h>
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <folly/ssl/OpenSSLPtrTypes.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <chrono>

namespace sidecar {

/**
 * Structure to hold credential information for a service
 */
struct ServiceCredential {
    std::string serviceName;
    fizz::extensions::DelegatedCredential credential;
    folly::ssl::EvpPkeyUniquePtr credentialPrivateKey;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;

    // Public verification information (can be shared with clients)
    std::string publicKeyDer;  // DER-encoded public key
    fizz::SignatureScheme signatureScheme;

    // Serialized PEM (generated once and cached)
    std::string credentialPEM;
};

/**
 * CredentialManager
 *
 * Responsible for:
 * - Generating delegated credentials for registered services
 * - Storing and retrieving credentials by service name
 * - Providing public verification information to clients
 */
class CredentialManager {
public:
    /**
     * Constructor
     *
     * @param parentCert The parent certificate that will sign delegated credentials
     * @param parentKey The private key for the parent certificate
     * @param validitySeconds How long delegated credentials should be valid (default: 7 days)
     */
    CredentialManager(
        std::shared_ptr<fizz::SelfCert> parentCert,
        folly::ssl::EvpPkeyUniquePtr parentKey,
        std::chrono::seconds validitySeconds = std::chrono::hours(24 * 7));

    /**
     * Generate and store a delegated credential for a service
     *
     * @param serviceName The name/identity of the service requesting credentials
     * @return The generated credential information
     */
    std::shared_ptr<ServiceCredential> generateCredentialForService(
        const std::string& serviceName);

    /**
     * Retrieve stored credential for a service
     *
     * @param serviceName The service name to lookup
     * @return The credential if found, nullptr otherwise
     */
    std::shared_ptr<ServiceCredential> getCredential(const std::string& serviceName);

    /**
     * Get public verification information for a service (safe to share with clients)
     *
     * @param serviceName The service name
     * @return JSON string containing public verification info, or empty string if not found
     */
    std::string getPublicVerificationInfo(const std::string& serviceName);

    /**
     * Get delegated credential in PEM format (for server to use)
     *
     * @param serviceName The service name
     * @return PEM string containing the delegated credential and private key
     */
    std::string getCredentialPEM(const std::string& serviceName);

    /**
     * Check if a credential exists for a service
     */
    bool hasCredential(const std::string& serviceName) const;

    /**
     * Remove expired credentials from storage
     */
    void cleanupExpiredCredentials();

private:
    // Generate a new private key for delegated credential
    folly::ssl::EvpPkeyUniquePtr generateCredentialPrivateKey();

    // Convert public key to DER format for storage/transmission
    std::string publicKeyToDer(const folly::ssl::EvpPkeyUniquePtr& pkey);

    std::shared_ptr<fizz::SelfCert> parentCert_;
    folly::ssl::EvpPkeyUniquePtr parentKey_;
    std::chrono::seconds validitySeconds_;

    // Thread-safe storage of service credentials
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<ServiceCredential>> credentials_;
};

} // namespace sidecar
