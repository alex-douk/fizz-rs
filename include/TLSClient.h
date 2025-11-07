/*
 * TLSClient.h
 *
 * TLS client that connects to servers using delegated credentials.
 *
 * The client:
 * 1. Queries the sidecar via HTTPS for verification information
 * 2. Connects to the server via TLS
 * 3. Verifies the server's certificate and delegated credential
 */

#pragma once

#include <memory>
#include <string>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/client/AsyncFizzClient.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialClientExtension.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncSocket.h>

namespace client {

// Forward declaration
class FizzClientConnection;

/**
 * Verification information obtained from the sidecar
 */
struct VerificationInfo {
    std::string serviceName;
    uint32_t validTime;              // Validity period in seconds
    uint16_t expectedVerifyScheme;   // Expected signature scheme
    std::string publicKeyDer;        // DER-encoded public key (hex string)
    uint64_t expiresAt;              // Unix timestamp when credential expires

    VerificationInfo()
        : validTime(0),
          expectedVerifyScheme(0),
          expiresAt(0) {}
};

/**
 * TLS client that verifies delegated credentials
 */
class TLSClient {
public:
    /**
     * Constructor
     *
     * @param sidecarHost Sidecar hostname/IP
     * @param sidecarPort Sidecar HTTPS port
     * @param sidecarCertPath Path to sidecar's CA certificate for HTTPS verification
     */
    TLSClient(const std::string& sidecarHost,
              int sidecarPort,
              const std::string& sidecarCertPath);

    ~TLSClient();

    /**
     * Query the sidecar for verification information
     *
     * @param serviceName Name of the service to verify
     * @return true if verification info retrieved successfully, false otherwise
     */
    bool getVerificationInfo(const std::string& serviceName);

    /**
     * Connect to a TLS server and verify its delegated credential
     *
     * @param serverHost Server hostname/IP
     * @param serverPort Server TLS port
     * @param serviceName Service name to verify
     * @return true if connection and verification successful, false otherwise
     */
    bool connectToServer(const std::string& serverHost,
                        int serverPort,
                        const std::string& serviceName);

    /**
     * Get the verification information for the last queried service
     */
    const VerificationInfo& getVerificationInfoData() const {
        return verificationInfo_;
    }

    /**
     * Check if we have valid verification info
     */
    bool hasVerificationInfo() const {
        return !verificationInfo_.serviceName.empty();
    }

private:
    // Create Fizz client context with delegated credential support
    std::shared_ptr<fizz::client::FizzClientContext> createFizzClientContext();
    // HTTPS client functions for communicating with sidecar
    bool makeHTTPSRequest(
        const std::string& method,
        const std::string& path,
        const std::string& body,
        std::string& responseBody);

    // Initialize SSL context for HTTPS client (to sidecar)
    SSL_CTX* createSidecarSSLContext();

    // Parse verification info response from sidecar
    bool parseVerificationResponse(const std::string& response);

    // Configuration
    std::string sidecarHost_;
    int sidecarPort_;
    std::string sidecarCertPath_;

    // Verification data
    VerificationInfo verificationInfo_;

    // Fizz components
    std::unique_ptr<folly::EventBase> evb_;
    std::shared_ptr<FizzClientConnection> connection_;
};

/**
 * Connection handler for Fizz client connection
 */
class FizzClientConnection : public fizz::client::AsyncFizzClient::HandshakeCallback,
                             public folly::AsyncTransportWrapper::ReadCallback {
public:
    explicit FizzClientConnection(
        std::shared_ptr<fizz::client::AsyncFizzClient> transport,
        const VerificationInfo& verificationInfo,
        const std::string& sidecarCertPath);

    // HandshakeCallback methods
    void fizzHandshakeSuccess(fizz::client::AsyncFizzClient* client) noexcept override;
    void fizzHandshakeError(
        fizz::client::AsyncFizzClient* client,
        folly::exception_wrapper ex) noexcept override;

    // ReadCallback methods
    void getReadBuffer(void** bufReturn, size_t* lenReturn) override;
    void readDataAvailable(size_t len) noexcept override;
    void readEOF() noexcept override;
    void readErr(const folly::AsyncSocketException& ex) noexcept override;

    bool isConnected() const { return connected_; }
    bool hadError() const { return hadError_; }

private:
    std::shared_ptr<fizz::client::AsyncFizzClient> transport_;
    VerificationInfo verificationInfo_;
    std::string sidecarCertPath_;
    bool connected_{false};
    bool hadError_{false};
    std::array<char, 4096> readBuf_;
};

} // namespace client
