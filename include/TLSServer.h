/*
 * TLSServer.h
 *
 * TLS server that uses delegated credentials from the sidecar.
 *
 * The server:
 * 1. Connects to the sidecar via HTTPS
 * 2. Registers its service name and receives delegated credentials
 * 3. Uses these credentials to serve TLS connections to clients
 */

#pragma once

#include <memory>
#include <string>
#include <atomic>
#include <chrono>
#include <openssl/ssl.h>

#include <fizz/server/FizzServerContext.h>
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialCertManager.h>
#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/EventBase.h>

namespace server {

// Forward declarations
class FizzServerConnection;

/**
 * Credential information received from the sidecar
 */
struct DelegatedCredentialInfo {
    std::string serviceName;
    uint32_t validTime;          // Validity period in seconds
    uint16_t signatureScheme;    // Signature scheme used
    std::string credentialPEM;   // PEM format delegated credential + private key
    std::string parentCertPath;  // Path to parent certificate
    std::chrono::system_clock::time_point receivedAt;

    DelegatedCredentialInfo()
        : validTime(0),
          signatureScheme(0),
          receivedAt(std::chrono::system_clock::now()) {}
};

/**
 * TLS server that registers with the sidecar and uses delegated credentials
 */
class TLSServer : public folly::AsyncServerSocket::AcceptCallback {
public:
    /**
     * Constructor
     *
     * @param serviceName Name of this service
     * @param serverPort Port for the TLS server to listen on
     * @param sidecarHost Sidecar hostname/IP
     * @param sidecarPort Sidecar HTTPS port
     * @param sidecarCertPath Path to sidecar's CA certificate for HTTPS verification
     */
    TLSServer(const std::string& serviceName,
              int serverPort,
              const std::string& sidecarHost,
              int sidecarPort,
              const std::string& sidecarCertPath);

    ~TLSServer();

    /**
     * Register with the sidecar and obtain delegated credentials
     *
     * @return true if registration successful, false otherwise
     */
    bool registerWithSidecar();

    /**
     * Start the TLS server (blocking call)
     * This will serve client connections using delegated credentials
     */
    void start();

    /**
     * Stop the TLS server
     */
    void stop();

    /**
     * Check if server is running
     */
    bool isRunning() const { return running_; }

    /**
     * Get credential information
     */
    const DelegatedCredentialInfo& getCredentialInfo() const {
        return credentialInfo_;
    }

    /**
     * Check if credentials are valid (received and not expired)
     */
    bool hasValidCredentials() const;

    // AcceptCallback methods
    void connectionAccepted(
        folly::NetworkSocket fdNetworkSocket,
        const folly::SocketAddress& clientAddr,
        folly::AsyncServerSocket::AcceptCallback::AcceptInfo info) noexcept override;

    void acceptError(folly::exception_wrapper ex) noexcept override;

private:
    // HTTPS client functions for communicating with sidecar
    bool makeHTTPSRequest(
        const std::string& method,
        const std::string& path,
        const std::string& body,
        std::string& responseBody);

    // Initialize SSL context for HTTPS client
    SSL_CTX* createClientSSLContext();

    // Parse registration response from sidecar
    bool parseRegistrationResponse(const std::string& response);

    // Setup Fizz server context with delegated credentials
    std::shared_ptr<fizz::server::FizzServerContext> createFizzServerContext();

    // Configuration
    std::string serviceName_;
    int serverPort_;
    std::string sidecarHost_;
    int sidecarPort_;
    std::string sidecarCertPath_;

    // Credential storage
    DelegatedCredentialInfo credentialInfo_;

    // Server state
    std::atomic<bool> running_;
    int serverSocket_;

    // Fizz components
    std::shared_ptr<fizz::server::FizzServerContext> fizzContext_;
    std::unique_ptr<folly::EventBase> evb_;
    folly::AsyncServerSocket::UniquePtr socket_;
    std::vector<std::shared_ptr<FizzServerConnection>> connections_;
};

/**
 * Connection handler for individual client connections
 */
class FizzServerConnection : public fizz::server::AsyncFizzServer::HandshakeCallback,
                             public folly::AsyncTransportWrapper::ReadCallback {
public:
    explicit FizzServerConnection(
        std::shared_ptr<fizz::server::AsyncFizzServer> transport);

    // HandshakeCallback methods
    void fizzHandshakeSuccess(fizz::server::AsyncFizzServer* server) noexcept override;
    void fizzHandshakeError(
        fizz::server::AsyncFizzServer* server,
        folly::exception_wrapper ex) noexcept override;
    void fizzHandshakeAttemptFallback(fizz::server::AttemptVersionFallback fallback) override;

    // ReadCallback methods
    void getReadBuffer(void** bufReturn, size_t* lenReturn) override;
    void readDataAvailable(size_t len) noexcept override;
    void readEOF() noexcept override;
    void readErr(const folly::AsyncSocketException& ex) noexcept override;

private:
    std::shared_ptr<fizz::server::AsyncFizzServer> transport_;
    bool connected_{false};
    std::array<char, 4096> readBuf_;
};

} // namespace server
