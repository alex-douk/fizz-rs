/*
 * HTTPServer.h
 *
 * Simple HTTPS server for the sidecar to handle:
 * - Server credential registration requests
 * - Client verification info requests
 */

#pragma once

#include "CredentialManager.h"
#include <memory>
#include <string>
#include <functional>
#include <atomic>
#include <openssl/ssl.h>

namespace sidecar {

/**
 * Simple HTTPS server for handling sidecar requests
 *
 * Endpoints:
 * - POST /register - Server registers and gets credentials (HTTPS)
 *   Request body: {"serviceName": "service-name"}
 *   Response: {"status": "success", "credential": "..."}
 *
 * - GET /verify?service=<name> - Client gets public verification info (HTTPS)
 *   Response: {"serviceName": "...", "validTime": ..., ...}
 */
class HTTPServer {
public:
    /**
     * Constructor
     *
     * @param port The port to listen on
     * @param credentialManager The credential manager to use
     * @param certPath Path to the server certificate for HTTPS
     * @param keyPath Path to the server private key for HTTPS
     */
    HTTPServer(int port,
               std::shared_ptr<CredentialManager> credentialManager,
               const std::string& certPath,
               const std::string& keyPath);

    ~HTTPServer();

    /**
     * Start the HTTPS server (blocking call)
     */
    void start();

    /**
     * Stop the HTTPS server
     */
    void stop();

    /**
     * Check if server is running
     */
    bool isRunning() const { return running_; }

private:
    // Initialize SSL context
    void initializeSSL();

    // Handle incoming client connection
    void handleClient(int clientSocket);

    // Parse HTTP request
    struct HTTPRequest {
        std::string method;
        std::string path;
        std::string queryString;
        std::string body;
    };

    HTTPRequest parseRequest(const std::string& requestData);

    // Route handlers
    std::string handleRegister(const HTTPRequest& request);
    std::string handleVerify(const HTTPRequest& request);

    // Utility to send HTTP response over SSL
    void sendResponse(
        SSL* ssl,
        int statusCode,
        const std::string& statusText,
        const std::string& body,
        const std::string& contentType = "application/json");

    // Extract query parameter
    std::string getQueryParam(const std::string& queryString, const std::string& key);

    int port_;
    int serverSocket_;
    std::shared_ptr<CredentialManager> credentialManager_;
    std::atomic<bool> running_;

    // SSL/TLS members
    SSL_CTX* sslContext_;
    std::string certPath_;
    std::string keyPath_;
};

} // namespace sidecar
