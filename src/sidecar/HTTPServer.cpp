/*
 * HTTPServer.cpp
 *
 * Simple HTTPS server implementation for the sidecar.
 */

#include "HTTPServer.h"
#include <fizz/extensions/delegatedcred/Serialization.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <openssl/err.h>

namespace sidecar {

HTTPServer::HTTPServer(int port,
                       std::shared_ptr<CredentialManager> credentialManager,
                       const std::string& certPath,
                       const std::string& keyPath)
    : port_(port),
      serverSocket_(-1),
      credentialManager_(std::move(credentialManager)),
      running_(false),
      sslContext_(nullptr),
      certPath_(certPath),
      keyPath_(keyPath) {
    initializeSSL();
}

HTTPServer::~HTTPServer() {
    stop();
    if (sslContext_) {
        SSL_CTX_free(sslContext_);
        sslContext_ = nullptr;
    }
}

void HTTPServer::initializeSSL() {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Create SSL context
    const SSL_METHOD* method = TLS_server_method();
    sslContext_ = SSL_CTX_new(method);

    if (!sslContext_) {
        throw std::runtime_error("Failed to create SSL context");
    }

    // Load certificate
    if (SSL_CTX_use_certificate_file(sslContext_, certPath_.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(sslContext_);
        sslContext_ = nullptr;
        throw std::runtime_error("Failed to load certificate: " + certPath_);
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(sslContext_, keyPath_.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(sslContext_);
        sslContext_ = nullptr;
        throw std::runtime_error("Failed to load private key: " + keyPath_);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(sslContext_)) {
        SSL_CTX_free(sslContext_);
        sslContext_ = nullptr;
        throw std::runtime_error("Private key does not match the certificate");
    }

    std::cout << "SSL/TLS initialized successfully" << std::endl;
}

void HTTPServer::start() {
    // Create socket
    serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket_ < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    // Set socket options to allow reuse
    int opt = 1;
    if (setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(serverSocket_);
        throw std::runtime_error("Failed to set socket options");
    }

    // Bind socket
    struct sockaddr_in serverAddr;
    std::memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port_);

    if (bind(serverSocket_, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(serverSocket_);
        throw std::runtime_error("Failed to bind socket to port " + std::to_string(port_));
    }

    // Listen
    if (listen(serverSocket_, 10) < 0) {
        close(serverSocket_);
        throw std::runtime_error("Failed to listen on socket");
    }

    running_ = true;
    std::cout << "Sidecar HTTPS server listening on port " << port_ << std::endl;

    // Accept connections
    while (running_) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);

        int clientSocket = accept(serverSocket_, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            if (running_) {
                std::cerr << "Failed to accept connection" << std::endl;
            }
            continue;
        }

        // Handle client in the same thread (simple implementation)
        // For production, use thread pool or async I/O
        handleClient(clientSocket);
        close(clientSocket);
    }
}

void HTTPServer::stop() {
    running_ = false;
    if (serverSocket_ >= 0) {
        close(serverSocket_);
        serverSocket_ = -1;
    }
}

void HTTPServer::handleClient(int clientSocket) {
    // Create SSL object for this connection
    SSL* ssl = SSL_new(sslContext_);
    if (!ssl) {
        std::cerr << "Failed to create SSL object" << std::endl;
        return;
    }

    // Attach the socket to the SSL object
    SSL_set_fd(ssl, clientSocket);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return;
    }

    // Read request over SSL
    char buffer[4096];
    int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytesRead <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    buffer[bytesRead] = '\0';
    std::string requestData(buffer, bytesRead);

    try {
        auto request = parseRequest(requestData);

        std::string response;

        // Route based on path
        if (request.method == "POST" && request.path == "/register") {
            response = handleRegister(request);
            sendResponse(ssl, 200, "OK", response);
        } else if (request.method == "GET" && request.path == "/verify") {
            response = handleVerify(request);
            if (!response.empty()) {
                sendResponse(ssl, 200, "OK", response);
            } else {
                sendResponse(ssl, 404, "Not Found",
                    "{\"error\": \"Service not found\"}");
            }
        } else {
            sendResponse(ssl, 404, "Not Found",
                "{\"error\": \"Endpoint not found\"}");
        }
    } catch (const std::exception& e) {
        std::string errorJson = "{\"error\": \"" + std::string(e.what()) + "\"}";
        sendResponse(ssl, 500, "Internal Server Error", errorJson);
    }

    // Clean shutdown
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

HTTPServer::HTTPRequest HTTPServer::parseRequest(const std::string& requestData) {
    HTTPRequest request;

    std::istringstream stream(requestData);
    std::string line;

    // Parse request line
    if (std::getline(stream, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        std::istringstream lineStream(line);
        lineStream >> request.method;

        std::string fullPath;
        lineStream >> fullPath;

        // Split path and query string
        size_t queryPos = fullPath.find('?');
        if (queryPos != std::string::npos) {
            request.path = fullPath.substr(0, queryPos);
            request.queryString = fullPath.substr(queryPos + 1);
        } else {
            request.path = fullPath;
        }
    }

    // Skip headers and find body
    bool foundEmptyLine = false;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) {
            foundEmptyLine = true;
            break;
        }
    }

    // Read body if present
    if (foundEmptyLine) {
        std::ostringstream bodyStream;
        bodyStream << stream.rdbuf();
        request.body = bodyStream.str();
    }

    return request;
}

std::string HTTPServer::handleRegister(const HTTPRequest& request) {
    // Parse service name from JSON body
    // Simple JSON parsing (for production, use a proper JSON library)
    std::string serviceName;

    size_t namePos = request.body.find("\"serviceName\"");
    if (namePos != std::string::npos) {
        size_t colonPos = request.body.find(':', namePos);
        if (colonPos != std::string::npos) {
            size_t quoteStart = request.body.find('"', colonPos);
            if (quoteStart != std::string::npos) {
                size_t quoteEnd = request.body.find('"', quoteStart + 1);
                if (quoteEnd != std::string::npos) {
                    serviceName = request.body.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                }
            }
        }
    }

    if (serviceName.empty()) {
        throw std::runtime_error("Missing serviceName in request");
    }

    std::cout << "Registering service: " << serviceName << std::endl;

    // Generate credential
    auto credential = credentialManager_->generateCredentialForService(serviceName);

    // Get credential PEM (includes delegated credential + private key)
    std::string credentialPEM = credentialManager_->getCredentialPEM(serviceName);

    // Escape newlines for JSON
    std::string escapedPEM;
    for (char c : credentialPEM) {
        if (c == '\n') {
            escapedPEM += "\\n";
        } else if (c == '"') {
            escapedPEM += "\\\"";
        } else if (c == '\\') {
            escapedPEM += "\\\\";
        } else {
            escapedPEM += c;
        }
    }

    // Build response
    std::ostringstream response;
    response << "{\n";
    response << "  \"status\": \"success\",\n";
    response << "  \"serviceName\": \"" << serviceName << "\",\n";
    response << "  \"message\": \"Delegated credential generated successfully\",\n";
    response << "  \"validTime\": " << credential->credential.valid_time << ",\n";
    response << "  \"signatureScheme\": "
             << static_cast<uint16_t>(credential->signatureScheme) << ",\n";
    response << "  \"credentialPEM\": \"" << escapedPEM << "\",\n";
    response << "  \"parentCertPath\": \"" << certPath_ << "\"\n";
    response << "}";

    return response.str();
}

std::string HTTPServer::handleVerify(const HTTPRequest& request) {
    // Extract service name from query string
    std::string serviceName = getQueryParam(request.queryString, "service");

    if (serviceName.empty()) {
        throw std::runtime_error("Missing 'service' query parameter");
    }

    std::cout << "Verification request for service: " << serviceName << std::endl;

    // Get public verification info
    return credentialManager_->getPublicVerificationInfo(serviceName);
}

void HTTPServer::sendResponse(
    SSL* ssl,
    int statusCode,
    const std::string& statusText,
    const std::string& body,
    const std::string& contentType) {

    std::ostringstream response;
    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;

    std::string responseStr = response.str();
    SSL_write(ssl, responseStr.c_str(), responseStr.length());
}

std::string HTTPServer::getQueryParam(
    const std::string& queryString,
    const std::string& key) {

    size_t keyPos = queryString.find(key + "=");
    if (keyPos == std::string::npos) {
        return "";
    }

    size_t valueStart = keyPos + key.length() + 1;
    size_t valueEnd = queryString.find('&', valueStart);

    if (valueEnd == std::string::npos) {
        return queryString.substr(valueStart);
    } else {
        return queryString.substr(valueStart, valueEnd - valueStart);
    }
}

} // namespace sidecar
