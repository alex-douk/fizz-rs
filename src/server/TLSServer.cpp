/*
 * TLSServer.cpp
 *
 * Implementation of TLS server that uses delegated credentials from the sidecar.
 */

#include "TLSServer.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <openssl/err.h>

#include <fizz/extensions/delegatedcred/Serialization.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <fizz/server/TicketTypes.h>
#include <fizz/server/SlidingBloomReplayCache.h>
#include <fizz/crypto/RandomGenerator.h>
#include <folly/io/async/AsyncSocket.h>

namespace server {

TLSServer::TLSServer(const std::string& serviceName,
                     int serverPort,
                     const std::string& sidecarHost,
                     int sidecarPort,
                     const std::string& sidecarCertPath)
    : serviceName_(serviceName),
      serverPort_(serverPort),
      sidecarHost_(sidecarHost),
      sidecarPort_(sidecarPort),
      sidecarCertPath_(sidecarCertPath),
      running_(false),
      serverSocket_(-1) {

    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

TLSServer::~TLSServer() {
    stop();
}

bool TLSServer::registerWithSidecar() {
    std::cout << "Registering with sidecar at " << sidecarHost_ << ":"
              << sidecarPort_ << "..." << std::endl;

    // Build JSON request body
    std::ostringstream requestBody;
    requestBody << "{\"serviceName\": \"" << serviceName_ << "\"}";

    // Make HTTPS POST request to /register
    std::string responseBody;
    if (!makeHTTPSRequest("POST", "/register", requestBody.str(), responseBody)) {
        std::cerr << "Failed to connect to sidecar" << std::endl;
        return false;
    }

    // Parse response
    if (!parseRegistrationResponse(responseBody)) {
        std::cerr << "Failed to parse sidecar response" << std::endl;
        return false;
    }

    std::cout << "Successfully registered with sidecar!" << std::endl;
    std::cout << "  Service: " << credentialInfo_.serviceName << std::endl;
    std::cout << "  Valid time: " << credentialInfo_.validTime << " seconds" << std::endl;
    std::cout << "  Signature scheme: " << credentialInfo_.signatureScheme << std::endl;

    return true;
}

SSL_CTX* TLSServer::createClientSSLContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to create SSL context");
    }

    // Load CA certificate for verifying the sidecar
    if (SSL_CTX_load_verify_locations(ctx, sidecarCertPath_.c_str(), nullptr) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        throw std::runtime_error("Failed to load CA certificate: " + sidecarCertPath_);
    }

    // Require certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    return ctx;
}

bool TLSServer::makeHTTPSRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body,
    std::string& responseBody) {

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }

    // Resolve hostname
    struct hostent* host = gethostbyname(sidecarHost_.c_str());
    if (!host) {
        std::cerr << "Failed to resolve hostname: " << sidecarHost_ << std::endl;
        close(sock);
        return false;
    }

    // Connect to sidecar
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sidecarPort_);
    std::memcpy(&addr.sin_addr.s_addr, host->h_addr, host->h_length);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to connect to sidecar" << std::endl;
        close(sock);
        return false;
    }

    // Create SSL context and connection
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    bool success = false;

    try {
        ctx = createClientSSLContext();
        ssl = SSL_new(ctx);

        if (!ssl) {
            throw std::runtime_error("Failed to create SSL object");
        }

        SSL_set_fd(ssl, sock);

        // Perform SSL handshake
        if (SSL_connect(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("SSL handshake failed");
        }

        // Build HTTP request
        std::ostringstream request;
        request << method << " " << path << " HTTP/1.1\r\n";
        request << "Host: " << sidecarHost_ << "\r\n";
        request << "Content-Type: application/json\r\n";
        request << "Content-Length: " << body.length() << "\r\n";
        request << "Connection: close\r\n";
        request << "\r\n";
        request << body;

        std::string requestStr = request.str();

        // Send request
        if (SSL_write(ssl, requestStr.c_str(), requestStr.length()) <= 0) {
            throw std::runtime_error("Failed to send HTTPS request");
        }

        // Read response
        char buffer[4096];
        std::ostringstream response;
        int bytesRead;

        while ((bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytesRead] = '\0';
            response << buffer;
        }

        std::string responseStr = response.str();

        // Parse HTTP response to extract body
        size_t bodyStart = responseStr.find("\r\n\r\n");
        if (bodyStart != std::string::npos) {
            responseBody = responseStr.substr(bodyStart + 4);
        } else {
            responseBody = responseStr;
        }

        success = true;

    } catch (const std::exception& e) {
        std::cerr << "HTTPS request error: " << e.what() << std::endl;
    }

    // Cleanup
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    close(sock);

    return success;
}

bool TLSServer::parseRegistrationResponse(const std::string& response) {
    // Simple JSON parsing
    // Expected format: {"status": "success", "serviceName": "...", "validTime": ..., "signatureScheme": ..., "credentialPEM": "...", "parentCertPath": "..."}

    // Check for success status
    if (response.find("\"status\"") == std::string::npos ||
        response.find("\"success\"") == std::string::npos) {
        return false;
    }

    // Extract serviceName
    size_t namePos = response.find("\"serviceName\"");
    if (namePos != std::string::npos) {
        size_t colonPos = response.find(':', namePos);
        if (colonPos != std::string::npos) {
            size_t quoteStart = response.find('\"', colonPos);
            if (quoteStart != std::string::npos) {
                size_t quoteEnd = response.find('\"', quoteStart + 1);
                if (quoteEnd != std::string::npos) {
                    credentialInfo_.serviceName =
                        response.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                }
            }
        }
    }

    // Extract validTime
    size_t validTimePos = response.find("\"validTime\"");
    if (validTimePos != std::string::npos) {
        size_t colonPos = response.find(':', validTimePos);
        if (colonPos != std::string::npos) {
            size_t numStart = colonPos + 1;
            // Skip whitespace
            while (numStart < response.length() && std::isspace(response[numStart])) {
                numStart++;
            }
            size_t numEnd = numStart;
            while (numEnd < response.length() && std::isdigit(response[numEnd])) {
                numEnd++;
            }
            if (numEnd > numStart) {
                credentialInfo_.validTime =
                    std::stoul(response.substr(numStart, numEnd - numStart));
            }
        }
    }

    // Extract signatureScheme
    size_t schemePos = response.find("\"signatureScheme\"");
    if (schemePos != std::string::npos) {
        size_t colonPos = response.find(':', schemePos);
        if (colonPos != std::string::npos) {
            size_t numStart = colonPos + 1;
            // Skip whitespace
            while (numStart < response.length() && std::isspace(response[numStart])) {
                numStart++;
            }
            size_t numEnd = numStart;
            while (numEnd < response.length() && std::isdigit(response[numEnd])) {
                numEnd++;
            }
            if (numEnd > numStart) {
                credentialInfo_.signatureScheme =
                    static_cast<uint16_t>(std::stoul(response.substr(numStart, numEnd - numStart)));
            }
        }
    }

    // Extract credentialPEM
    size_t pemPos = response.find("\"credentialPEM\"");
    if (pemPos != std::string::npos) {
        size_t colonPos = response.find(':', pemPos);
        if (colonPos != std::string::npos) {
            size_t quoteStart = response.find('\"', colonPos);
            if (quoteStart != std::string::npos) {
                size_t quoteEnd = response.find('\"', quoteStart + 1);
                if (quoteEnd != std::string::npos) {
                    std::string escapedPEM = response.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                    // Unescape the PEM string
                    credentialInfo_.credentialPEM = "";
                    for (size_t i = 0; i < escapedPEM.length(); i++) {
                        if (escapedPEM[i] == '\\' && i + 1 < escapedPEM.length()) {
                            if (escapedPEM[i + 1] == 'n') {
                                credentialInfo_.credentialPEM += '\n';
                                i++;
                            } else if (escapedPEM[i + 1] == '\\') {
                                credentialInfo_.credentialPEM += '\\';
                                i++;
                            } else if (escapedPEM[i + 1] == '\"') {
                                credentialInfo_.credentialPEM += '\"';
                                i++;
                            } else {
                                credentialInfo_.credentialPEM += escapedPEM[i];
                            }
                        } else {
                            credentialInfo_.credentialPEM += escapedPEM[i];
                        }
                    }
                }
            }
        }
    }

    // Extract parentCertPath
    size_t certPathPos = response.find("\"parentCertPath\"");
    if (certPathPos != std::string::npos) {
        size_t colonPos = response.find(':', certPathPos);
        if (colonPos != std::string::npos) {
            size_t quoteStart = response.find('\"', colonPos);
            if (quoteStart != std::string::npos) {
                size_t quoteEnd = response.find('\"', quoteStart + 1);
                if (quoteEnd != std::string::npos) {
                    credentialInfo_.parentCertPath =
                        response.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                }
            }
        }
    }

    credentialInfo_.receivedAt = std::chrono::system_clock::now();

    return !credentialInfo_.serviceName.empty() &&
           credentialInfo_.validTime > 0 &&
           !credentialInfo_.credentialPEM.empty() &&
           !credentialInfo_.parentCertPath.empty();
}

bool TLSServer::hasValidCredentials() const {
    if (credentialInfo_.serviceName.empty() || credentialInfo_.validTime == 0) {
        return false;
    }

    // Check if credentials have expired
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - credentialInfo_.receivedAt).count();

    return elapsed < credentialInfo_.validTime;
}

std::shared_ptr<fizz::server::FizzServerContext> TLSServer::createFizzServerContext() {
    std::cout << "Creating Fizz server context with delegated credentials..." << std::endl;

    // Create certificate manager that supports delegated credentials
    auto certManager = std::make_unique<fizz::extensions::DelegatedCredentialCertManager>();

    // Create combined PEM file with parent cert + delegated credential
    std::string combinedPEM;

    // Read parent certificate
    std::ifstream parentCertFile(credentialInfo_.parentCertPath);
    if (!parentCertFile) {
        throw std::runtime_error("Failed to open parent certificate: " +
                               credentialInfo_.parentCertPath);
    }
    std::stringstream buffer;
    buffer << parentCertFile.rdbuf();
    combinedPEM = buffer.str();
    parentCertFile.close();

    // Append delegated credential PEM
    combinedPEM += credentialInfo_.credentialPEM;

    std::cout << "Loading delegated credential from PEM..." << std::endl;

    // Load the delegated credential using Fizz's serialization
    auto dcCert = fizz::extensions::loadDCFromPEM(
        combinedPEM,
        fizz::extensions::DelegatedCredentialMode::Server);

    if (!dcCert) {
        throw std::runtime_error("Failed to load delegated credential from PEM");
    }

    std::cout << "Successfully loaded delegated credential" << std::endl;

    // [DIAGNOSTIC] Log loaded credential details
    std::cout << "[Server] Loaded delegated credential details:" << std::endl;
    std::cout << "  Service: " << credentialInfo_.serviceName << std::endl;
    std::cout << "  Valid time from sidecar: " << credentialInfo_.validTime << " seconds" << std::endl;
    std::cout << "  Signature scheme from sidecar: " << credentialInfo_.signatureScheme << std::endl;

    // Extract credential details from the loaded dcCert
    const auto& credential = dcCert->getDelegatedCredential();
    std::cout << "  Loaded credential_scheme (parent signs DC): "
              << static_cast<uint16_t>(credential.credential_scheme) << std::endl;
    std::cout << "  Loaded expected_verify_scheme (DC signs handshake): "
              << static_cast<uint16_t>(credential.expected_verify_scheme) << std::endl;
    std::cout << "  Loaded valid_time: " << credential.valid_time << " seconds" << std::endl;

    // Add delegated credential as default cert
    certManager->addDelegatedCredentialAndSetDefault(
        std::shared_ptr<fizz::extensions::SelfDelegatedCredential>(
            std::move(dcCert)));

    // Create Fizz server context
    auto ctx = std::make_shared<fizz::server::FizzServerContext>();
    ctx->setCertManager(std::move(certManager));

    // Set supported cipher suites
    ctx->setSupportedCiphers({{
        fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
        fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
        fizz::CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    }});

    // Set supported signature schemes
    ctx->setSupportedSigSchemes({
        fizz::SignatureScheme::ecdsa_secp256r1_sha256,
        fizz::SignatureScheme::ecdsa_secp384r1_sha384,
        fizz::SignatureScheme::ecdsa_secp521r1_sha512,
        fizz::SignatureScheme::rsa_pss_sha256
    });

    // Set supported groups
    ctx->setSupportedGroups({
        fizz::NamedGroup::secp256r1,
        fizz::NamedGroup::x25519
    });

    // Note: Skipping ticket cipher setup - not needed for delegated credential presentation
    // Ticket cipher is only for session resumption, which is separate from initial handshake

    std::cout << "Fizz server context created successfully" << std::endl;

    return ctx;
}

void TLSServer::start() {
    std::cout << "TLS server starting on port " << serverPort_ << "..." << std::endl;
    std::cout << "Using delegated credentials from sidecar" << std::endl;
    std::cout << "  Service: " << credentialInfo_.serviceName << std::endl;
    std::cout << "  Valid time: " << credentialInfo_.validTime << " seconds" << std::endl;
    std::cout << "  Signature scheme: " << credentialInfo_.signatureScheme << std::endl;

    // Create Fizz server context with delegated credentials
    fizzContext_ = createFizzServerContext();

    // Create event base for async I/O
    evb_ = std::make_unique<folly::EventBase>();

    // Create server socket
    socket_ = folly::AsyncServerSocket::UniquePtr(
        new folly::AsyncServerSocket(evb_.get()));

    // Set up socket
    socket_->bind(serverPort_);
    socket_->listen(10);
    socket_->addAcceptCallback(this, evb_.get());
    socket_->startAccepting();

    running_ = true;
    std::cout << "Fizz TLS server listening on port " << serverPort_ << std::endl;
    std::cout << "Server is ready to accept connections with delegated credentials" << std::endl;

    // Run event loop
    while (running_) {
        evb_->loopOnce();
    }

    std::cout << "Server shutting down..." << std::endl;
}

void TLSServer::stop() {
    running_ = false;
    if (socket_) {
        socket_->removeAcceptCallback(this, nullptr);
    }
    if (evb_) {
        evb_->terminateLoopSoon();
    }
}

void TLSServer::connectionAccepted(
    folly::NetworkSocket fdNetworkSocket,
    const folly::SocketAddress& clientAddr,
    folly::AsyncServerSocket::AcceptCallback::AcceptInfo /* info */) noexcept {

    std::cout << "Accepted connection from " << clientAddr.describe() << std::endl;

    try {
        // Create socket from file descriptor
        auto sock = new folly::AsyncSocket(evb_.get(), fdNetworkSocket);

        // Create Fizz server for this connection
        auto fizzServer = fizz::server::AsyncFizzServer::UniquePtr(
            new fizz::server::AsyncFizzServer(
                folly::AsyncSocket::UniquePtr(sock),
                fizzContext_));

        // Create connection handler
        auto conn = std::make_shared<FizzServerConnection>(
            std::shared_ptr<fizz::server::AsyncFizzServer>(std::move(fizzServer)));

        connections_.push_back(conn);

        std::cout << "Starting TLS handshake with delegated credentials..." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error accepting connection: " << e.what() << std::endl;
    }
}

void TLSServer::acceptError(folly::exception_wrapper ex) noexcept {
    std::cerr << "Accept error: " << ex.what() << std::endl;
}

// FizzServerConnection implementation

FizzServerConnection::FizzServerConnection(
    std::shared_ptr<fizz::server::AsyncFizzServer> transport)
    : transport_(std::move(transport)) {
    // Start the TLS handshake
    transport_->accept(this);
}

void FizzServerConnection::fizzHandshakeSuccess(
    fizz::server::AsyncFizzServer* server) noexcept {
    std::cout << "TLS handshake successful!" << std::endl;

    connected_ = true;

    // Print connection info
    auto cipher = server->getState().cipher();
    auto peerCert = server->getState().unverifiedCertChain();

    std::cout << "  Cipher: " << toString(*cipher) << std::endl;
    std::cout << "  Delegated credential was presented to client" << std::endl;

    // Set up read callback to receive data
    server->setReadCB(this);

    // Send a welcome message
    const char* welcomeMsg = "Welcome! You have successfully connected to a server using delegated credentials.\n";
    server->writeChain(nullptr, folly::IOBuf::copyBuffer(welcomeMsg));
}

void FizzServerConnection::fizzHandshakeError(
    fizz::server::AsyncFizzServer* /* server */,
    folly::exception_wrapper ex) noexcept {
    std::cerr << "TLS handshake error: " << ex.what() << std::endl;
    // Connection will be cleaned up automatically
}

void FizzServerConnection::fizzHandshakeAttemptFallback(
    fizz::server::AttemptVersionFallback /* fallback */) {
    std::cerr << "Client attempted version fallback - not supported" << std::endl;
    // We don't support fallback to older TLS versions
    transport_->closeNow();
}

void FizzServerConnection::getReadBuffer(void** bufReturn, size_t* lenReturn) {
    *bufReturn = readBuf_.data();
    *lenReturn = readBuf_.size();
}

void FizzServerConnection::readDataAvailable(size_t len) noexcept {
    std::cout << "Received " << len << " bytes from client" << std::endl;

    // Echo back the data
    auto buf = folly::IOBuf::copyBuffer(readBuf_.data(), len);
    transport_->writeChain(nullptr, std::move(buf));
}

void FizzServerConnection::readEOF() noexcept {
    std::cout << "Client closed connection" << std::endl;
    transport_->closeNow();
}

void FizzServerConnection::readErr(const folly::AsyncSocketException& ex) noexcept {
    std::cerr << "Read error: " << ex.what() << std::endl;
    transport_->closeNow();
}

} // namespace server
