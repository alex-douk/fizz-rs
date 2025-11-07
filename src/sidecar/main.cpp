/*
 * main.cpp
 *
 * Sidecar entry point - Certificate manager that generates delegated credentials
 * for TLS servers using RFC 9345.
 *
 * The sidecar requires a pre-existing parent certificate with delegated credential
 * extension. Use the generate_sidecar_cert utility to create this certificate.
 */

#include "CredentialManager.h"
#include "HTTPServer.h"

#include <fizz/backend/openssl/certificate/OpenSSLSelfCertImpl.h>
#include <fizz/crypto/Utils.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <iostream>
#include <fstream>
#include <memory>
#include <csignal>
#include <sstream>

namespace {

// Global server instance for signal handling
std::unique_ptr<sidecar::HTTPServer> g_server;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down sidecar..." << std::endl;
        if (g_server) {
            g_server->stop();
        }
    }
}

/**
 * Load certificate from PEM file
 */
folly::ssl::X509UniquePtr loadCertificate(const std::string& certPath) {
    std::ifstream certFile(certPath);
    if (!certFile.good()) {
        throw std::runtime_error("Cannot open certificate file: " + certPath);
    }

    std::string certPem((std::istreambuf_iterator<char>(certFile)),
                        std::istreambuf_iterator<char>());

    folly::ssl::BioUniquePtr bio(BIO_new_mem_buf(certPem.data(), certPem.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for certificate");
    }

    folly::ssl::X509UniquePtr cert(
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));

    if (!cert) {
        throw std::runtime_error("Failed to parse certificate from: " + certPath);
    }

    return cert;
}

/**
 * Load private key from PEM file
 */
folly::ssl::EvpPkeyUniquePtr loadPrivateKey(const std::string& keyPath) {
    std::ifstream keyFile(keyPath);
    if (!keyFile.good()) {
        throw std::runtime_error("Cannot open private key file: " + keyPath);
    }

    std::string keyPem((std::istreambuf_iterator<char>(keyFile)),
                       std::istreambuf_iterator<char>());

    folly::ssl::BioUniquePtr bio(BIO_new_mem_buf(keyPem.data(), keyPem.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    folly::ssl::EvpPkeyUniquePtr key(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));

    if (!key) {
        throw std::runtime_error("Failed to parse private key from: " + keyPath);
    }

    return key;
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --port PORT          HTTP server port (default: 8080)\n"
              << "  --cert PATH          Path to parent certificate (default: sidecar_cert.pem)\n"
              << "  --key PATH           Path to parent private key (default: sidecar_key.pem)\n"
              << "  --validity HOURS     Credential validity in hours (default: 168 = 7 days)\n"
              << "  --help               Show this help message\n\n"
              << "The parent certificate must have the DelegatedCredential extension.\n"
              << "Use the generate_sidecar_cert utility to create a suitable certificate.\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    try {
        // Initialize crypto
        fizz::CryptoUtils::init();

        // Configuration with defaults
        int port = 8080;
        std::string certPath = "sidecar_cert.pem";
        std::string keyPath = "sidecar_key.pem";
        int validityHours = 168; // 7 days

        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
            std::string arg(argv[i]);

            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            } else if (arg == "--port" && i + 1 < argc) {
                port = std::atoi(argv[++i]);
            } else if (arg == "--cert" && i + 1 < argc) {
                certPath = argv[++i];
            } else if (arg == "--key" && i + 1 < argc) {
                keyPath = argv[++i];
            } else if (arg == "--validity" && i + 1 < argc) {
                validityHours = std::atoi(argv[++i]);
            } else {
                std::cerr << "Unknown option: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }

        std::cout << "=== Tahini Sidecar - Delegated Credential Manager ===" << std::endl;
        std::cout << "\nConfiguration:" << std::endl;
        std::cout << "  Port: " << port << std::endl;
        std::cout << "  Certificate: " << certPath << std::endl;
        std::cout << "  Private Key: " << keyPath << std::endl;
        std::cout << "  Credential Validity: " << validityHours << " hours\n" << std::endl;

        // Load parent certificate and key
        std::cout << "Loading parent certificate and key..." << std::endl;

        auto cert = loadCertificate(certPath);
        auto key = loadPrivateKey(keyPath);

        // Verify the certificate has delegated credential extension
        try {
            fizz::extensions::DelegatedCredentialUtils::checkExtensions(cert);
            std::cout << "✓ Certificate has required DelegatedCredential extension" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "\n ERROR: Certificate does not support delegated credentials!" << std::endl;
            std::cerr << "        " << e.what() << std::endl;
            std::cerr << "\n  Please use the generate_sidecar_cert utility to create a proper certificate.\n" << std::endl;
            return 1;
        }

        // Create certificate vector for OpenSSLSelfCertImpl
        std::vector<folly::ssl::X509UniquePtr> certChain;
        certChain.push_back(std::move(cert));

        // Load key again for CredentialManager (needs separate ownership)
        auto keyForManager = loadPrivateKey(keyPath);

        // Create parent cert object
        auto parentCert = std::make_shared<fizz::openssl::OpenSSLSelfCertImpl<fizz::openssl::KeyType::P256>>(
            std::move(key),
            std::move(certChain));

        std::cout << "✓ Parent certificate loaded successfully" << std::endl;
        std::cout << "  Identity: " << parentCert->getIdentity() << std::endl;

        // Create credential manager
        auto credentialManager = std::make_shared<sidecar::CredentialManager>(
            parentCert,
            std::move(keyForManager),
            std::chrono::hours(validityHours));

        std::cout << "✓ Credential manager initialized" << std::endl;

        // Create HTTPS server
        g_server = std::make_unique<sidecar::HTTPServer>(
            port,
            credentialManager,
            certPath,
            keyPath);

        // Set up signal handlers
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        std::cout << "\n=== Sidecar Ready ===" << std::endl;
        std::cout << "\nEndpoints:" << std::endl;
        std::cout << "  POST https://localhost:" << port << "/register" << std::endl;
        std::cout << "       Request:  {\"serviceName\": \"<name>\"}" << std::endl;
        std::cout << "       Response: Credential generation confirmation" << std::endl;
        std::cout << "\n  GET  https://localhost:" << port << "/verify?service=<name>" << std::endl;
        std::cout << "       Response: Public verification info for service" << std::endl;
        std::cout << "\nPress Ctrl+C to stop\n" << std::endl;

        // Start server (blocking)
        g_server->start();

        std::cout << "Sidecar stopped" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\nFatal error: " << e.what() << std::endl;
        std::cerr << "\nRun with --help for usage information." << std::endl;
        return 1;
    }
}
