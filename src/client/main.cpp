/*
 * main.cpp - Client entry point
 *
 * TLS client that connects to servers using delegated credentials
 * and verifies them using information from the sidecar.
 */

#include "TLSClient.h"

#include <iostream>
#include <memory>
#include <string>
#include <cstring>
#include <csignal>

// Global client pointer for signal handling
client::TLSClient* g_client = nullptr;

void showHelp(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n"
              << "\n"
              << "TLS client that verifies delegated credentials\n"
              << "\n"
              << "Required Options:\n"
              << "  --service NAME         Service name to connect to\n"
              << "  --server-host HOST     Server hostname/IP\n"
              << "\n"
              << "Optional Options:\n"
              << "  --server-port PORT     Server port (default: 9090)\n"
              << "  --sidecar-host HOST    Sidecar hostname/IP (default: localhost)\n"
              << "  --sidecar-port PORT    Sidecar HTTPS port (default: 8080)\n"
              << "  --sidecar-cert PATH    Path to sidecar CA certificate (default: sidecar_cert.pem)\n"
              << "  --help, -h             Show this help message\n"
              << "\n"
              << "Example:\n"
              << "  " << programName << " --service my-service --server-host localhost --server-port 9090\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    // Default configuration
    std::string serviceName;
    std::string serverHost;
    int serverPort = 9090;
    std::string sidecarHost = "localhost";
    int sidecarPort = 8080;
    std::string sidecarCertPath = "sidecar_cert.pem";

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            showHelp(argv[0]);
            return 0;
        } else if (arg == "--service" && i + 1 < argc) {
            serviceName = argv[++i];
        } else if (arg == "--server-host" && i + 1 < argc) {
            serverHost = argv[++i];
        } else if (arg == "--server-port" && i + 1 < argc) {
            serverPort = std::stoi(argv[++i]);
        } else if (arg == "--sidecar-host" && i + 1 < argc) {
            sidecarHost = argv[++i];
        } else if (arg == "--sidecar-port" && i + 1 < argc) {
            sidecarPort = std::stoi(argv[++i]);
        } else if (arg == "--sidecar-cert" && i + 1 < argc) {
            sidecarCertPath = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            std::cerr << "Use --help for usage information" << std::endl;
            return 1;
        }
    }

    // Validate required arguments
    if (serviceName.empty()) {
        std::cerr << "Error: --service is required" << std::endl;
        std::cerr << "Use --help for usage information" << std::endl;
        return 1;
    }

    if (serverHost.empty()) {
        std::cerr << "Error: --server-host is required" << std::endl;
        std::cerr << "Use --help for usage information" << std::endl;
        return 1;
    }

    try {
        std::cout << "=== Tahini TLS Client ===" << std::endl;
        std::cout << "Service:      " << serviceName << std::endl;
        std::cout << "Server:       " << serverHost << ":" << serverPort << std::endl;
        std::cout << "Sidecar:      " << sidecarHost << ":" << sidecarPort << std::endl;
        std::cout << "Sidecar Cert: " << sidecarCertPath << std::endl;
        std::cout << std::endl;

        // Create client
        auto client = std::make_unique<client::TLSClient>(
            sidecarHost,
            sidecarPort,
            sidecarCertPath
        );

        g_client = client.get();

        // Step 1: Get verification info from sidecar
        std::cout << "Step 1: Querying sidecar for verification information..." << std::endl;
        if (!client->getVerificationInfo(serviceName)) {
            std::cerr << "Failed to get verification info from sidecar" << std::endl;
            return 1;
        }
        std::cout << std::endl;

        // Step 2: Connect to server and verify credentials
        std::cout << "Step 2: Connecting to server and verifying credentials..." << std::endl;
        if (!client->connectToServer(serverHost, serverPort, serviceName)) {
            std::cerr << "Failed to connect to server or verify credentials" << std::endl;
            return 1;
        }
        std::cout << std::endl;

        std::cout << "=== Connection Successful ===" << std::endl;
        std::cout << "Successfully connected to server with verified delegated credentials!" << std::endl;

        // For now, just exit after successful connection
        // In a real application, you would send/receive data here

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
