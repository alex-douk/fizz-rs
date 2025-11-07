/*
 * main.cpp
 *
 * Server entry point - TLS server that registers with the sidecar
 * and uses delegated credentials to serve clients.
 */

#include "TLSServer.h"

#include <iostream>
#include <memory>
#include <csignal>
#include <string>

namespace {

// Global server instance for signal handling
std::unique_ptr<server::TLSServer> g_server;

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down server..." << std::endl;
        if (g_server) {
            g_server->stop();
        }
    }
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --name NAME              Service name (required)\n"
              << "  --port PORT              Server port to listen on (default: 9090)\n"
              << "  --sidecar-host HOST      Sidecar hostname/IP (default: localhost)\n"
              << "  --sidecar-port PORT      Sidecar HTTPS port (default: 8080)\n"
              << "  --sidecar-cert PATH      Path to sidecar CA certificate (default: sidecar_cert.pem)\n"
              << "  --help                   Show this help message\n\n"
              << "The server will:\n"
              << "  1. Connect to the sidecar via HTTPS\n"
              << "  2. Register its service name and receive delegated credentials\n"
              << "  3. Use these credentials to serve TLS connections to clients\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    try {
        // Configuration with defaults
        std::string serviceName;
        int serverPort = 9090;
        std::string sidecarHost = "localhost";
        int sidecarPort = 8080;
        std::string sidecarCertPath = "sidecar_cert.pem";

        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
            std::string arg(argv[i]);

            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            } else if (arg == "--name" && i + 1 < argc) {
                serviceName = argv[++i];
            } else if (arg == "--port" && i + 1 < argc) {
                serverPort = std::atoi(argv[++i]);
            } else if (arg == "--sidecar-host" && i + 1 < argc) {
                sidecarHost = argv[++i];
            } else if (arg == "--sidecar-port" && i + 1 < argc) {
                sidecarPort = std::atoi(argv[++i]);
            } else if (arg == "--sidecar-cert" && i + 1 < argc) {
                sidecarCertPath = argv[++i];
            } else {
                std::cerr << "Unknown option: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }

        // Validate required arguments
        if (serviceName.empty()) {
            std::cerr << "Error: Service name is required (--name)\n" << std::endl;
            printUsage(argv[0]);
            return 1;
        }

        std::cout << "=== Tahini TLS Server ===" << std::endl;
        std::cout << "\nConfiguration:" << std::endl;
        std::cout << "  Service Name: " << serviceName << std::endl;
        std::cout << "  Server Port: " << serverPort << std::endl;
        std::cout << "  Sidecar: " << sidecarHost << ":" << sidecarPort << std::endl;
        std::cout << "  Sidecar CA Certificate: " << sidecarCertPath << "\n" << std::endl;

        // Create TLS server
        g_server = std::make_unique<server::TLSServer>(
            serviceName,
            serverPort,
            sidecarHost,
            sidecarPort,
            sidecarCertPath);

        // Set up signal handlers
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        // Register with sidecar
        std::cout << "=== Registering with Sidecar ===" << std::endl;
        if (!g_server->registerWithSidecar()) {
            std::cerr << "\nFailed to register with sidecar!" << std::endl;
            std::cerr << "Make sure the sidecar is running and accessible at "
                      << sidecarHost << ":" << sidecarPort << std::endl;
            return 1;
        }

        std::cout << "\n=== Server Ready ===" << std::endl;
        std::cout << "\nDelegated credentials received from sidecar." << std::endl;
        std::cout << "Server will listen on port " << serverPort
                  << " for client connections." << std::endl;
        std::cout << "\nPress Ctrl+C to stop\n" << std::endl;

        // Start server (blocking)
        g_server->start();

        std::cout << "Server stopped" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\nFatal error: " << e.what() << std::endl;
        std::cerr << "\nRun with --help for usage information." << std::endl;
        return 1;
    }
}
