#include <memory>
#include <iostream>
#include <fstream>
#include <string>
#include <utility>

#include "files.h"
#include "credential.h"
#include "nlohmann/json.hpp"

int main(int argc, char* argv[]) {
    // Read certificate and key
    folly::ssl::X509UniquePtr certificate = sidecar::loadCertificate("fizz.crt");
    folly::ssl::EvpPkeyUniquePtr key = sidecar::loadPrivateKey("fizz.key");
    
    // Verify the certificate has delegated credential extension
    fizz::extensions::DelegatedCredentialUtils::checkExtensions(certificate);
    
    // Create certificate vector for OpenSSLSelfCertImpl
    std::vector<folly::ssl::X509UniquePtr> certChain;
    certChain.push_back(std::move(certificate));

    // Create parent certificate object
    auto parentCertificate = std::make_shared<fizz::openssl::OpenSSLSelfCertImpl<fizz::openssl::KeyType::P256>>(
        std::move(key), std::move(certChain));

    // Load key again.
    key = sidecar::loadPrivateKey("fizz.key");

    // How long to make the delegation valid for.
    std::chrono::seconds validitySeconds = std::chrono::hours(24 * 7);
    
    // Generate delegated credential
    auto [serverCredential, clientVerificationInfo] = sidecar::generateDelegatedCredential(
        std::move(parentCertificate),
        std::move(key),
        validitySeconds);
        
    // serialize server.
    nlohmann::json serverJson = nlohmann::json::object({
        {"signatureScheme", serverCredential.signatureScheme},
        {"credentialPEM", serverCredential.credentialPEM}
    });
        
    std::ofstream server_file("/tmp/fizz_server.json");
    server_file << serverJson.dump(2) << std::endl;
    server_file.close();

    // Serialize client.    
    nlohmann::json clientJson = nlohmann::json::object({
        {"service_name", ""},
        {"valid_time", 0},    
        {"expected_verify_scheme", clientVerificationInfo.verifyScheme},
        {"public_key_der", clientVerificationInfo.publicKeyDer},
        {"expires_at", 0}
    });
    
    std::ofstream client_file("/tmp/fizz_client.json");
    client_file << clientJson.dump(2) << std::endl;
    client_file.close();

    return 0;
}
