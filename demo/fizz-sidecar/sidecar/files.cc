#include "files.h"

#include <iostream>
#include <fstream>
#include <sstream>

namespace sidecar {

folly::ssl::X509UniquePtr loadCertificate(const std::string &certPath) {
  std::ifstream certFile(certPath);
  if (!certFile.good()) {
      throw std::runtime_error("Cannot open certificate file: " + certPath);
  }

  std::string certPem((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
  folly::ssl::BioUniquePtr bio(BIO_new_mem_buf(certPem.data(), certPem.size()));
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for certificate");
  }

  folly::ssl::X509UniquePtr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));

  if (!cert) {
    throw std::runtime_error("Failed to parse certificate from: " + certPath);
  }

  return cert;
}

folly::ssl::EvpPkeyUniquePtr loadPrivateKey(const std::string &keyPath) {
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

  folly::ssl::EvpPkeyUniquePtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!key) {
    throw std::runtime_error("Failed to parse private key from: " + keyPath);
  }

  return key;
}


}  // namespace sidecar
