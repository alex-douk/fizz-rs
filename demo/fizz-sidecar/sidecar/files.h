#ifndef SIDECAR_FILES_H_
#define SIDECAR_FILES_H_

#include <folly/ssl/OpenSSLPtrTypes.h>

#include <string>

namespace sidecar {

folly::ssl::X509UniquePtr loadCertificate(const std::string &certPath);
folly::ssl::EvpPkeyUniquePtr loadPrivateKey(const std::string &keyPath);

}  // namespace sidecar

#endif  // SIDECAR_FILES_H_
