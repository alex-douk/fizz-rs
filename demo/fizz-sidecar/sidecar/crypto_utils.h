#ifndef SIDECAR_CRYPTO_UTILS_H_
#define SIDECAR_CRYPTO_UTILS_H_

#include <folly/ssl/OpenSSLPtrTypes.h>

#include <string>

namespace sidecar {

// Generate a new random private key (needs to use the same algorithm and
// configuration as the parent certficate key).
folly::ssl::EvpPkeyUniquePtr generateKeyPair();

// Serialize Public Key part of a key pair in DER format.
std::string publicKeyToDer(const folly::ssl::EvpPkeyUniquePtr& pkey);

}  // namespace sidecar

#endif  // SIDECAR_CRYPTO_UTILS_H_
