#include "crypto_utils.h"

#include <iomanip>

namespace sidecar {

// Generate a new random private key (needs to use the same algorithm and
// configuration as the parent certficate key).
folly::ssl::EvpPkeyUniquePtr generateKeyPair() {
  // Generate a P-256 EC key for the delegated credential
  // Note: Must match parent certificate key type due to Fizz library limitation
  folly::ssl::EvpPkeyUniquePtr pkey(EVP_PKEY_new());
  folly::ssl::EcGroupUniquePtr group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  folly::ssl::EcKeyUniquePtr ecKey(EC_KEY_new());

  if (!pkey || !group || !ecKey) {
    throw std::runtime_error("Failed to create key structures");
  }

  EC_GROUP_set_asn1_flag(group.get(), OPENSSL_EC_NAMED_CURVE);
  EC_GROUP_set_point_conversion_form(group.get(),
                                     POINT_CONVERSION_UNCOMPRESSED);

  if (EC_KEY_set_group(ecKey.get(), group.get()) != 1) {
    throw std::runtime_error("Failed to set EC group");
  }

  if (EC_KEY_generate_key(ecKey.get()) != 1) {
    throw std::runtime_error("Failed to generate EC key");
  }

  if (EVP_PKEY_set1_EC_KEY(pkey.get(), ecKey.get()) != 1) {
    throw std::runtime_error("Failed to assign EC key to EVP_PKEY");
  }

  return pkey;
}

// Serialize Public Key in DER format.
std::string publicKeyToDer(const folly::ssl::EvpPkeyUniquePtr& pkey) {
  int derLen = i2d_PUBKEY(pkey.get(), nullptr);
  if (derLen < 0) {
    throw std::runtime_error("Failed to get DER length");
  }

  std::vector<unsigned char> derData(derLen);
  unsigned char* derPtr = derData.data();

  if (i2d_PUBKEY(pkey.get(), &derPtr) < 0) {
    throw std::runtime_error("Failed to convert public key to DER");
  }

  // Convert to hex string for easier transmission
  std::ostringstream hexStream;
  hexStream << std::hex << std::setfill('0');
  for (unsigned char byte : derData) {
    hexStream << std::setw(2) << static_cast<int>(byte);
  }

  return hexStream.str();
}

}  // namespace sidecar
