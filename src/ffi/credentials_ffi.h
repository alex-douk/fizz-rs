/*
 * credentials_ffi.h
 *
 * FFI wrapper for delegated credential generation and verification.
 * This header is included by the CXX bridge.
 */

#pragma once

#define GLOG_USE_GLOG_EXPORT

// Include glog before folly to satisfy its requirements
#include <glog/logging.h>

#include <fizz/protocol/Certificate.h>
#include <folly/ssl/OpenSSLPtrTypes.h>
#include <memory>
#include <string>
#include <cstdint>
#include <chrono>

// Forward declare shared structs from bridge
// (Full definitions will be available when bridge.rs.h is included)
struct CertificateData;
struct ServiceCredential;
struct VerificationInfo;

// Opaque type for credential generator
// Full definition is required for CXX UniquePtr operations
struct FizzCredentialGenerator {
    std::shared_ptr<fizz::SelfCert> parentCert;
    folly::ssl::EvpPkeyUniquePtr parentKey;
    std::chrono::seconds validitySeconds;
};

// Include function declarations (uses forward-declared rust:: types)
#include "ffi/bridge_decl.h"
