/*
 * certificates_ffi.h
 *
 * FFI wrapper for certificate loading and management operations.
 * This header is included by the CXX bridge.
 */

#pragma once

#define GLOG_USE_GLOG_EXPORT

// Include glog before folly to satisfy its requirements
#include <glog/logging.h>

#include <folly/ssl/OpenSSLPtrTypes.h>
#include <memory>
#include <string>
#include <cstdint>

// Forward declare shared struct from bridge
// (Full definitions will be available when bridge.rs.h is included)
struct CertificateData;
struct CertificatePublic;

// Opaque type for private keys
// Full definition is required for CXX UniquePtr operations
struct FizzPrivateKey {
    folly::ssl::EvpPkeyUniquePtr key;
};

// Include function declarations (uses forward-declared rust:: types)
#include "ffi/bridge_decl.h"
