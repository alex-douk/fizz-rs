cmake_minimum_required(VERSION 3.10)
project(tahini_cpp_fizz VERSION 1.0.0 LANGUAGES CXX)

# Add custom CMake modules to path
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Fizz dependencies (assumes system-wide installation)
find_package(folly REQUIRED)
find_package(glog REQUIRED)
find_package(Sodium REQUIRED)
find_package(fizz REQUIRED)

message(STATUS "Building Tahini C++ Fizz Project")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")

# ============================================================================
# Sidecar Components
# ============================================================================

# Credential Manager library
add_library(credential_manager
    src/sidecar/CredentialManager.cpp
)

target_include_directories(credential_manager PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(credential_manager
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
)

# HTTP Server library
add_library(http_server
    src/sidecar/HTTPServer.cpp
)

target_include_directories(http_server PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(http_server
    credential_manager
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
)

# Sidecar executable
add_executable(sidecar
    src/sidecar/main.cpp
)

target_include_directories(sidecar PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(sidecar
    credential_manager
    http_server
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
    Threads::Threads
)

# Certificate generation utility
add_executable(generate_sidecar_cert
    src/sidecar/generate_sidecar_cert.cpp
)

target_include_directories(generate_sidecar_cert PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(generate_sidecar_cert
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
)

# ============================================================================
# Server Components
# ============================================================================

# TLS Server library
add_library(tls_server
    src/server/TLSServer.cpp
)

target_include_directories(tls_server PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(tls_server
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
)

# Server executable
add_executable(server
    src/server/main.cpp
)

target_include_directories(server PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(server
    tls_server
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
    Threads::Threads
)

# ============================================================================
# Client Components
# ============================================================================

# TLS Client library
add_library(tls_client
    src/client/TLSClient.cpp
)

target_include_directories(tls_client PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(tls_client
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
)

# Client executable
add_executable(client
    src/client/main.cpp
)

target_include_directories(client PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(client
    tls_client
    fizz
    OpenSSL::SSL
    OpenSSL::Crypto
    Folly::folly
    Threads::Threads
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS sidecar generate_sidecar_cert server client
    RUNTIME DESTINATION bin
)

install(TARGETS credential_manager http_server tls_server tls_client
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# ============================================================================
# Print build summary
# ============================================================================

message(STATUS "")
message(STATUS "Tahini C++ Fizz Build Configuration:")
message(STATUS "  Sidecar:                 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/sidecar")
message(STATUS "  Certificate Generator:   ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/generate_sidecar_cert")
message(STATUS "  Server:                  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server")
message(STATUS "  Client:                  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/client")
message(STATUS "")
