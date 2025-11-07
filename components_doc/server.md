# Server Component API Documentation

## Overview

The server component is a TLS 1.3 server that registers with the sidecar to obtain delegated credentials for serving client connections. It implements an HTTPS client to communicate with the sidecar for credential registration, and uses the Fizz TLS library to serve clients with delegated credentials.

**Status:** ✅ **FULLY FUNCTIONAL** - Successfully presents delegated credentials to clients

**Namespace:** `server`

**Transport Protocol (to Sidecar):** HTTPS (SSL/TLS encrypted)

**Transport Protocol (to Clients):** TLS 1.3 via Fizz library

**Default Server Port:** 9090

**Default Sidecar Port:** 8080

## Initialization

### Command Line Interface

```bash
./server [OPTIONS]
```

**Options:**
- `--name NAME`: Service name (required)
- `--port PORT`: Server port to listen on (default: 9090)
- `--sidecar-host HOST`: Sidecar hostname/IP (default: localhost)
- `--sidecar-port PORT`: Sidecar HTTPS port (default: 8080)
- `--sidecar-cert PATH`: Path to sidecar CA certificate for HTTPS verification (default: sidecar_cert.pem)
- `--help`, `-h`: Show help message

**Requirements:**
- Service name must be provided via `--name` argument
- Sidecar CA certificate file must exist at the specified path for SSL verification
- Sidecar must be running and accessible at the specified host and port

**Initialization Sequence:**
1. Parse command line arguments
2. Validate required arguments (service name)
3. Create TLSServer instance with configuration
4. Set up signal handlers (SIGINT, SIGTERM)
5. Call `registerWithSidecar()` to obtain credentials
6. Start server on specified port (blocking)

**Exit Codes:**
- `0`: Successful execution
- `1`: Error (missing required arguments, registration failure, or runtime exception)

## C++ API

### `TLSServer` Class

**Purpose:** TLS server that registers with the sidecar and uses delegated credentials to serve clients.

#### Constructor

```cpp
TLSServer(const std::string& serviceName,
          int serverPort,
          const std::string& sidecarHost,
          int sidecarPort,
          const std::string& sidecarCertPath)
```

**Parameters:**
- `serviceName` (const std::string&): Name of this service for credential registration
- `serverPort` (int): Port for the TLS server to listen on
- `sidecarHost` (const std::string&): Sidecar hostname or IP address
- `sidecarPort` (int): Sidecar HTTPS port
- `sidecarCertPath` (const std::string&): Filesystem path to sidecar's CA certificate in PEM format

**Behavior:**
- Stores all configuration parameters
- Initializes OpenSSL library (loads error strings and algorithms)
- Sets initial server state to not running
- Initializes server socket to -1

**Notes:**
- Does not perform sidecar registration in constructor
- OpenSSL initialization is global and affects entire process

#### Destructor

```cpp
~TLSServer()
```

**Behavior:**
- Calls `stop()` to ensure clean shutdown
- Closes any open server socket

#### `bool registerWithSidecar()`

Registers with the sidecar and obtains delegated credentials.

**Returns:** bool
- `true`: Registration successful, credentials received and stored
- `false`: Registration failed (connection error or invalid response)

**Behavior:**
1. Prints registration attempt message to stdout
2. Constructs JSON request body with service name:
   ```json
   {"serviceName": "<serviceName>"}
   ```
3. Calls `makeHTTPSRequest()` with POST method to `/register` endpoint
4. If HTTPS request fails, prints error to stderr and returns false
5. Parses response using `parseRegistrationResponse()`
6. If parsing fails, prints error to stderr and returns false
7. Prints success message and credential details to stdout:
   - Service name
   - Valid time (seconds)
   - Signature scheme
8. Returns true

**Error Handling:**
- Prints "Failed to connect to sidecar" to stderr on connection failure
- Prints "Failed to parse sidecar response" to stderr on parsing failure

**Side Effects:**
- Updates internal `credentialInfo_` structure with received credential data
- Sets `credentialInfo_.receivedAt` to current system time

#### `void start()`

Starts the TLS 1.3 server using Fizz library (blocking call).

**Behavior:**
- Creates Folly EventBase for asynchronous I/O
- Creates TCP server socket bound to specified port
- Creates Fizz server context configured with:
  - Delegated credentials from sidecar (loaded from PEM)
  - Supported cipher suites (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)
  - Supported signature schemes (ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, etc.)
  - Certificate verifier with sidecar CA certificate
- Accepts client connections in a loop
- For each client:
  - Creates AsyncFizzServer instance
  - Performs TLS 1.3 handshake with delegated credential
  - Handles data exchange
  - Logs handshake success and cipher suite used
- Outputs comprehensive diagnostic logging showing credential details
- Returns when `stop()` is called

**Blocking:** This call blocks until `stop()` is called from another thread or signal handler

#### `void stop()`

Stops the TLS server.

**Behavior:**
- Sets `running_` atomic flag to false
- If `serverSocket_` is valid (>= 0):
  - Closes the server socket
  - Sets `serverSocket_` to -1

**Thread Safety:** Safe to call from signal handlers or other threads due to atomic `running_` flag

**Side Effects:**
- Causes `start()` to exit its loop and return

#### `bool isRunning() const`

Checks if server is running.

**Returns:** bool
- `true`: Server is currently running
- `false`: Server is stopped

**Thread Safety:** Thread-safe (reads atomic variable)

#### `const DelegatedCredentialInfo& getCredentialInfo() const`

Returns credential information received from sidecar.

**Returns:** const DelegatedCredentialInfo& - Reference to stored credential information

**Notes:**
- Returns reference to internal structure
- Credential info is populated by `registerWithSidecar()`
- May contain default values if registration has not been performed

#### `bool hasValidCredentials() const`

Checks if credentials are valid (received and not expired).

**Returns:** bool
- `true`: Credentials exist and have not expired
- `false`: No credentials or credentials have expired

**Validation Logic:**
1. Returns false if `serviceName` is empty
2. Returns false if `validTime` is 0
3. Calculates elapsed time since `receivedAt` timestamp
4. Returns true if elapsed time < `validTime`, false otherwise

**Thread Safety:** Thread-safe (const method, reads only)

### `DelegatedCredentialInfo` Structure

**Purpose:** Container for credential information received from the sidecar.

**Public Members:**
- `serviceName` (std::string): The service name this credential is for
- `validTime` (uint32_t): Validity period in seconds
- `signatureScheme` (uint16_t): Signature scheme used for the credential
- `receivedAt` (std::chrono::system_clock::time_point): Timestamp when credential was received

#### Default Constructor

```cpp
DelegatedCredentialInfo()
```

**Behavior:**
- Sets `validTime` to 0
- Sets `signatureScheme` to 0
- Sets `receivedAt` to current system time

## HTTPS Client Functionality

The TLSServer includes internal HTTPS client functionality for communicating with the sidecar.

### Private Method: `bool makeHTTPSRequest(...)`

```cpp
bool makeHTTPSRequest(
    const std::string& method,
    const std::string& path,
    const std::string& body,
    std::string& responseBody)
```

**Parameters:**
- `method` (const std::string&): HTTP method (e.g., "POST", "GET")
- `path` (const std::string&): URL path (e.g., "/register")
- `body` (const std::string&): Request body content
- `responseBody` (std::string&): Output parameter for response body

**Returns:** bool
- `true`: Request successful, responseBody populated
- `false`: Request failed

**Behavior:**
1. Creates TCP socket (AF_INET, SOCK_STREAM)
2. Resolves sidecar hostname using `gethostbyname()`
3. Connects to sidecar on specified port
4. Creates SSL context via `createClientSSLContext()`
5. Creates SSL object and attaches to socket
6. Performs SSL handshake via `SSL_connect()`
7. Builds HTTP request:
   ```
   <method> <path> HTTP/1.1\r\n
   Host: <sidecarHost>\r\n
   Content-Type: application/json\r\n
   Content-Length: <bodyLength>\r\n
   Connection: close\r\n
   \r\n
   <body>
   ```
8. Sends request via `SSL_write()`
9. Reads response via `SSL_read()` in 4096-byte chunks
10. Extracts response body (content after "\r\n\r\n")
11. Performs SSL shutdown via `SSL_shutdown()`
12. Frees SSL resources and closes socket
13. Returns success/failure status

**Error Handling:**
- Prints error messages to stderr for:
  - Socket creation failure
  - Hostname resolution failure
  - Connection failure
  - SSL context creation failure
  - SSL object creation failure
  - SSL handshake failure
  - Request send failure
- All OpenSSL errors are printed using `ERR_print_errors_fp(stderr)`
- Exceptions are caught and logged, function returns false

**Cleanup:**
- SSL object always freed if created
- SSL context always freed if created
- Socket always closed

### Private Method: `SSL_CTX* createClientSSLContext()`

Creates SSL context for HTTPS client connections.

**Returns:** SSL_CTX* - Pointer to SSL context

**Throws:** std::runtime_error if:
- SSL context creation fails
- CA certificate file cannot be loaded
- Private key check fails

**Behavior:**
1. Creates SSL context using `TLS_client_method()`
2. Loads CA certificate from `sidecarCertPath_` using `SSL_CTX_load_verify_locations()`
3. Sets verify mode to `SSL_VERIFY_PEER` (requires certificate verification)
4. Returns SSL context pointer

**SSL Configuration:**
- **Method:** `TLS_client_method()` - Supports all TLS client versions
- **Verification:** Peer certificate verification required
- **CA Certificate:** Loaded from file specified in constructor

**Error Output:**
- OpenSSL errors printed to stderr using `ERR_print_errors_fp()`

### Private Method: `bool parseRegistrationResponse(...)`

```cpp
bool parseRegistrationResponse(const std::string& response)
```

**Parameters:**
- `response` (const std::string&): JSON response body from sidecar

**Returns:** bool
- `true`: Response successfully parsed and credentials extracted
- `false`: Response parsing failed or required fields missing

**Expected Response Format:**
```json
{
  "status": "success",
  "serviceName": "<serviceName>",
  "validTime": <validTimeSeconds>,
  "signatureScheme": <schemeNumber>
}
```

**Parsing Logic:**
- Uses simple string searching (does not use a JSON library)
- Checks for presence of `"status"` and `"success"` substrings
- Extracts `serviceName` by finding field name, colon, and quoted string value
- Extracts `validTime` by finding field name, colon, and decimal digits
- Extracts `signatureScheme` by finding field name, colon, and decimal digits
- Converts numeric strings to integers using `std::stoul()`
- Sets `credentialInfo_.receivedAt` to current system time

**Validation:**
- Returns false if:
  - Response does not contain both `"status"` and `"success"`
  - `serviceName` is empty after parsing
  - `validTime` is 0 after parsing

**Side Effects:**
- Updates `credentialInfo_.serviceName`
- Updates `credentialInfo_.validTime`
- Updates `credentialInfo_.signatureScheme`
- Updates `credentialInfo_.receivedAt`

## Sidecar Communication Protocol

### Registration Endpoint: `POST /register`

**Sidecar Endpoint:** `POST https://<sidecarHost>:<sidecarPort>/register`

**Request Headers:**
```
Host: <sidecarHost>
Content-Type: application/json
Content-Length: <bodyLength>
Connection: close
```

**Request Body:**
```json
{
  "serviceName": "<serviceName>"
}
```

**Expected Response (200 OK):**
```json
{
  "status": "success",
  "serviceName": "<serviceName>",
  "message": "Delegated credential generated successfully",
  "validTime": <validTimeSeconds>,
  "signatureScheme": <schemeNumber>
}
```

**Response Fields Used by Server:**
- `status` (string): Must be "success" for successful parsing
- `serviceName` (string): Service name confirmation
- `validTime` (number): Validity period in seconds
- `signatureScheme` (number): Signature scheme identifier (uint16_t)

**SSL/TLS:**
- Connection uses SSL/TLS encryption
- Server verifies sidecar certificate using CA certificate from `--sidecar-cert`
- Verification mode: `SSL_VERIFY_PEER` (strict certificate checking)

## Signal Handling

The server registers signal handlers for graceful shutdown:

**Signals Handled:**
- `SIGINT` (Ctrl+C)
- `SIGTERM`

**Signal Handler Behavior:**
1. Prints shutdown message to stdout
2. Calls `g_server->stop()` on global server instance
3. Causes `start()` to exit and main() to return

**Signal Handler Implementation:**
```cpp
void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nShutting down server..." << std::endl;
        if (g_server) {
            g_server->stop();
        }
    }
}
```

**Registration:**
- Handlers registered using `std::signal()` before calling `start()`
- Global `g_server` pointer provides access from signal handler context

## Usage Examples

### Basic Server Startup

```bash
./server --name my-service --port 9090 --sidecar-host localhost --sidecar-port 8080 --sidecar-cert /path/to/sidecar_cert.pem
```

### Programmatic Usage

```cpp
#include "TLSServer.h"
#include <memory>

int main() {
    // Create server instance
    auto server = std::make_unique<server::TLSServer>(
        "my-service",           // serviceName
        9090,                   // serverPort
        "localhost",            // sidecarHost
        8080,                   // sidecarPort
        "sidecar_cert.pem"      // sidecarCertPath
    );

    // Register with sidecar
    if (!server->registerWithSidecar()) {
        std::cerr << "Registration failed!" << std::endl;
        return 1;
    }

    // Check credentials
    if (!server->hasValidCredentials()) {
        std::cerr << "Invalid credentials!" << std::endl;
        return 1;
    }

    // Get credential info
    const auto& credInfo = server->getCredentialInfo();
    std::cout << "Valid time: " << credInfo.validTime << " seconds" << std::endl;
    std::cout << "Signature scheme: " << credInfo.signatureScheme << std::endl;

    // Start server (blocking)
    server->start();

    return 0;
}
```

### Checking Credential Validity

```cpp
server::TLSServer server("my-service", 9090, "localhost", 8080, "sidecar_cert.pem");

if (server.registerWithSidecar()) {
    const auto& cred = server.getCredentialInfo();

    std::cout << "Service: " << cred.serviceName << std::endl;
    std::cout << "Valid for: " << cred.validTime << " seconds" << std::endl;
    std::cout << "Signature scheme: " << cred.signatureScheme << std::endl;

    if (server.hasValidCredentials()) {
        std::cout << "Credentials are valid" << std::endl;
    } else {
        std::cout << "Credentials expired or invalid" << std::endl;
    }
}
```

## Integration Guidelines

### Sidecar Integration

**Prerequisites:**
1. Sidecar must be running and listening on HTTPS port (default: 8080)
2. Sidecar CA certificate must be available for SSL verification
3. Sidecar must have `/register` endpoint implemented

**Registration Flow:**
1. Server creates HTTPS connection to sidecar
2. Server verifies sidecar certificate using CA certificate
3. Server sends POST request to `/register` with service name
4. Sidecar generates delegated credential
5. Sidecar responds with credential metadata
6. Server parses and stores credential information

**Error Scenarios:**
- **Connection Failure:** Server cannot reach sidecar (network issue, wrong host/port)
- **SSL Verification Failure:** Sidecar certificate invalid or CA cert path wrong
- **Registration Failure:** Sidecar returns error or malformed response
- **Parse Failure:** Response does not match expected JSON format

### Client Integration

**Current State: FULLY IMPLEMENTED ✅**

The server successfully accepts and handles client TLS connections with delegated credentials:

**Connection Flow:**
1. Server listens on specified port for TLS connections
2. Client connects and initiates TLS 1.3 handshake
3. Server presents delegated credential during handshake
4. Client verifies parent certificate against sidecar's CA
5. Client verifies delegated credential signature and validity
6. TLS handshake completes successfully
7. Secure data exchange occurs

**Client Verification:**
- Clients query sidecar's `/verify` endpoint for verification information
- Clients verify both parent certificate and delegated credential
- Clients validate signature scheme matches expected scheme (1027)
- Clients check credential validity period

**Supported Features:**
- TLS 1.3 with Fizz library
- Delegated credential extension (RFC 9345)
- Multiple cipher suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- ECDSA signature schemes (P-256, P-384, P-521)

## Dependencies

### Fizz Library
- `fizz::server::AsyncFizzServer`: TLS 1.3 server implementation
- `fizz::server::FizzServerContext`: Server configuration and context
- `fizz::extensions::DelegatedCredentialUtils`: Delegated credential handling
- `fizz::DefaultCertificateVerifier`: Certificate chain verification
- `fizz::openssl::OpenSSLSelfCertImpl`: OpenSSL certificate implementation
- Cipher suite definitions (TLS_AES_128_GCM_SHA256, etc.)
- Signature scheme definitions (ecdsa_secp256r1_sha256, etc.)

### Folly Library
- `folly::EventBase`: Asynchronous I/O event loop
- `folly::AsyncServerSocket`: Asynchronous TCP server socket
- `folly::ssl::X509StoreUniquePtr`: Smart pointer for X509 store
- `folly::ssl::OpenSSLCertUtils`: Certificate utilities

### OpenSSL
- `SSL_CTX`: SSL context for client connections to sidecar
- `SSL`: Per-connection SSL state
- `SSL_load_error_strings()`: Error string initialization
- `OpenSSL_add_ssl_algorithms()`: Algorithm initialization
- `TLS_client_method()`: SSL method for client connections
- `SSL_CTX_load_verify_locations()`: CA certificate loading
- `SSL_CTX_set_verify()`: Certificate verification configuration
- `SSL_connect()`: Client-side SSL handshake
- `SSL_read()` / `SSL_write()`: SSL I/O operations
- `SSL_shutdown()`: SSL connection shutdown
- `ERR_print_errors_fp()`: Error reporting

### POSIX Sockets
- `socket()`: TCP socket creation
- `connect()`: TCP connection establishment
- `gethostbyname()`: Hostname resolution
- `close()`: Socket cleanup
- `struct sockaddr_in`: IPv4 address structure
- `struct hostent`: Host information structure

### C++ Standard Library
- `<memory>`: std::unique_ptr, std::shared_ptr
- `<string>`: std::string
- `<atomic>`: std::atomic for thread-safe flags
- `<chrono>`: Time points and durations
- `<sstream>`: String stream for building requests
- `<iostream>`: Console I/O
- `<csignal>`: Signal handling

## Diagnostic Features

### Credential Loading Diagnostics

The server outputs comprehensive diagnostic information when loading delegated credentials:

**Implementation** (src/server/TLSServer.cpp:390-402):
```cpp
std::cout << "[Server] Loaded delegated credential details:" << std::endl;
std::cout << "  Service: " << credentialInfo_.serviceName << std::endl;
std::cout << "  Valid time from sidecar: " << credentialInfo_.validTime << " seconds" << std::endl;
std::cout << "  Signature scheme from sidecar: " << credentialInfo_.signatureScheme << std::endl;
std::cout << "  Loaded credential_scheme (parent signs DC): "
          << static_cast<uint16_t>(credential.credential_scheme) << std::endl;
std::cout << "  Loaded expected_verify_scheme (DC signs handshake): "
          << static_cast<uint16_t>(credential.expected_verify_scheme) << std::endl;
std::cout << "  Loaded valid_time: " << credential.valid_time << " seconds" << std::endl;
```

**Output Example:**
```
[Server] Loaded delegated credential details:
  Service: test-service
  Valid time from sidecar: 607235 seconds
  Signature scheme from sidecar: 1027
  Loaded credential_scheme (parent signs DC): 1027
  Loaded expected_verify_scheme (DC signs handshake): 1027
  Loaded valid_time: 607235 seconds
```

**Information Logged:**
- Service name and validity duration from sidecar response
- Signature schemes from both sidecar metadata and loaded credential
- credential_scheme: Used by parent certificate to sign the DC (1027 = ecdsa_secp256r1_sha256)
- expected_verify_scheme: Used by DC to sign TLS handshake messages (1027)
- Validity time in seconds

## Verified Working End-to-End ✅

The server has been successfully tested and verified to work end-to-end with the sidecar and client components.

### Actual Test Output

From `server.log`:
```
=== Tahini TLS Server ===

Configuration:
  Service Name: test-service
  Server Port: 9090
  Sidecar: localhost:8080
  Sidecar CA Certificate: sidecar_cert.pem

=== Registering with Sidecar ===
Registering with sidecar at localhost:8080...
Successfully registered with sidecar!
  Service: test-service
  Valid time: 607235 seconds
  Signature scheme: 1027

=== Server Ready ===

Delegated credentials received from sidecar.
Server will listen on port 9090 for client connections.

Press Ctrl+C to stop

TLS server starting on port 9090...
Using delegated credentials from sidecar
  Service: test-service
  Valid time: 607235 seconds
  Signature scheme: 1027
Creating Fizz server context with delegated credentials...
Loading delegated credential from PEM...
Successfully loaded delegated credential
[Server] Loaded delegated credential details:
  Service: test-service
  Valid time from sidecar: 607235 seconds
  Signature scheme from sidecar: 1027
  Loaded credential_scheme (parent signs DC): 1027
  Loaded expected_verify_scheme (DC signs handshake): 1027
  Loaded valid_time: 607235 seconds
Fizz server context created successfully
Fizz TLS server listening on port 9090
Server is ready to accept connections with delegated credentials
Accepted connection from 127.0.0.1:39202
Starting TLS handshake with delegated credentials...
TLS handshake successful!
  Cipher: TLS_AES_128_GCM_SHA256
  Delegated credential was presented to client
```

**Key Success Indicators:**
- ✅ Registration with sidecar successful
- ✅ Delegated credentials loaded from PEM
- ✅ TLS server listening on port 9090
- ✅ Client connections accepted
- ✅ TLS 1.3 handshake successful with delegated credential
- ✅ Cipher suite negotiated (TLS_AES_128_GCM_SHA256)

## RFC 9345 Compliance

The server **FULLY implements** RFC 9345 requirements for credential holders:

- ✅ **Credential Acquisition**: Obtains delegated credentials from sidecar via HTTPS
- ✅ **Credential Storage**: Stores credentials in PEM format and loads them for serving
- ✅ **TLS Extension**: Presents delegated credentials during TLS 1.3 handshake
- ✅ **Signature Verification**: Uses DC's private key for handshake signatures
- ✅ **Certificate Chain**: Includes both parent certificate and delegated credential
- ✅ **Validity Checking**: Ensures credentials are within valid time period

## Implementation Notes

### TLS Server Implementation

**Fully Functional:** The server implements complete TLS 1.3 functionality using Facebook's Fizz library:
- Creates server socket and accepts client connections
- Performs TLS 1.3 handshakes with delegated credentials
- Presents delegated credential extension to clients
- Handles bidirectional data exchange
- Logs detailed handshake information

### Current Limitations

1. **Simple JSON Parsing:**
   - Uses basic string searching instead of JSON library
   - May fail on formatting variations
   - No support for escaped characters in strings
   - No validation of JSON structure

2. **No Credential Refresh:**
   - Credentials obtained once during registration
   - No automatic renewal when credentials expire
   - No periodic re-registration

3. **No Concurrent Connection Handling:**
   - HTTPS client makes synchronous, blocking requests to sidecar
   - No connection pooling or reuse for sidecar communication
   - Client connections handled sequentially (one at a time)

### Security Considerations

**SSL Certificate Verification:**
- Server strictly verifies sidecar certificate using provided CA certificate
- Verification mode: `SSL_VERIFY_PEER`
- Handshake fails if certificate verification fails

**Credential Storage:**
- Credentials stored in memory only
- No persistence to disk
- Credentials lost on server restart

**No Authentication:**
- Server does not authenticate itself to sidecar beyond SSL/TLS
- Service name is self-asserted, no cryptographic proof
