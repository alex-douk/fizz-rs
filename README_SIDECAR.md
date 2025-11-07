# Tahini Sidecar - Delegated Credential Manager

The sidecar is a certificate manager that generates and manages delegated credentials for TLS servers according to RFC 9345.

## Overview

The sidecar implements the following workflow:

1. **Initialization**: Loads a parent certificate with the DelegatedCredential extension and sets up HTTPS endpoints
2. **Server Registration**: Servers register with the sidecar via HTTPS and receive delegated credentials
3. **Client Verification**: Clients query the sidecar via HTTPS for public verification information

## Components

### 1. `generate_sidecar_cert`
Utility to generate the parent certificate with required extensions.

**Features:**
- Generates self-signed certificate with DelegatedCredential extension (OID: 1.3.6.1.4.1.44363.44)
- Creates EC P-256 key pair
- Adds CA capabilities for signing delegated credentials
- Outputs stable PEM files for distribution

### 2. `sidecar`
Main sidecar service that manages delegated credentials.

**Features:**
- HTTPS API for secure server registration and client verification
- Thread-safe credential storage
- Automatic credential generation using Fizz library
- Configurable credential validity period
- SSL/TLS encryption for all endpoints

## Building

### Prerequisites

- CMake 3.10 or higher
- C++17 compiler
- OpenSSL
- Folly library
- Fizz library (included in `fizz/` directory)

### Build Instructions

```bash
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build
make

# Executables will be in build/bin/
# - generate_sidecar_cert
# - sidecar
```

## Usage

### Step 1: Generate Parent Certificate

Before running the sidecar, generate the parent certificate:

```bash
./bin/generate_sidecar_cert --cert sidecar_cert.pem --key sidecar_key.pem --cn "sidecar.tahini.local"
```

**Options:**
- `--cert PATH` : Output certificate path (default: sidecar_cert.pem)
- `--key PATH` : Output private key path (default: sidecar_key.pem)
- `--cn NAME` : Common Name for the certificate (default: sidecar.tahini.local)
- `--days DAYS` : Certificate validity in days (default: 365)

**Output:**
- `sidecar_cert.pem` : Parent certificate (distribute to clients)
- `sidecar_key.pem` : Private key (keep secure)

### Step 2: Start the Sidecar

```bash
./bin/sidecar --cert sidecar_cert.pem --key sidecar_key.pem --port 8080
```

**Options:**
- `--cert PATH` : Path to parent certificate (default: sidecar_cert.pem)
- `--key PATH` : Path to parent private key (default: sidecar_key.pem)
- `--port PORT` : HTTPS server port (default: 8080)
- `--validity HOURS` : Credential validity in hours (default: 168 = 7 days)

The sidecar will verify the certificate has the required DelegatedCredential extension and start the HTTPS server. The same certificate and key used for signing delegated credentials are also used for HTTPS.

## API Endpoints

### POST /register

Server registers and receives delegated credentials.

**Request:**
```json
{
  "serviceName": "my-service"
}
```

**Response:**
```json
{
  "status": "success",
  "serviceName": "my-service",
  "message": "Delegated credential generated successfully",
  "validTime": 604800,
  "signatureScheme": 2052
}
```

**Example:**
```bash
curl -X POST https://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"serviceName": "my-service"}' \
  --cacert sidecar_cert.pem
```

### GET /verify?service=<name>

Client retrieves public verification information for a service.

**Response:**
```json
{
  "serviceName": "my-service",
  "validTime": 604800,
  "expectedVerifyScheme": 2052,
  "publicKeyDer": "3059301306072a8648ce3d020106082a8648ce3d03010703420004...",
  "expiresAt": 1234567890
}
```

**Example:**
```bash
curl https://localhost:8080/verify?service=my-service \
  --cacert sidecar_cert.pem
```

## RFC 9345 Implementation

The sidecar leverages Fizz's built-in RFC 9345 support:

- **DelegatedCredentialUtils::generateCredential()**: Creates delegated credentials
- **DelegatedCredential struct**: Stores credential data (valid_time, public_key, signature)
- **Signature schemes**: Supports P256, P384, P521, RSA, ED25519
- **Lifetime validation**: Max 7 days as per RFC 9345

### Credential Structure

Each generated credential contains:
- `valid_time`: Validity period in seconds
- `expected_verify_scheme`: Signature algorithm for credential verification
- `public_key`: DER-encoded public key of the delegated credential
- `credential_scheme`: Signature algorithm used to sign the credential
- `signature`: Signature over the credential by the parent certificate

## Architecture

### CredentialManager

Thread-safe manager for delegated credentials:

```cpp
class CredentialManager {
public:
    // Generate credential for a service
    std::shared_ptr<ServiceCredential> generateCredentialForService(
        const std::string& serviceName);

    // Retrieve existing credential
    std::shared_ptr<ServiceCredential> getCredential(
        const std::string& serviceName);

    // Get public verification info (safe for clients)
    std::string getPublicVerificationInfo(
        const std::string& serviceName);
};
```

### HTTPServer

Simple HTTPS server handling registration and verification:

```cpp
class HTTPServer {
public:
    HTTPServer(int port,
               std::shared_ptr<CredentialManager> credentialManager,
               const std::string& certPath,
               const std::string& keyPath);

    void start();  // Blocking call
    void stop();
};
```

## Security Considerations

1. **Parent Certificate Protection**:
   - Keep `sidecar_key.pem` secure and access-controlled
   - The parent certificate signs all delegated credentials
   - Compromise of parent key compromises all delegated credentials

2. **Certificate Distribution**:
   - Distribute `sidecar_cert.pem` (public certificate) to clients
   - Clients use this to verify delegated credentials
   - Certificate must be obtained through a trusted channel

3. **Credential Lifetime**:
   - Default: 7 days (RFC 9345 maximum)
   - Shorter lifetimes reduce exposure window
   - Configure via `--validity` parameter

4. **HTTPS Security**:
   - All endpoints use HTTPS with TLS encryption
   - The same certificate used for signing delegated credentials is used for HTTPS
   - Clients must verify the server certificate using the sidecar's certificate as CA
   - Use `--cacert sidecar_cert.pem` with curl or equivalent verification in production clients

## Integration with Server and Client

### Server Integration (Future)

The server will:
1. Connect to sidecar HTTPS endpoint
2. POST to `/register` with its service name
3. Receive delegated credential information
4. Use the credential for TLS handshakes

### Client Integration (Future)

The client will:
1. GET verification info from `/verify?service=<name>` via HTTPS
2. Connect to server via TLS
3. Receive delegated credential in TLS handshake
4. Verify using parent certificate and public key info

## Files Created

```
cpp_fizz_proto/
├── CMakeLists.txt                     # Build configuration
├── README_SIDECAR.md                  # This file
├── include/
│   ├── CredentialManager.h            # Credential management interface
│   └── HTTPServer.h                   # HTTP server interface
├── src/sidecar/
│   ├── CredentialManager.cpp          # Credential management implementation
│   ├── HTTPServer.cpp                 # HTTP server implementation
│   ├── main.cpp                       # Sidecar entry point
│   └── generate_sidecar_cert.cpp      # Certificate generation utility
├── sidecar_cert.pem                   # Generated parent certificate
└── sidecar_key.pem                    # Generated private key
```

## Troubleshooting

### Certificate missing DelegatedCredential extension

```
ERROR: Certificate does not support delegated credentials!
```

**Solution**: Use `generate_sidecar_cert` to create a proper certificate.

### Port already in use

```
Failed to bind socket to port 8080
```

**Solution**: Use `--port` to specify a different port, or kill the process using port 8080.

### Cannot load certificate

```
Cannot open certificate file: sidecar_cert.pem
```

**Solution**: Run `generate_sidecar_cert` first, or specify correct path with `--cert`.

## References

- [RFC 9345 - Delegated Credentials for TLS](https://www.rfc-editor.org/rfc/rfc9345.html)
- [Fizz TLS Library](https://github.com/facebookincubator/fizz)
- CLAUDE.md - Project requirements and behavior specification
