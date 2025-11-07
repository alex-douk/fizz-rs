/*
 * generate_sidecar_cert.cpp
 *
 * Utility to generate a parent certificate with the DelegatedCredential extension
 * for use by the sidecar. This certificate can sign delegated credentials per RFC 9345.
 *
 * The generated certificate will have:
 * - DelegatedCredential extension (OID: 1.3.6.1.4.1.44363.44)
 * - CA:TRUE basic constraint
 * - digitalSignature and keyCertSign key usage
 * - EC P-256 key
 */

#include <fizz/crypto/Utils.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <iostream>
#include <fstream>
#include <memory>
#include <cstring>

namespace {

// Smart pointer deleters for OpenSSL types
struct X509Deleter {
    void operator()(X509* p) const { X509_free(p); }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

struct EcKeyDeleter {
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
};

struct EcGroupDeleter {
    void operator()(EC_GROUP* p) const { EC_GROUP_free(p); }
};

struct Asn1ObjectDeleter {
    void operator()(ASN1_OBJECT* p) const { ASN1_OBJECT_free(p); }
};

struct X509ExtensionDeleter {
    void operator()(X509_EXTENSION* p) const { X509_EXTENSION_free(p); }
};

using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EcKeyPtr = std::unique_ptr<EC_KEY, EcKeyDeleter>;
using EcGroupPtr = std::unique_ptr<EC_GROUP, EcGroupDeleter>;
using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, Asn1ObjectDeleter>;
using X509ExtensionPtr = std::unique_ptr<X509_EXTENSION, X509ExtensionDeleter>;

/**
 * Generate an EC P-256 private key
 */
EvpPkeyPtr generateP256Key() {
    EvpPkeyPtr pkey(EVP_PKEY_new());
    EcGroupPtr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    EcKeyPtr ecKey(EC_KEY_new());

    if (!pkey || !group || !ecKey) {
        throw std::runtime_error("Failed to allocate key structures");
    }

    EC_GROUP_set_asn1_flag(group.get(), OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_UNCOMPRESSED);

    if (EC_KEY_set_group(ecKey.get(), group.get()) != 1) {
        throw std::runtime_error("Failed to set EC group");
    }

    if (EC_KEY_generate_key(ecKey.get()) != 1) {
        throw std::runtime_error("Failed to generate EC key");
    }

    if (EVP_PKEY_set1_EC_KEY(pkey.get(), ecKey.get()) != 1) {
        throw std::runtime_error("Failed to assign EC key to EVP_PKEY");
    }

    std::cout << "✓ Generated EC P-256 private key" << std::endl;
    return pkey;
}

/**
 * Create a self-signed X.509 certificate with delegated credential extension
 */
X509Ptr createCertificate(
    EVP_PKEY* pkey,
    const std::string& commonName,
    int validityDays) {

    X509Ptr cert(X509_new());
    if (!cert) {
        throw std::runtime_error("Failed to create X509 structure");
    }

    // Set version to V3 (value 2)
    if (X509_set_version(cert.get(), 2) != 1) {
        throw std::runtime_error("Failed to set certificate version");
    }

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 60L * 60 * 24 * validityDays);

    // Set public key
    if (X509_set_pubkey(cert.get(), pkey) != 1) {
        throw std::runtime_error("Failed to set public key");
    }

    // Build subject name
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Tahini Project"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0);

    // Set issuer (self-signed)
    if (X509_set_issuer_name(cert.get(), name) != 1) {
        throw std::runtime_error("Failed to set issuer name");
    }

    std::cout << "✓ Created certificate for CN=" << commonName << std::endl;

    // Add X509v3 extensions

    // 1. Basic Constraints: CA:TRUE (critical)
    X509_EXTENSION* basicConstraints = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
    if (basicConstraints) {
        X509_add_ext(cert.get(), basicConstraints, -1);
        X509_EXTENSION_free(basicConstraints);
        std::cout << "✓ Added Basic Constraints extension (CA:TRUE)" << std::endl;
    }

    // 2. Key Usage: digitalSignature, keyCertSign (critical)
    X509_EXTENSION* keyUsage = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_key_usage,
        "critical,digitalSignature,keyCertSign");
    if (keyUsage) {
        X509_add_ext(cert.get(), keyUsage, -1);
        X509_EXTENSION_free(keyUsage);
        std::cout << "✓ Added Key Usage extension" << std::endl;
    }

    // 3. DelegatedCredential extension (OID: 1.3.6.1.4.1.44363.44)
    // This is the critical extension that allows this cert to sign delegated credentials
    Asn1ObjectPtr oid(OBJ_txt2obj("1.3.6.1.4.1.44363.44", 1));
    if (!oid) {
        throw std::runtime_error("Failed to create DelegatedCredential OID");
    }

    // Create extension with NULL value (as per RFC 9345)
    // The DelegationUsage extension value is NULL (0x05 0x00)
    unsigned char extValue[] = {0x05, 0x00};

    X509_EXTENSION* dcExt = X509_EXTENSION_create_by_OBJ(
        nullptr, oid.get(), 0, ASN1_OCTET_STRING_new());

    if (!dcExt) {
        throw std::runtime_error("Failed to create DelegatedCredential extension");
    }

    if (ASN1_OCTET_STRING_set(X509_EXTENSION_get_data(dcExt), extValue, sizeof(extValue)) != 1) {
        X509_EXTENSION_free(dcExt);
        throw std::runtime_error("Failed to set extension value");
    }

    if (X509_add_ext(cert.get(), dcExt, -1) != 1) {
        X509_EXTENSION_free(dcExt);
        throw std::runtime_error("Failed to add DelegatedCredential extension");
    }

    X509_EXTENSION_free(dcExt);
    std::cout << "✓ Added DelegatedCredential extension (OID: 1.3.6.1.4.1.44363.44)" << std::endl;

    // Sign the certificate
    if (X509_sign(cert.get(), pkey, EVP_sha256()) == 0) {
        throw std::runtime_error("Failed to sign certificate");
    }

    std::cout << "✓ Certificate signed with SHA256" << std::endl;

    return cert;
}

/**
 * Save certificate to PEM file
 */
void saveCertificate(X509* cert, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    if (PEM_write_X509(file, cert) != 1) {
        fclose(file);
        throw std::runtime_error("Failed to write certificate to file");
    }

    fclose(file);
    std::cout << "✓ Saved certificate to: " << filename << std::endl;
}

/**
 * Save private key to PEM file
 */
void savePrivateKey(EVP_PKEY* pkey, const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "wb");
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    if (PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        fclose(file);
        throw std::runtime_error("Failed to write private key to file");
    }

    fclose(file);
    std::cout << "✓ Saved private key to: " << filename << std::endl;
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n"
              << "Generate a parent certificate with DelegatedCredential extension for the sidecar.\n\n"
              << "Options:\n"
              << "  --cert PATH          Output certificate path (default: sidecar_cert.pem)\n"
              << "  --key PATH           Output private key path (default: sidecar_key.pem)\n"
              << "  --cn NAME            Common Name for certificate (default: sidecar.tahini.local)\n"
              << "  --days DAYS          Certificate validity in days (default: 365)\n"
              << "  --help               Show this help message\n";
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    try {
        // Initialize OpenSSL
        fizz::CryptoUtils::init();

        // Default configuration
        std::string certPath = "sidecar_cert.pem";
        std::string keyPath = "sidecar_key.pem";
        std::string commonName = "sidecar.tahini.local";
        int validityDays = 365;

        // Parse command line arguments
        for (int i = 1; i < argc; i++) {
            std::string arg(argv[i]);

            if (arg == "--help" || arg == "-h") {
                printUsage(argv[0]);
                return 0;
            } else if (arg == "--cert" && i + 1 < argc) {
                certPath = argv[++i];
            } else if (arg == "--key" && i + 1 < argc) {
                keyPath = argv[++i];
            } else if (arg == "--cn" && i + 1 < argc) {
                commonName = argv[++i];
            } else if (arg == "--days" && i + 1 < argc) {
                validityDays = std::atoi(argv[++i]);
            } else {
                std::cerr << "Unknown option: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }

        std::cout << "=== Sidecar Certificate Generator ===" << std::endl;
        std::cout << "\nConfiguration:" << std::endl;
        std::cout << "  Common Name: " << commonName << std::endl;
        std::cout << "  Validity: " << validityDays << " days" << std::endl;
        std::cout << "  Certificate output: " << certPath << std::endl;
        std::cout << "  Private key output: " << keyPath << std::endl;
        std::cout << "\nGenerating certificate...\n" << std::endl;

        // Generate key
        auto privateKey = generateP256Key();

        // Create certificate
        auto certificate = createCertificate(privateKey.get(), commonName, validityDays);

        // Save to files
        saveCertificate(certificate.get(), certPath);
        savePrivateKey(privateKey.get(), keyPath);

        std::cout << "\n=== Success ===" << std::endl;
        std::cout << "\nThe parent certificate has been generated with:" << std::endl;
        std::cout << "  - DelegatedCredential extension (RFC 9345)" << std::endl;
        std::cout << "  - CA capabilities" << std::endl;
        std::cout << "  - EC P-256 key" << std::endl;
        std::cout << "\nYou can now start the sidecar with:" << std::endl;
        std::cout << "  ./sidecar --cert " << certPath << " --key " << keyPath << std::endl;
        std::cout << "\nThe public certificate (" << certPath << ") can be distributed to clients" << std::endl;
        std::cout << "for verification purposes.\n" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
