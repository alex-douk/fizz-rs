//! Certificate and private key loading and management.
//!
//! This module provides APIs for loading X.509 certificates and private keys,
//! generating keypairs, and extracting certificate metadata.

use crate::error::Result;
use crate::bridge::ffi;

/// A loaded X.509 certificate with its private key
#[derive(Clone)]
pub struct Certificate {
    pub(crate) inner: crate::bridge::CertificateData,
}

impl Certificate {
    /// Load a certificate and private key from PEM strings
    ///
    /// # Arguments
    /// * `cert_pem` - Certificate in PEM format
    /// * `key_pem` - Private key in PEM format
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::certificates::Certificate;
    /// # let cert_pem = "...";
    /// # let key_pem = "...";
    /// let cert = Certificate::load_from_pem(cert_pem, key_pem)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let inner = ffi::load_certificate_from_pem(cert_pem, key_pem)?;
        Ok(Self { inner })
    }

    /// Load a certificate and private key from files
    ///
    /// # Arguments
    /// * `cert_path` - Path to certificate file
    /// * `key_path` - Path to private key file
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::certificates::Certificate;
    /// let cert = Certificate::load_from_files("cert.pem", "key.pem")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_from_files(cert_path: &str, key_path: &str) -> Result<Self> {
        let inner = ffi::load_certificate_from_file(cert_path, key_path)?;
        Ok(Self { inner })
    }

    /// Get the certificate as PEM string
    pub fn to_pem(&self) -> String {
        ffi::certificate_to_pem(&self.inner)
    }

    /// Get supported signature schemes for this certificate
    pub fn signature_schemes(&self) -> Vec<u16> {
        ffi::get_certificate_sig_schemes(&self.inner)
    }

    /// Get the underlying CertificateData (for internal use)
    pub(crate) fn as_inner(&self) -> &crate::bridge::CertificateData {
        &self.inner
    }
}

/// A certificate without its private key (public component only)
///
/// This type is used for servers that use delegated credentials.
/// According to RFC 9345 security requirements, servers using delegated
/// credentials should NEVER have access to the parent certificate's private key.
/// Only the credential manager/sidecar that generates credentials needs the
/// certificate's private key.
///
/// Use this type when:
/// - Creating a server TLS context with delegated credentials
/// - The certificate is only needed for verification, not signing
///
/// Use `Certificate` (with private key) when:
/// - Generating delegated credentials (credential manager/sidecar)
/// - You need to sign data with the certificate's private key
#[derive(Clone)]
pub struct CertificatePublic {
    pub(crate) inner: crate::bridge::CertificatePublic,
}

impl CertificatePublic {
    /// Load only the certificate from PEM string (no private key)
    ///
    /// # Arguments
    /// * `cert_pem` - Certificate in PEM format
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::certificates::CertificatePublic;
    /// # let cert_pem = "...";
    /// let cert = CertificatePublic::load_from_pem(cert_pem)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_from_pem(cert_pem: &str) -> Result<Self> {
        let inner = ffi::load_certificate_public_from_pem(cert_pem)?;
        Ok(Self { inner })
    }

    /// Load only the certificate from file (no private key)
    ///
    /// # Arguments
    /// * `cert_path` - Path to certificate file
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::certificates::CertificatePublic;
    /// let cert = CertificatePublic::load_from_file("cert.pem")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn load_from_file(cert_path: &str) -> Result<Self> {
        let inner = ffi::load_certificate_public_from_file(cert_path)?;
        Ok(Self { inner })
    }

    /// Get the certificate as PEM string
    pub fn to_pem(&self) -> String {
        self.inner.cert_pem.clone()
    }

    /// Get supported signature schemes for this certificate
    pub fn signature_schemes(&self) -> Vec<u16> {
        self.inner.sig_schemes.clone()
    }

    /// Get the underlying CertificatePublic (for internal use)
    pub(crate) fn as_inner(&self) -> &crate::bridge::CertificatePublic {
        &self.inner
    }
}

/// A private key (may be separate from a certificate)
pub struct PrivateKey {
    inner: cxx::UniquePtr<ffi::FizzPrivateKey>,
}

impl PrivateKey {
    /// Generate a new EC P-256 keypair
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::certificates::PrivateKey;
    /// let key = PrivateKey::generate_ec_p256()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_ec_p256() -> Result<Self> {
        let inner = ffi::generate_ec_p256_keypair()?;
        Ok(Self { inner })
    }

    /// Load a private key from PEM string
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::certificates::PrivateKey;
    /// # let pem_string = "...";
    /// let key = PrivateKey::from_pem(pem_string)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_pem(pem: &str) -> Result<Self> {
        let inner = ffi::load_private_key_from_pem(pem)?;
        Ok(Self { inner })
    }

    /// Export the private key as PEM string
    pub fn to_pem(&self) -> String {
        ffi::private_key_to_pem(&self.inner)
    }

    /// Get the public key in DER format (as hex string)
    pub fn public_key_der_hex(&self) -> String {
        ffi::get_public_key_der(&self.inner)
    }

    /// Get the public key in DER format (as bytes)
    pub fn public_key_der(&self) -> Vec<u8> {
        let hex = self.public_key_der_hex();
        hex_to_bytes(&hex)
    }
}

/// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            hex.get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect()
}
