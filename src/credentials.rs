//! Delegated credential generation and verification.
//!
//! This module provides APIs for generating delegated credentials from parent
//! certificates, self-verifying generated credentials, and managing credential data.

use serde::ser::SerializeStruct;

use crate::error::Result;
use crate::certificates::Certificate;
use crate::bridge::ffi;
use crate::bridge::{ServiceCredential, VerificationInfo, DelegatedCredential};

/// Generator for delegated credentials
pub struct CredentialGenerator {
    inner: cxx::UniquePtr<ffi::FizzCredentialGenerator>,
}

unsafe impl Send for CredentialGenerator {}
unsafe impl Send for ffi::FizzCredentialGenerator {}
// unsafe impl Sync for ffi::FizzCredentialGenerator {}

impl CredentialGenerator {
    /// Create a new credential generator from a parent certificate
    ///
    /// The parent certificate must have the delegated credential extension enabled.
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::{certificates::Certificate, credentials::CredentialGenerator};
    /// let cert = Certificate::load_from_files("cert.pem", "key.pem")?;
    /// let generator = CredentialGenerator::new(cert)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(parent_cert: Certificate) -> Result<Self> {
        let inner = ffi::new_credential_generator(parent_cert.as_inner())?;
        Ok(Self { inner })
    }

    /// Generate a delegated credential valid for the specified duration
    ///
    /// # Arguments
    /// * `service_name` - Service name for the credential
    /// * `valid_seconds` - Validity period in seconds (max 7 days per RFC 9345)
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::credentials::CredentialGenerator;
    /// # let generator: CredentialGenerator = unimplemented!();
    /// let credential = generator.generate("my-service", 86400)?; // 1 day
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate(&self, service_name: &str, valid_seconds: u32) -> Result<DelegatedCredentialData> {
        let inner = ffi::generate_delegated_credential(&self.inner, service_name, valid_seconds)?;
        Ok(DelegatedCredentialData { inner })
    }

    /// Self-verify a generated credential
    ///
    /// This performs the same verification that a client would perform,
    /// ensuring the credential is valid and properly signed.
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::credentials::CredentialGenerator;
    /// # let generator: CredentialGenerator = unimplemented!();
    /// # let credential = unimplemented!();
    /// let is_valid = generator.verify(&credential)?;
    /// assert!(is_valid);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn verify(&self, credential: &DelegatedCredentialData) -> Result<bool> {
        Ok(ffi::verify_delegated_credential(&self.inner, &credential.inner)?)
    }
}

/// A delegated credential with associated metadata
#[derive(Clone, Debug)]
pub struct DelegatedCredentialData {
    pub(crate) inner: ServiceCredential,
}

impl DelegatedCredentialData {
    /// Export the credential as PEM string
    ///
    /// This includes both the credential and its private key.
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::credentials::DelegatedCredentialData;
    /// # let credential: DelegatedCredentialData = unimplemented!();
    /// let pem = credential.to_pem();
    /// std::fs::write("credential.pem", pem)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn to_pem(&self) -> String {
        ffi::delegated_credential_to_pem(&self.inner)
    }

    /// Load a credential from PEM string
    ///
    /// Note: This function is not yet implemented in the C++ layer.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let inner = ServiceCredential {
            service_name: String::new(),
            credential: DelegatedCredential {
                valid_time: 0,
                expected_verify_scheme: 0,
                public_key_der: String::new(),
                credential_scheme: 0,
                signature: String::new(),
            },
            private_key_pem: String::new(),
            public_key_der: String::new(),
            created_at: 0,
            expires_at: 0,
            credential_pem: pem.to_owned(),
        };
        Ok(Self { inner })
    }

    /// Get public verification information for distribution to clients
    ///
    /// This information can be distributed to clients out-of-band or via HTTP
    /// for them to verify the delegated credential during TLS handshake.
    ///
    /// # Example
    /// ```no_run
    /// # use fizz_rs::credentials::DelegatedCredentialData;
    /// # let credential: DelegatedCredentialData = unimplemented!();
    /// let verification_info = credential.verification_info();
    /// let json = verification_info.to_json();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn verification_info(&self) -> VerificationInfo {
        ffi::get_public_verification_info(&self.inner)
    }

    /// Check if the credential has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.inner.expires_at
    }

    /// Get the service name for this credential
    pub fn service_name(&self) -> &str {
        &self.inner.service_name
    }

    /// Get the creation timestamp (Unix seconds)
    pub fn created_at(&self) -> u64 {
        self.inner.created_at
    }

    /// Get the expiration timestamp (Unix seconds)
    pub fn expires_at(&self) -> u64 {
        self.inner.expires_at
    }
}

impl VerificationInfo {
    /// Convert verification info to JSON string
    pub fn to_json(&self) -> String {
        ffi::verification_info_to_json(self)
    }

    /// Parse verification info from JSON string
    ///
    /// Note: This function is not yet implemented in the C++ layer.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(ffi::verification_info_from_json(json)?)
    }
}


impl serde::Serialize for VerificationInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
                let mut serde_state = serializer.serialize_struct("VerificationInfo", false as usize + 5)?;
                serde_state.serialize_field("service_name", &self.service_name)?;
                serde_state.serialize_field("valid_time", &self.valid_time)?;
                serde_state.serialize_field("expected_verify_scheme", &self.expected_verify_scheme)?;
                serde_state.serialize_field("public_key_der", &self.public_key_der)?;
                serde_state.serialize_field("expires_at", &self.expires_at)?;
                serde_state.end()
    }
}

use std::marker::PhantomData;
use std::fmt::Formatter;

impl<'de> serde::Deserialize<'de> for VerificationInfo {
    fn deserialize<__D>(
        __deserializer: __D,
    ) -> std::result::Result<Self, __D::Error>
    where
        __D: serde::Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        #[doc(hidden)]
        enum __Field {
            __field0,
            __field1,
            __field2,
            __field3,
            __field4,
            __ignore,
        }
        #[doc(hidden)]
        struct __FieldVisitor;
        #[automatically_derived]
        impl<'de> serde::de::Visitor<'de> for __FieldVisitor {
            type Value = __Field;
            fn expecting(
                &self,
                __formatter: &mut Formatter,
            ) -> std::fmt::Result {
                Formatter::write_str(
                    __formatter,
                    "field identifier",
                )
            }
            fn visit_u64<__E>(
                self,
                __value: u64,
            ) -> std::result::Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    0u64 => Ok(__Field::__field0),
                    1u64 => Ok(__Field::__field1),
                    2u64 => Ok(__Field::__field2),
                    3u64 => Ok(__Field::__field3),
                    4u64 => Ok(__Field::__field4),
                    _ => Ok(__Field::__ignore),
                }
            }
            fn visit_str<__E>(
                self,
                __value: &str,
            ) -> std::result::Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    "service_name" => Ok(__Field::__field0),
                    "valid_time" => Ok(__Field::__field1),
                    "expected_verify_scheme" => {
                        Ok(__Field::__field2)
                    }
                    "public_key_der" => Ok(__Field::__field3),
                    "expires_at" => Ok(__Field::__field4),
                    _ => Ok(__Field::__ignore),
                }
            }
            fn visit_bytes<__E>(
                self,
                __value: &[u8],
            ) -> std::result::Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    b"service_name" => Ok(__Field::__field0),
                    b"valid_time" => Ok(__Field::__field1),
                    b"expected_verify_scheme" => {
                        Ok(__Field::__field2)
                    }
                    b"public_key_der" => Ok(__Field::__field3),
                    b"expires_at" => Ok(__Field::__field4),
                    _ => Ok(__Field::__ignore),
                }
            }
        }
        #[automatically_derived]
        impl<'de> serde::Deserialize<'de> for __Field {
            #[inline]
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> std::result::Result<Self, __D::Error>
            where
                __D: serde::Deserializer<'de>,
            {
                serde::Deserializer::deserialize_identifier(
                    __deserializer,
                    __FieldVisitor,
                )
            }
        }
        #[doc(hidden)]
        struct __Visitor<'de> {
            marker: PhantomData<VerificationInfo>,
            lifetime: PhantomData<&'de ()>,
        }
        #[automatically_derived]
        impl<'de> serde::de::Visitor<'de> for __Visitor<'de> {
            type Value = VerificationInfo;
            fn expecting(
                &self,
                __formatter: &mut Formatter,
            ) -> std::fmt::Result {
                Formatter::write_str(
                    __formatter,
                    "struct VerificationInfo",
                )
            }
            #[inline]
            fn visit_seq<__A>(
                self,
                mut __seq: __A,
            ) -> std::result::Result<Self::Value, __A::Error>
            where
                __A: serde::de::SeqAccess<'de>,
            {
                let __field0 = match serde::de::SeqAccess::next_element::<
                    String,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                0usize,
                                &"struct VerificationInfo with 5 elements",
                            ),
                        );
                    }
                };
                let __field1 = match serde::de::SeqAccess::next_element::<
                    u32,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                1usize,
                                &"struct VerificationInfo with 5 elements",
                            ),
                        );
                    }
                };
                let __field2 = match serde::de::SeqAccess::next_element::<
                    u16,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                2usize,
                                &"struct VerificationInfo with 5 elements",
                            ),
                        );
                    }
                };
                let __field3 = match serde::de::SeqAccess::next_element::<
                    String,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                3usize,
                                &"struct VerificationInfo with 5 elements",
                            ),
                        );
                    }
                };
                let __field4 = match serde::de::SeqAccess::next_element::<
                    u64,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                4usize,
                                &"struct VerificationInfo with 5 elements",
                            ),
                        );
                    }
                };
                Ok(VerificationInfo {
                    service_name: __field0,
                    valid_time: __field1,
                    expected_verify_scheme: __field2,
                    public_key_der: __field3,
                    expires_at: __field4,
                })
            }
            #[inline]
            fn visit_map<__A>(
                self,
                mut __map: __A,
            ) -> std::result::Result<Self::Value, __A::Error>
            where
                __A: serde::de::MapAccess<'de>,
            {
                let mut __field0: Option<String> = None;
                let mut __field1: Option<u32> = None;
                let mut __field2: Option<u16> = None;
                let mut __field3: Option<String> = None;
                let mut __field4: Option<u64> = None;
                while let Some(__key) = serde::de::MapAccess::next_key::<
                    __Field,
                >(&mut __map)? {
                    match __key {
                        __Field::__field0 => {
                            if Option::is_some(&__field0) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "service_name",
                                    ),
                                );
                            }
                            __field0 = Some(
                                serde::de::MapAccess::next_value::<String>(&mut __map)?,
                            );
                        }
                        __Field::__field1 => {
                            if Option::is_some(&__field1) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "valid_time",
                                    ),
                                );
                            }
                            __field1 = Some(
                                serde::de::MapAccess::next_value::<u32>(&mut __map)?,
                            );
                        }
                        __Field::__field2 => {
                            if Option::is_some(&__field2) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "expected_verify_scheme",
                                    ),
                                );
                            }
                            __field2 = Some(
                                serde::de::MapAccess::next_value::<u16>(&mut __map)?,
                            );
                        }
                        __Field::__field3 => {
                            if Option::is_some(&__field3) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "public_key_der",
                                    ),
                                );
                            }
                            __field3 = Some(
                                serde::de::MapAccess::next_value::<String>(&mut __map)?,
                            );
                        }
                        __Field::__field4 => {
                            if Option::is_some(&__field4) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "expires_at",
                                    ),
                                );
                            }
                            __field4 = Some(
                                serde::de::MapAccess::next_value::<u64>(&mut __map)?,
                            );
                        }
                        _ => {
                            let _ = serde::de::MapAccess::next_value::<
                                serde::de::IgnoredAny,
                            >(&mut __map)?;
                        }
                    }
                }
                let __field0 = match __field0 {
                    Some(__field0) => __field0,
                    None => {
                        crate::bridge::missing_field("service_name")?
                    }
                };
                let __field1 = match __field1 {
                    Some(__field1) => __field1,
                    None => {
                        crate::bridge::missing_field("valid_time")?
                    }
                };
                let __field2 = match __field2 {
                    Some(__field2) => __field2,
                    None => {
                        crate::bridge::missing_field(
                            "expected_verify_scheme",
                        )?
                    }
                };
                let __field3 = match __field3 {
                    Some(__field3) => __field3,
                    None => {
                        crate::bridge::missing_field("public_key_der")?
                    }
                };
                let __field4 = match __field4 {
                    Some(__field4) => __field4,
                    None => {
                        crate::bridge::missing_field("expires_at")?
                    }
                };
                Ok(VerificationInfo {
                    service_name: __field0,
                    valid_time: __field1,
                    expected_verify_scheme: __field2,
                    public_key_der: __field3,
                    expires_at: __field4,
                })
            }
        }
        #[doc(hidden)]
        const FIELDS: &'static [&'static str] = &[
            "service_name",
            "valid_time",
            "expected_verify_scheme",
            "public_key_der",
            "expires_at",
        ];
        serde::Deserializer::deserialize_struct(
            __deserializer,
            "VerificationInfo",
            FIELDS,
            __Visitor {
                marker: PhantomData::<VerificationInfo>,
                lifetime: PhantomData,
            },
        )
    }
}
