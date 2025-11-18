//! Shared types used across the fizz_rs library.
//!
//! These types are defined in the CXX bridge and can be used from both Rust and C++.

// Note: The actual struct definitions are in bridge.rs
// This module re-exports them and provides convenience methods

pub use crate::bridge::{
    DelegatedCredential,
    ServiceCredential,
    VerificationInfo,
    CertificateData,
};

pub use crate::bridge::missing_field;
pub use std::marker::PhantomData;
pub use std::fmt::Formatter;

/// Signature scheme identifiers (from TLS 1.3)
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
}

impl SignatureScheme {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0403 => Some(SignatureScheme::EcdsaSecp256r1Sha256),
            0x0503 => Some(SignatureScheme::EcdsaSecp384r1Sha384),
            0x0603 => Some(SignatureScheme::EcdsaSecp521r1Sha512),
            0x0804 => Some(SignatureScheme::RsaPssRsaeSha256),
            0x0805 => Some(SignatureScheme::RsaPssRsaeSha384),
            0x0806 => Some(SignatureScheme::RsaPssRsaeSha512),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

#[allow(unused_extern_crates, clippy::useless_attribute)]
#[automatically_derived]
impl serde::Serialize for DelegatedCredential {
    fn serialize<__S>(
        &self,
        __serializer: __S,
    ) -> Result<__S::Ok, __S::Error>
    where
        __S: serde::Serializer,
    {
        let mut _serde_state = serde::Serializer::serialize_struct(
            __serializer,
            "DelegatedCredential",
            false as usize + 1 + 1 + 1 + 1 + 1,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "valid_time",
            &self.valid_time,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "expected_verify_scheme",
            &self.expected_verify_scheme,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "public_key_der",
            &self.public_key_der,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "credential_scheme",
            &self.credential_scheme,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "signature",
            &self.signature,
        )?;
        serde::ser::SerializeStruct::end(_serde_state)
    }
}

impl<'de> serde::Deserialize<'de> for DelegatedCredential {
    fn deserialize<__D>(
        __deserializer: __D,
    ) -> Result<Self, __D::Error>
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
            ) -> Result<Self::Value, __E>
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
            ) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    "valid_time" => Ok(__Field::__field0),
                    "expected_verify_scheme" => {
                        Ok(__Field::__field1)
                    }
                    "public_key_der" => Ok(__Field::__field2),
                    "credential_scheme" => {
                        Ok(__Field::__field3)
                    }
                    "signature" => Ok(__Field::__field4),
                    _ => Ok(__Field::__ignore),
                }
            }
            fn visit_bytes<__E>(
                self,
                __value: &[u8],
            ) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    b"valid_time" => Ok(__Field::__field0),
                    b"expected_verify_scheme" => {
                        Ok(__Field::__field1)
                    }
                    b"public_key_der" => Ok(__Field::__field2),
                    b"credential_scheme" => {
                        Ok(__Field::__field3)
                    }
                    b"signature" => Ok(__Field::__field4),
                    _ => Ok(__Field::__ignore),
                }
            }
        }
        #[automatically_derived]
        impl<'de> serde::Deserialize<'de> for __Field {
            #[inline]
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> Result<Self, __D::Error>
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
            marker: PhantomData<DelegatedCredential>,
            lifetime: PhantomData<&'de ()>,
        }
        #[automatically_derived]
        impl<'de> serde::de::Visitor<'de> for __Visitor<'de> {
            type Value = DelegatedCredential;
            fn expecting(
                &self,
                __formatter: &mut Formatter,
            ) -> std::fmt::Result {
                Formatter::write_str(
                    __formatter,
                    "struct DelegatedCredential",
                )
            }
            #[inline]
            fn visit_seq<__A>(
                self,
                mut __seq: __A,
            ) -> Result<Self::Value, __A::Error>
            where
                __A: serde::de::SeqAccess<'de>,
            {
                let __field0 = match serde::de::SeqAccess::next_element::<
                    u32,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                0usize,
                                &"struct DelegatedCredential with 5 elements",
                            ),
                        );
                    }
                };
                let __field1 = match serde::de::SeqAccess::next_element::<
                    u16,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                1usize,
                                &"struct DelegatedCredential with 5 elements",
                            ),
                        );
                    }
                };
                let __field2 = match serde::de::SeqAccess::next_element::<
                    String,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                2usize,
                                &"struct DelegatedCredential with 5 elements",
                            ),
                        );
                    }
                };
                let __field3 = match serde::de::SeqAccess::next_element::<
                    u16,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                3usize,
                                &"struct DelegatedCredential with 5 elements",
                            ),
                        );
                    }
                };
                let __field4 = match serde::de::SeqAccess::next_element::<
                    String,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                4usize,
                                &"struct DelegatedCredential with 5 elements",
                            ),
                        );
                    }
                };
                Ok(DelegatedCredential {
                    valid_time: __field0,
                    expected_verify_scheme: __field1,
                    public_key_der: __field2,
                    credential_scheme: __field3,
                    signature: __field4,
                })
            }
            #[inline]
            fn visit_map<__A>(
                self,
                mut __map: __A,
            ) -> Result<Self::Value, __A::Error>
            where
                __A: serde::de::MapAccess<'de>,
            {
                let mut __field0: Option<u32> = None;
                let mut __field1: Option<u16> = None;
                let mut __field2: Option<String> = None;
                let mut __field3: Option<u16> = None;
                let mut __field4: Option<String> = None;
                while let Some(__key) = serde::de::MapAccess::next_key::<
                    __Field,
                >(&mut __map)? {
                    match __key {
                        __Field::__field0 => {
                            if Option::is_some(&__field0) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "valid_time",
                                    ),
                                );
                            }
                            __field0 = Some(
                                serde::de::MapAccess::next_value::<u32>(&mut __map)?,
                            );
                        }
                        __Field::__field1 => {
                            if Option::is_some(&__field1) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "expected_verify_scheme",
                                    ),
                                );
                            }
                            __field1 = Some(
                                serde::de::MapAccess::next_value::<u16>(&mut __map)?,
                            );
                        }
                        __Field::__field2 => {
                            if Option::is_some(&__field2) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "public_key_der",
                                    ),
                                );
                            }
                            __field2 = Some(
                                serde::de::MapAccess::next_value::<String>(&mut __map)?,
                            );
                        }
                        __Field::__field3 => {
                            if Option::is_some(&__field3) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "credential_scheme",
                                    ),
                                );
                            }
                            __field3 = Some(
                                serde::de::MapAccess::next_value::<u16>(&mut __map)?,
                            );
                        }
                        __Field::__field4 => {
                            if Option::is_some(&__field4) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "signature",
                                    ),
                                );
                            }
                            __field4 = Some(
                                serde::de::MapAccess::next_value::<String>(&mut __map)?,
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
                        missing_field("valid_time")?
                    }
                };
                let __field1 = match __field1 {
                    Some(__field1) => __field1,
                    None => {
                        missing_field(
                            "expected_verify_scheme",
                        )?
                    }
                };
                let __field2 = match __field2 {
                    Some(__field2) => __field2,
                    None => {
                        missing_field("public_key_der")?
                    }
                };
                let __field3 = match __field3 {
                    Some(__field3) => __field3,
                    None => {
                        missing_field("credential_scheme")?
                    }
                };
                let __field4 = match __field4 {
                    Some(__field4) => __field4,
                    None => {
                        missing_field("signature")?
                    }
                };
                Ok(DelegatedCredential {
                    valid_time: __field0,
                    expected_verify_scheme: __field1,
                    public_key_der: __field2,
                    credential_scheme: __field3,
                    signature: __field4,
                })
            }
        }
        #[doc(hidden)]
        const FIELDS: &'static [&'static str] = &[
            "valid_time",
            "expected_verify_scheme",
            "public_key_der",
            "credential_scheme",
            "signature",
        ];
        serde::Deserializer::deserialize_struct(
            __deserializer,
            "DelegatedCredential",
            FIELDS,
            __Visitor {
                marker: PhantomData::<DelegatedCredential>,
                lifetime: PhantomData,
            },
        )
    }
}

impl serde::Serialize for ServiceCredential {
    fn serialize<__S>(
        &self,
        __serializer: __S,
    ) -> Result<__S::Ok, __S::Error>
    where
        __S: serde::Serializer,
    {
        let mut _serde_state = serde::Serializer::serialize_struct(
            __serializer,
            "ServiceCredential",
            false as usize + 1 + 1 + 1 + 1 + 1 + 1 + 1,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "service_name",
            &self.service_name,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "credential",
            &self.credential,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "private_key_pem",
            &self.private_key_pem,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "public_key_der",
            &self.public_key_der,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "created_at",
            &self.created_at,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "expires_at",
            &self.expires_at,
        )?;
        serde::ser::SerializeStruct::serialize_field(
            &mut _serde_state,
            "credential_pem",
            &self.credential_pem,
        )?;
        serde::ser::SerializeStruct::end(_serde_state)
    }
}


impl<'de> serde::Deserialize<'de> for ServiceCredential {
    fn deserialize<__D>(
        __deserializer: __D,
    ) -> Result<Self, __D::Error>
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
            __field5,
            __field6,
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
            ) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    0u64 => Ok(__Field::__field0),
                    1u64 => Ok(__Field::__field1),
                    2u64 => Ok(__Field::__field2),
                    3u64 => Ok(__Field::__field3),
                    4u64 => Ok(__Field::__field4),
                    5u64 => Ok(__Field::__field5),
                    6u64 => Ok(__Field::__field6),
                    _ => Ok(__Field::__ignore),
                }
            }
            fn visit_str<__E>(
                self,
                __value: &str,
            ) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    "service_name" => Ok(__Field::__field0),
                    "credential" => Ok(__Field::__field1),
                    "private_key_pem" => Ok(__Field::__field2),
                    "public_key_der" => Ok(__Field::__field3),
                    "created_at" => Ok(__Field::__field4),
                    "expires_at" => Ok(__Field::__field5),
                    "credential_pem" => Ok(__Field::__field6),
                    _ => Ok(__Field::__ignore),
                }
            }
            fn visit_bytes<__E>(
                self,
                __value: &[u8],
            ) -> Result<Self::Value, __E>
            where
                __E: serde::de::Error,
            {
                match __value {
                    b"service_name" => Ok(__Field::__field0),
                    b"credential" => Ok(__Field::__field1),
                    b"private_key_pem" => Ok(__Field::__field2),
                    b"public_key_der" => Ok(__Field::__field3),
                    b"created_at" => Ok(__Field::__field4),
                    b"expires_at" => Ok(__Field::__field5),
                    b"credential_pem" => Ok(__Field::__field6),
                    _ => Ok(__Field::__ignore),
                }
            }
        }
        #[automatically_derived]
        impl<'de> serde::Deserialize<'de> for __Field {
            #[inline]
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> Result<Self, __D::Error>
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
            marker: PhantomData<ServiceCredential>,
            lifetime: PhantomData<&'de ()>,
        }
        #[automatically_derived]
        impl<'de> serde::de::Visitor<'de> for __Visitor<'de> {
            type Value = ServiceCredential;
            fn expecting(
                &self,
                __formatter: &mut Formatter,
            ) -> std::fmt::Result {
                Formatter::write_str(
                    __formatter,
                    "struct ServiceCredential",
                )
            }
            #[inline]
            fn visit_seq<__A>(
                self,
                mut __seq: __A,
            ) -> Result<Self::Value, __A::Error>
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
                                &"struct ServiceCredential with 7 elements",
                            ),
                        );
                    }
                };
                let __field1 = match serde::de::SeqAccess::next_element::<
                    DelegatedCredential,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                1usize,
                                &"struct ServiceCredential with 7 elements",
                            ),
                        );
                    }
                };
                let __field2 = match serde::de::SeqAccess::next_element::<
                    String,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                2usize,
                                &"struct ServiceCredential with 7 elements",
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
                                &"struct ServiceCredential with 7 elements",
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
                                &"struct ServiceCredential with 7 elements",
                            ),
                        );
                    }
                };
                let __field5 = match serde::de::SeqAccess::next_element::<
                    u64,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                5usize,
                                &"struct ServiceCredential with 7 elements",
                            ),
                        );
                    }
                };
                let __field6 = match serde::de::SeqAccess::next_element::<
                    String,
                >(&mut __seq)? {
                    Some(__value) => __value,
                    None => {
                        return Err(
                            serde::de::Error::invalid_length(
                                6usize,
                                &"struct ServiceCredential with 7 elements",
                            ),
                        );
                    }
                };
                Ok(ServiceCredential {
                    service_name: __field0,
                    credential: __field1,
                    private_key_pem: __field2,
                    public_key_der: __field3,
                    created_at: __field4,
                    expires_at: __field5,
                    credential_pem: __field6,
                })
            }
            #[inline]
            fn visit_map<__A>(
                self,
                mut __map: __A,
            ) -> Result<Self::Value, __A::Error>
            where
                __A: serde::de::MapAccess<'de>,
            {
                let mut __field0: Option<String> = None;
                let mut __field1: Option<
                    DelegatedCredential,
                > = None;
                let mut __field2: Option<String> = None;
                let mut __field3: Option<String> = None;
                let mut __field4: Option<u64> = None;
                let mut __field5: Option<u64> = None;
                let mut __field6: Option<String> = None;
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
                                        "credential",
                                    ),
                                );
                            }
                            __field1 = Some(
                                serde::de::MapAccess::next_value::<
                                    DelegatedCredential,
                                >(&mut __map)?,
                            );
                        }
                        __Field::__field2 => {
                            if Option::is_some(&__field2) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "private_key_pem",
                                    ),
                                );
                            }
                            __field2 = Some(
                                serde::de::MapAccess::next_value::<String>(&mut __map)?,
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
                                        "created_at",
                                    ),
                                );
                            }
                            __field4 = Some(
                                serde::de::MapAccess::next_value::<u64>(&mut __map)?,
                            );
                        }
                        __Field::__field5 => {
                            if Option::is_some(&__field5) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "expires_at",
                                    ),
                                );
                            }
                            __field5 = Some(
                                serde::de::MapAccess::next_value::<u64>(&mut __map)?,
                            );
                        }
                        __Field::__field6 => {
                            if Option::is_some(&__field6) {
                                return Err(
                                    <__A::Error as serde::de::Error>::duplicate_field(
                                        "credential_pem",
                                    ),
                                );
                            }
                            __field6 = Some(
                                serde::de::MapAccess::next_value::<String>(&mut __map)?,
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
                        missing_field("service_name")?
                    }
                };
                let __field1 = match __field1 {
                    Some(__field1) => __field1,
                    None => {
                        missing_field("credential")?
                    }
                };
                let __field2 = match __field2 {
                    Some(__field2) => __field2,
                    None => {
                        missing_field("private_key_pem")?
                    }
                };
                let __field3 = match __field3 {
                    Some(__field3) => __field3,
                    None => {
                        missing_field("public_key_der")?
                    }
                };
                let __field4 = match __field4 {
                    Some(__field4) => __field4,
                    None => {
                        missing_field("created_at")?
                    }
                };
                let __field5 = match __field5 {
                    Some(__field5) => __field5,
                    None => {
                        missing_field("expires_at")?
                    }
                };
                let __field6 = match __field6 {
                    Some(__field6) => __field6,
                    None => {
                        missing_field("credential_pem")?
                    }
                };
                Ok(ServiceCredential {
                    service_name: __field0,
                    credential: __field1,
                    private_key_pem: __field2,
                    public_key_der: __field3,
                    created_at: __field4,
                    expires_at: __field5,
                    credential_pem: __field6,
                })
            }
        }
        #[doc(hidden)]
        const FIELDS: &'static [&'static str] = &[
            "service_name",
            "credential",
            "private_key_pem",
            "public_key_der",
            "created_at",
            "expires_at",
            "credential_pem",
        ];
        serde::Deserializer::deserialize_struct(
            __deserializer,
            "ServiceCredential",
            FIELDS,
            __Visitor {
                marker: PhantomData::<ServiceCredential>,
                lifetime: PhantomData,
            },
        )
    }
}
