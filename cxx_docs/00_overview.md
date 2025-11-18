# CXX Framework Overview

**Version:** 1.0.178
**License:** MIT OR Apache-2.0
**Repository:** https://github.com/dtolnay/cxx
**Documentation:** https://cxx.rs
**Owner:** dtolnay

## Introduction

The `cxx` crate provides a **safe mechanism for calling C++ code from Rust and Rust code from C++** without the vulnerabilities of traditional bindgen or cbindgen approaches. It requires rustc 1.81+ and C++11 or newer.

## Core Principle

**"Auditing just the C++ side would be sufficient to catch all problems, i.e. the Rust side can be 100% safe."**

This principle ensures that unsafe behavior can only originate from the C++ side, making security audits more focused and manageable.

## How It Works

The library uses paired code generators:
- **Rust procedural macro** (`#[cxx::bridge]`)
- **C++ generator** (CLI tool or build.rs integration)

These generators create zero-overhead FFI bridges with static analysis guarantees.

## Three Kinds of FFI Items

### 1. Shared Structs
Structs that are visible to both Rust and C++ with identical memory layout.

### 2. Opaque Types
Types that are language-specific and cannot be inspected from the other language. They can only be accessed through references or smart pointers.

### 3. Functions
Functions can be implemented in either language and called from the other. Function signatures must be declared in the bridge module.

## Key Differences from bindgen/cbindgen

CXX differs from traditional binding generators by requiring signature definitions in **both locations** (Rust and C++), with compile-time verification ensuring synchronization. This prevents subtle ABI mismatches and unsafe operations.

## Setup Instructions

### Cargo-based Build
```toml
[dependencies]
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

### Non-Cargo Build
Use the `cxxbridge` CLI tool for projects not using Cargo.

## Safety Mechanisms

1. **Paired Code Generator Control**: Both Rust and C++ code are generated from the same bridge definition
2. **Move-Safety Analysis**: Prevents unsafe movement of types with move constructors
3. **ABI Compatibility Handling**: Ensures proper alignment and layout across language boundaries
4. **Template Instantiation Support**: Safely handles C++ templates

## Builtin Types

| Rust Type | C++ Type | Notes |
|-----------|----------|-------|
| `String` | `rust::String` | Rust's owned string |
| `&str` | `rust::Str` | Rust's string slice |
| `CxxString` | `std::string` | C++ string |
| `Box<T>` | `rust::Box<T>` | Rust's unique pointer |
| `UniquePtr<T>` | `std::unique_ptr<T>` | C++ unique pointer |
| `SharedPtr<T>` | `std::shared_ptr<T>` | C++ shared pointer |
| `WeakPtr<T>` | `std::weak_ptr<T>` | C++ weak pointer |
| `Vec<T>` | `rust::Vec<T>` | Rust's vector |
| `CxxVector<T>` | `std::vector<T>` | C++ vector |
| `&[T]` | `rust::Slice<const T>` | Rust's slice |
| `&mut [T]` | `rust::Slice<T>` | Rust's mutable slice |
| `fn(...)` | `rust::Fn<...>` | Function pointer |

## Basic Example

```rust
#[cxx::bridge]
mod ffi {
    // Shared struct
    struct BlobMetadata {
        size: usize,
        tags: Vec<String>,
    }

    // C++ types and functions
    extern "C++" {
        include!("blobstore.h");

        type BlobstoreClient;

        fn new_blobstore_client() -> UniquePtr<BlobstoreClient>;
        fn put(&self, parts: &mut MultiBuf) -> u64;
        fn tag(&self, blobid: u64, tag: &str);
        fn metadata(&self, blobid: u64) -> BlobMetadata;
    }

    // Rust types and functions
    extern "Rust" {
        type MultiBuf;

        fn next(&mut self) -> &[u8];
    }
}
```

## Project Structure

- **Modules:** `kind`, `memory`, `vector`
- **Macros:** `let_cxx_string!`, `type_id!`
- **Structs:** `CxxString`, `CxxVector`, `Exception`, `SharedPtr`, `UniquePtr`, `WeakPtr`
- **Traits:** `ExternType`
- **Attribute Macros:** `#[bridge]`

## Documentation Coverage

100% of the crate is documented.

## Dependencies

Core dependencies:
- `cxxbridge-macro` - Procedural macro implementation
- `foldhash` - Hashing utilities
- `link-cplusplus` - C++ standard library linking
