# CXX Framework Documentation

This directory contains comprehensive documentation for the CXX framework (version 1.0.178), extracted from https://docs.rs/cxx/1.0.178/cxx/.

## About CXX

CXX provides **safe interoperability between Rust and C++** without the vulnerabilities of traditional binding generators. The framework uses paired code generators (Rust procedural macro + C++ generator) to create zero-overhead FFI bridges with compile-time safety guarantees.

**Core Principle:** "Auditing just the C++ side would be sufficient to catch all problems, i.e. the Rust side can be 100% safe."

## Documentation Files

### Getting Started
- **[00_overview.md](00_overview.md)** - Introduction, core concepts, builtin types, and basic examples

### Modules
- **[01_modules.md](01_modules.md)** - Documentation for `kind`, `memory`, and `vector` modules
  - Marker types for C++ type knowledge
  - Smart pointer trait bounds
  - Vector iterator types and utilities

### Type System

#### String Types
- **[02_string_types.md](02_string_types.md)** - CxxString and string handling
  - `CxxString` struct - Rust binding to C++ `std::string`
  - `let_cxx_string!` macro - Stack-allocated C++ strings
  - String conversion and UTF-8 handling

#### Smart Pointers
- **[03_smart_pointers.md](03_smart_pointers.md)** - Memory management across FFI
  - `UniquePtr<T>` - Exclusive ownership (like `std::unique_ptr`)
  - `SharedPtr<T>` - Shared ownership (like `std::shared_ptr`)
  - `WeakPtr<T>` - Non-owning references (like `std::weak_ptr`)

#### Collections
- **[04_vector_types.md](04_vector_types.md)** - C++ vector interop
  - `CxxVector<T>` - Rust binding to C++ `std::vector`
  - Element access, iteration, modification
  - Trivial vs opaque type handling

### Advanced Topics

#### Traits and Type System
- **[05_traits_and_extern_types.md](05_traits_and_extern_types.md)** - Type bridging
  - `ExternType` trait - Defining C++ types in Rust
  - `type_id!` macro - Specifying C++ type names
  - Trivial vs Opaque types
  - Multi-module type sharing

#### Error Handling
- **[06_exception_handling.md](06_exception_handling.md)** - C++ exceptions in Rust
  - `Exception` struct - C++ exception representation
  - Converting exceptions to Rust `Result`
  - Error handling patterns and best practices

#### Bridge Definition
- **[07_bridge_macro.md](07_bridge_macro.md)** - The `#[cxx::bridge]` attribute
  - Bridge module structure
  - `extern "C++"` and `extern "Rust"` blocks
  - Shared structs
  - Namespace support
  - Complete examples

## Quick Reference

### Key Types

| Type | Description | Documentation |
|------|-------------|---------------|
| `CxxString` | C++ `std::string` binding | [02_string_types.md](02_string_types.md) |
| `CxxVector<T>` | C++ `std::vector<T>` binding | [04_vector_types.md](04_vector_types.md) |
| `UniquePtr<T>` | C++ `std::unique_ptr<T>` binding | [03_smart_pointers.md](03_smart_pointers.md) |
| `SharedPtr<T>` | C++ `std::shared_ptr<T>` binding | [03_smart_pointers.md](03_smart_pointers.md) |
| `WeakPtr<T>` | C++ `std::weak_ptr<T>` binding | [03_smart_pointers.md](03_smart_pointers.md) |
| `Exception` | C++ exception wrapper | [06_exception_handling.md](06_exception_handling.md) |

### Key Traits

| Trait | Purpose | Documentation |
|-------|---------|---------------|
| `ExternType` | Define C++ types in Rust | [05_traits_and_extern_types.md](05_traits_and_extern_types.md) |
| `Kind` | Mark type characteristics | [01_modules.md](01_modules.md) |
| `UniquePtrTarget` | Generic unique pointer support | [01_modules.md](01_modules.md) |
| `SharedPtrTarget` | Generic shared pointer support | [01_modules.md](01_modules.md) |
| `VectorElement` | Generic vector element support | [01_modules.md](01_modules.md) |

### Key Macros

| Macro | Purpose | Documentation |
|-------|---------|---------------|
| `#[cxx::bridge]` | Define FFI bridge | [07_bridge_macro.md](07_bridge_macro.md) |
| `let_cxx_string!` | Create stack-allocated C++ string | [02_string_types.md](02_string_types.md) |
| `type_id!` | Specify C++ type identifier | [05_traits_and_extern_types.md](05_traits_and_extern_types.md) |

## Common Use Cases

### Calling C++ from Rust
See [07_bridge_macro.md](07_bridge_macro.md) - `extern "C++"` blocks

### Calling Rust from C++
See [07_bridge_macro.md](07_bridge_macro.md) - `extern "Rust"` blocks

### Sharing Data Structures
See [07_bridge_macro.md](07_bridge_macro.md) - Shared structs

### Memory Management
See [03_smart_pointers.md](03_smart_pointers.md) - Smart pointer types

### Error Handling
See [06_exception_handling.md](06_exception_handling.md) - Exception handling

### Type Safety
See [05_traits_and_extern_types.md](05_traits_and_extern_types.md) - ExternType trait

## Example: Basic Bridge

```rust
#[cxx::bridge]
mod ffi {
    // Shared struct (visible to both Rust and C++)
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

## Example: Error Handling

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        fn risky_operation(value: i32) -> Result<i32>;
    }
}

fn main() {
    match ffi::risky_operation(42) {
        Ok(result) => println!("Success: {}", result),
        Err(e) => eprintln!("C++ error: {}", e.what()),
    }
}
```

## Example: Smart Pointers

```rust
use cxx::UniquePtr;

#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("widget.h");

        type Widget;

        fn create_widget() -> UniquePtr<Widget>;
        fn get_name(widget: &Widget) -> String;
        fn set_name(widget: Pin<&mut Widget>, name: &str);
    }
}

fn main() {
    let mut widget = ffi::create_widget();
    println!("Name: {}", ffi::get_name(&widget));
    ffi::set_name(widget.pin_mut(), "MyWidget");
}
```

## Requirements

- **Rust:** 1.81+
- **C++:** C++11 or newer
- **License:** MIT OR Apache-2.0

## External Resources

- **Official Website:** https://cxx.rs
- **Repository:** https://github.com/dtolnay/cxx
- **API Documentation:** https://docs.rs/cxx/1.0.178/cxx/
- **Crate:** https://crates.io/crates/cxx

## Project Information

- **Version:** 1.0.178
- **Maintainer:** dtolnay
- **Documentation Coverage:** 100%
- **License:** MIT OR Apache-2.0

## Build Integration

### With Cargo

```toml
[dependencies]
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

```rust
// build.rs
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .flag_if_supported("-std=c++14")
        .compile("mybridge");

    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/mylib.cc");
    println!("cargo:rerun-if-changed=include/mylib.h");
}
```

### Without Cargo

Use the `cxxbridge` CLI tool for non-Cargo projects.

## Navigation Tips

1. **New to CXX?** Start with [00_overview.md](00_overview.md)
2. **Need to define a bridge?** See [07_bridge_macro.md](07_bridge_macro.md)
3. **Working with C++ objects?** Check [03_smart_pointers.md](03_smart_pointers.md)
4. **Handling errors?** Read [06_exception_handling.md](06_exception_handling.md)
5. **Sharing types across modules?** See [05_traits_and_extern_types.md](05_traits_and_extern_types.md)

---

*Documentation generated from https://docs.rs/cxx/1.0.178/cxx/ for offline reference and future Claude Code sessions.*
