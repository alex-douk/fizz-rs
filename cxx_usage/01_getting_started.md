# Getting Started with CXX

## What is CXX?

CXX is a library that enables **safe interoperability between Rust and C++** without the pitfalls of traditional FFI approaches. It provides:

- **Static analysis** and code generation for safe FFI bridges
- **Zero-overhead** operation with idiomatic APIs for both languages
- **Built-in bindings** for standard library types (strings, vectors, smart pointers)
- **Compile-time safety** guarantees that catch errors before runtime

## Why CXX?

### The Triangle Metaphor

Consider Rust, C, and C++ as vertices of a triangle where edge length represents language similarity. The Rust–C++ edge is the shortest because both languages share compatible concepts:

- Ownership and borrowing semantics
- Vectors and strings
- Error handling patterns
- Smart pointers

### Traditional Approach (via C)

Traditional bindgen/cbindgen approaches require:
1. Descending from C++ to C (losing type safety and idiomatic features)
2. Ascending from C to Rust (rebuilding safety with unsafe code)

This means coding "the two longest edges of the triangle" with extensive unsafe code.

### CXX Approach

CXX is the **midpoint of the Rust–C++ edge**, allowing you to:
- Write idiomatic Rust code
- Write idiomatic C++ code
- Let the compiler catch errors at both boundaries
- Use rich standard library types naturally

**Key principle**: "Anything you could do wrong in Rust, and almost anything you could reasonably do wrong in C++, will be caught by the compiler."

---

## Quick Start Tutorial

### Step 1: Create a Cargo Project

```bash
cargo new cxx-demo
cd cxx-demo
```

### Step 2: Add Dependencies

**Cargo.toml:**
```toml
[package]
name = "cxx-demo"
version = "0.1.0"
edition = "2021"

[dependencies]
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

### Step 3: Create Build Script

**build.rs:**
```rust
fn main() {
    cxx_build::bridge("src/main.rs")  // Rust bridge file
        .file("src/blobstore.cc")      // C++ implementation
        .std("c++14")                   // C++ standard
        .compile("cxx-demo");           // Output library name

    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/blobstore.cc");
    println!("cargo:rerun-if-changed=include/blobstore.h");
}
```

### Step 4: Define the Bridge

**src/main.rs:**
```rust
#[cxx::bridge]
mod ffi {
    // Shared struct - visible to both Rust and C++
    struct BlobMetadata {
        size: usize,
        tags: Vec<String>,
    }

    // C++ types and functions
    unsafe extern "C++" {
        include!("cxx-demo/blobstore.h");

        type BlobstoreClient;

        fn new_blobstore_client() -> UniquePtr<BlobstoreClient>;
        fn put(&self, parts: &mut MultiBuf) -> u64;
        fn tag(&self, blobid: u64, tag: &str);
        fn metadata(&self, blobid: u64) -> BlobMetadata;
    }

    // Rust types and functions
    extern "Rust" {
        type MultiBuf;

        fn next_chunk(buf: &mut MultiBuf) -> &[u8];
    }
}

// Rust implementation
pub struct MultiBuf {
    chunks: Vec<Vec<u8>>,
    pos: usize,
}

fn next_chunk(buf: &mut MultiBuf) -> &[u8] {
    let next = buf.chunks.get(buf.pos);
    buf.pos += 1;
    next.map(Vec::as_slice).unwrap_or(&[])
}

fn main() {
    let client = ffi::new_blobstore_client();

    // Add some data
    let chunks = vec![b"fearless".to_vec(), b"concurrency".to_vec()];
    let mut buf = MultiBuf { chunks, pos: 0 };

    let blobid = client.put(&mut buf);
    println!("blobid = {}", blobid);

    client.tag(blobid, "rust");

    let metadata = client.metadata(blobid);
    println!("tags = {:?}", metadata.tags);
}
```

### Step 5: Write C++ Header

**include/blobstore.h:**
```cpp
#pragma once
#include "rust/cxx.h"
#include <memory>

class BlobstoreClient {
public:
    BlobstoreClient();
    uint64_t put(MultiBuf& buf);
    void tag(uint64_t blobid, rust::Str tag);
    BlobMetadata metadata(uint64_t blobid);

private:
    class impl;
    std::shared_ptr<impl> impl_;
};

std::unique_ptr<BlobstoreClient> new_blobstore_client();
```

### Step 6: Write C++ Implementation

**src/blobstore.cc:**
```cpp
#include "cxx-demo/blobstore.h"
#include "cxx-demo/src/main.rs.h"
#include <algorithm>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>

// Implementations would go here
class BlobstoreClient::impl {
    friend BlobstoreClient;
    std::unordered_map<uint64_t, rust::Vec<uint8_t>> blobs;
    std::unordered_map<uint64_t, std::set<rust::String>> tags;
    uint64_t next_id = 1;
};

BlobstoreClient::BlobstoreClient() : impl_(new impl) {}

uint64_t BlobstoreClient::put(MultiBuf& buf) {
    rust::Vec<uint8_t> contents;

    // Collect chunks by calling back to Rust
    for (;;) {
        auto chunk = next_chunk(buf);
        if (chunk.size() == 0) {
            break;
        }
        contents.reserve(contents.size() + chunk.size());
        std::copy(chunk.begin(), chunk.end(), std::back_inserter(contents));
    }

    uint64_t blobid = impl_->next_id++;
    impl_->blobs[blobid] = std::move(contents);
    return blobid;
}

void BlobstoreClient::tag(uint64_t blobid, rust::Str tag) {
    impl_->tags[blobid].emplace(tag);
}

BlobMetadata BlobstoreClient::metadata(uint64_t blobid) const {
    BlobMetadata metadata{};
    metadata.size = impl_->blobs[blobid].size();
    metadata.tags.reserve(impl_->tags[blobid].size());
    for (auto& tag : impl_->tags[blobid]) {
        metadata.tags.push_back(rust::String(tag));
    }
    return metadata;
}

std::unique_ptr<BlobstoreClient> new_blobstore_client() {
    return std::make_unique<BlobstoreClient>();
}
```

### Step 7: Build and Run

```bash
cargo build
cargo run
```

**Expected output:**
```
blobid = 1
tags = ["rust"]
```

---

## Understanding Generated Code

### Generated Files Location

CXX generates intermediate files in `target/cxxbridge/`:

```
target/cxxbridge/
├── cxx-demo/
│   └── src/
│       ├── main.rs.cc    # Generated C++ implementation
│       └── main.rs.h     # Generated C++ header
└── rust/
    └── cxx.h              # CXX runtime library header
```

### What Gets Generated

#### Rust Side
- `#[repr(C)]` structs with proper layout
- `#[link_name]` attributes for C calling convention
- Type-safe wrappers around FFI functions

#### C++ Side
- Header file (`main.rs.h`) with declarations matching the bridge
- Implementation file (`main.rs.cc`) with glue code
- Type conversions and safety checks

### Include Paths in C++

C++ code includes the generated headers:
```cpp
#include "crate-name/src/main.rs.h"
```

The include path follows the pattern:
```
<crate-name>/<path-to-rust-file>.rs.h
```

---

## Key Concepts

### 1. The Bridge Module

The `#[cxx::bridge]` attribute defines the FFI boundary:

```rust
#[cxx::bridge]
mod ffi {
    // Bridge declarations
}
```

All FFI declarations go inside this module.

### 2. Three Types of FFI Items

#### Shared Structs
Data structures visible to both languages with identical layout:

```rust
struct Data {
    value: i32,
    name: String,
}
```

#### Opaque Types
Types where implementation details are hidden from the other language:

```rust
extern "C++" {
    type CppType;  // Opaque to Rust
}

extern "Rust" {
    type RustType;  // Opaque to C++
}
```

#### Functions
Functions callable across the boundary:

```rust
extern "C++" {
    fn cpp_function() -> i32;
}

extern "Rust" {
    fn rust_function() -> i32;
}
```

### 3. Ownership Semantics

CXX preserves ownership semantics from both languages:

- **UniquePtr** for exclusive ownership (like `std::unique_ptr`)
- **SharedPtr** for shared ownership (like `std::shared_ptr`)
- **References** for borrowing (`&T`, `&mut T`, `Pin<&mut T>`)

### 4. Safety Guarantees

- Rust side is **100% safe** - no `unsafe` blocks needed in user code
- C++ side errors are caught by **static assertions** at compile time
- Type mismatches cause **compilation failures**, not runtime crashes

---

## Common Patterns

### Pattern 1: Opaque C++ Object with Methods

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        type Database;

        fn connect(url: &str) -> UniquePtr<Database>;
        fn query(self: &Database, sql: &str) -> Vec<String>;
        fn execute(self: Pin<&mut Database>, sql: &str) -> Result<()>;
    }
}
```

### Pattern 2: Shared Data Structure

```rust
#[cxx::bridge]
mod ffi {
    struct Config {
        host: String,
        port: u16,
        timeout_ms: u32,
    }

    unsafe extern "C++" {
        include!("server.h");
        fn start_server(config: Config) -> bool;
    }
}
```

### Pattern 3: Callback to Rust from C++

```rust
#[cxx::bridge]
mod ffi {
    extern "Rust" {
        type Logger;
        fn log(logger: &Logger, message: &str);
    }

    unsafe extern "C++" {
        include!("processor.h");
        fn process_data(logger: &Logger, data: &[u8]);
    }
}

pub struct Logger;

fn log(logger: &Logger, message: &str) {
    println!("[LOG] {}", message);
}
```

---

## Next Steps

- **[02_writing_cpp_for_rust.md](02_writing_cpp_for_rust.md)** - Detailed guide on implementing C++ code for Rust
- **[03_build_integration.md](03_build_integration.md)** - Build system setup and configuration
- **[04_async_interop.md](04_async_interop.md)** - Async/await patterns and futures
- **[05_advanced_patterns.md](05_advanced_patterns.md)** - Advanced usage patterns and best practices
