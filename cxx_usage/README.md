# CXX Usage Guide

**Comprehensive documentation for using CXX to write C++ code that interoperates with Rust.**

This directory contains practical, usage-focused documentation extracted from https://cxx.rs/, with extensive coverage of asynchronous interoperability patterns.

---

## What is CXX?

CXX enables **safe interoperability between Rust and C++** through:

- **Static analysis** and paired code generation
- **Zero-overhead** FFI bridges
- **Idiomatic APIs** for both languages
- **Compile-time safety** guarantees

**Core Philosophy**: "Anything you could do wrong in Rust, and almost anything you could reasonably do wrong in C++, will be caught by the compiler."

---

## Documentation Files

### 1. Getting Started
**[01_getting_started.md](01_getting_started.md)** - Complete introduction and tutorial

**Contents:**
- Quick start tutorial with complete working example
- Understanding the bridge mechanism
- Three types of FFI items (shared structs, opaque types, functions)
- Common patterns and idioms
- Project setup and build configuration

**Start here if you're new to CXX!**

---

### 2. Writing C++ for Rust
**[02_writing_cpp_for_rust.md](02_writing_cpp_for_rust.md)** - Comprehensive C++ implementation guide

**Contents:**
- Setting up C++ files and headers
- Working with CXX types (`rust::String`, `rust::Vec`, `rust::Slice`)
- Smart pointers (`UniquePtr`, `SharedPtr`)
- Implementing methods and functions
- Exception handling
- Calling Rust from C++
- PIMPL pattern and RAII
- Best practices for modern C++

**Essential reading for C++ developers working with Rust.**

---

### 3. Async/Await Interoperability
**[03_async_interop.md](03_async_interop.md)** - **Extended documentation on async patterns**

**Contents:**
- Current state of async support
- Conceptual background (Rust futures vs C++ async models)
- **Pattern 1**: Oneshot channel (single async result)
- **Pattern 2**: Multi-shot channel (streams of results)
- **Pattern 3**: Blocking bridge with spawn_blocking
- **Pattern 4**: Future executor bridge
- **Pattern 5**: C++20 coroutines to Rust futures
- Complete async HTTP client example
- Best practices and common pitfalls

**Critical reading for async Rust applications using C++ libraries.**

---

### 4. Build System Integration
**[04_build_integration.md](04_build_integration.md)** - Build configuration and multi-platform support

**Contents:**
- Cargo-based builds (recommended)
- Cross-crate dependencies
- Non-Cargo build systems (CMake, Bazel, Buck2)
- Using `cxxbridge` CLI
- Compiler flags and optimization
- Platform-specific builds
- Linking external libraries
- Troubleshooting build issues

**Essential for project setup and CI/CD integration.**

---

### 5. Advanced Patterns
**[05_advanced_patterns.md](05_advanced_patterns.md)** - Advanced techniques and best practices

**Contents:**
- Namespace management
- Renaming types and functions (`cxx_name`, `rust_name`)
- Enums (simple, with discriminants, extern)
- Complex shared structs
- Opaque type patterns with `ExternType`
- Function pointers and callbacks
- Error handling patterns
- Resource management (RAII, shared resources)
- Performance optimization (zero-copy, bulk operations)
- Testing strategies
- Debugging and profiling

**For experienced users and complex integration scenarios.**

---

## Quick Reference

### Common Use Cases

| Use Case | Documentation |
|----------|---------------|
| "I'm new to CXX" | Start with [01_getting_started.md](01_getting_started.md) |
| "How do I implement C++ for Rust?" | See [02_writing_cpp_for_rust.md](02_writing_cpp_for_rust.md) |
| "How do I handle async operations?" | Read [03_async_interop.md](03_async_interop.md) |
| "How do I set up my build?" | Check [04_build_integration.md](04_build_integration.md) |
| "How do I handle namespaces/enums?" | See [05_advanced_patterns.md](05_advanced_patterns.md) |

### Type Quick Reference

| Rust Type | C++ Type | Usage |
|-----------|----------|-------|
| `&str` | `rust::Str` | Read-only string view |
| `String` | `rust::String` | Owned string |
| `&[T]` | `rust::Slice<const T>` | Read-only slice |
| `&mut [T]` | `rust::Slice<T>` | Mutable slice |
| `Vec<T>` | `rust::Vec<T>` | Owned vector |
| `Box<T>` | `rust::Box<T>` | Owned Rust type |
| `UniquePtr<T>` | `std::unique_ptr<T>` | Owned C++ type |
| `SharedPtr<T>` | `std::shared_ptr<T>` | Shared C++ type |

See [02_writing_cpp_for_rust.md](02_writing_cpp_for_rust.md) for detailed type documentation.

### Async Pattern Quick Reference

| Pattern | Use Case | Documentation |
|---------|----------|---------------|
| Oneshot Channel | Single async result from C++ | [03_async_interop.md](03_async_interop.md#pattern-1-oneshot-channel-single-result) |
| Multi-shot Channel | Stream of events from C++ | [03_async_interop.md](03_async_interop.md#pattern-2-multi-shot-channel-stream-of-results) |
| Spawn Blocking | Blocking C++ in async Rust | [03_async_interop.md](03_async_interop.md#pattern-3-blocking-bridge-spawn-blocking) |
| Executor Bridge | Run Rust async from C++ | [03_async_interop.md](03_async_interop.md#pattern-4-future-executor-bridge) |
| C++20 Coroutines | Bridge coroutines to futures | [03_async_interop.md](03_async_interop.md#pattern-5-c20-coroutines-to-rust-futures) |

---

## Example: Basic Bridge

### Rust Side

```rust
#[cxx::bridge]
mod ffi {
    // Shared struct
    struct BlobMetadata {
        size: usize,
        tags: Vec<String>,
    }

    // C++ types and functions
    unsafe extern "C++" {
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
```

### C++ Side

```cpp
#include "my-crate/blobstore.h"
#include "my-crate/src/main.rs.h"

class BlobstoreClient {
    // Implementation...
};

std::unique_ptr<BlobstoreClient> new_blobstore_client() {
    return std::make_unique<BlobstoreClient>();
}

uint64_t BlobstoreClient::put(MultiBuf& buf) {
    rust::Vec<uint8_t> contents;

    // Call back to Rust
    for (;;) {
        auto chunk = next_chunk(buf);
        if (chunk.size() == 0) break;
        contents.insert(contents.end(), chunk.begin(), chunk.end());
    }

    // Store and return blob ID...
}
```

See [01_getting_started.md](01_getting_started.md) for complete tutorial.

---

## Example: Async HTTP Client

### Rust Side (Async)

```rust
use futures::channel::oneshot;

#[cxx::bridge]
mod ffi {
    struct HttpResponse {
        status: i32,
        body: Vec<u8>,
    }

    extern "Rust" {
        type HttpContext;
    }

    unsafe extern "C++" {
        include!("http.h");

        fn http_get_async(
            url: &str,
            callback: fn(Box<HttpContext>, HttpResponse),
            context: Box<HttpContext>,
        );
    }
}

pub struct HttpContext {
    sender: oneshot::Sender<Result<ffi::HttpResponse, String>>,
}

pub async fn http_get(url: &str) -> Result<ffi::HttpResponse, String> {
    let (sender, receiver) = oneshot::channel();
    let context = Box::new(HttpContext { sender });

    ffi::http_get_async(url, handle_response, context);

    receiver.await.map_err(|_| "Channel closed".to_string())?
}

fn handle_response(context: Box<HttpContext>, response: ffi::HttpResponse) {
    let _ = context.sender.send(Ok(response));
}
```

### C++ Side (Async)

```cpp
#include "my-crate/src/main.rs.h"
#include <thread>

void http_get_async(
    rust::Str url,
    rust::Fn<void(rust::Box<HttpContext>, HttpResponse)> callback,
    rust::Box<HttpContext> context
) {
    std::thread([
        url = std::string(url),
        callback = std::move(callback),
        context = std::move(context)
    ]() mutable {
        // Perform HTTP request...
        HttpResponse response;
        response.status = 200;
        // ... fill response ...

        callback(std::move(context), std::move(response));
    }).detach();
}
```

See [03_async_interop.md](03_async_interop.md) for complete async patterns.

---

## Key Concepts

### The Bridge Module

The `#[cxx::bridge]` attribute defines the FFI boundary between Rust and C++:

```rust
#[cxx::bridge]
mod ffi {
    // All FFI declarations go here
}
```

### Three Types of FFI Items

1. **Shared Structs** - Data visible to both languages
2. **Opaque Types** - Implementation hidden from other language
3. **Functions** - Callable across the boundary

See [01_getting_started.md](01_getting_started.md#key-concepts) for details.

### Safety Guarantees

- **Rust side**: 100% safe - no unsafe blocks needed
- **C++ side**: Static assertions catch errors at compile time
- **Type mismatches**: Cause compilation failures, not runtime crashes

---

## Build Setup

### Cargo (Recommended)

**Cargo.toml:**
```toml
[dependencies]
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

**build.rs:**
```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/implementation.cc")
        .std("c++14")
        .compile("my-bridge");
}
```

See [04_build_integration.md](04_build_integration.md) for complete build documentation.

### Non-Cargo Build Systems

CXX supports CMake, Bazel, Buck2, and other build systems via the `cxxbridge` CLI tool.

See [04_build_integration.md](04_build_integration.md#non-cargo-build-systems) for details.

---

## Async Interoperability

### Current Status

Native async support (`async fn` in bridge) is **not yet implemented**. However, robust patterns exist for bridging async operations.

### Recommended Pattern: Oneshot Channel

**For single async results from C++:**

```rust
use futures::channel::oneshot;

pub async fn fetch_data(url: &str) -> Result<Vec<u8>, String> {
    let (sender, receiver) = oneshot::channel();
    let context = Box::new(AsyncContext { sender });

    ffi::fetch_async(url, handle_result, context);

    receiver.await.map_err(|_| "Cancelled".to_string())?
}
```

See [03_async_interop.md](03_async_interop.md) for **comprehensive async documentation**.

---

## Best Practices

### 1. Keep Bridge Interface Minimal

```rust
// ✓ Good: Small, focused interface
unsafe extern "C++" {
    type Database;
    fn connect(url: &str) -> UniquePtr<Database>;
    fn query(db: &Database, sql: &str) -> Vec<String>;
}
```

### 2. Use Shared Structs for Data

```rust
// ✓ Good: Single struct
struct Config { host: String, port: u16 }
fn connect(config: Config);

// ✗ Avoid: Many parameters
fn connect(host: &str, port: u16, ...);
```

### 3. Prefer Slices for Zero-Copy

```rust
// ✓ Good: Zero-copy
fn process(data: &[u8]) -> i32;

// ✗ Avoid: Unnecessary copy
fn process(data: Vec<u8>) -> i32;
```

### 4. Handle Errors Properly

```cpp
// ✓ Good: Descriptive
throw std::invalid_argument("Invalid URL: " + url);

// ✗ Bad: Generic
throw std::runtime_error("Error");
```

### 5. Document the Bridge

```rust
#[cxx::bridge]
mod ffi {
    /// Opens database connection.
    ///
    /// # Errors
    /// Throws if URL invalid or connection fails.
    unsafe extern "C++" {
        fn connect(url: &str) -> Result<UniquePtr<Database>>;
    }
}
```

See [05_advanced_patterns.md](05_advanced_patterns.md#best-practices-summary) for more best practices.

---

## Common Pitfalls

### 1. Blocking the Async Runtime

```rust
// ✗ Bad: Blocks runtime
async fn bad() {
    ffi::blocking_call();  // Blocks!
}

// ✓ Good: Use spawn_blocking
async fn good() {
    tokio::task::spawn_blocking(|| {
        ffi::blocking_call()
    }).await.unwrap()
}
```

### 2. Lifetime Issues in C++

```cpp
// ✗ Bad: Dangling reference
std::thread([&context]() {  // context destroyed!
    use(context);
}).detach();

// ✓ Good: Move ownership
std::thread([context = std::move(context)]() mutable {
    use(context);
}).detach();
```

### 3. Missing Exception Handling

```cpp
// ✗ Bad: Can throw but not marked Result
int32_t risky();

// ✓ Good: Properly marked
Result<int32_t> risky();
```

See individual documentation files for more pitfalls and solutions.

---

## Requirements

- **Rust**: 1.81+
- **C++**: C++11 or newer (C++14+ recommended, C++17+ for async patterns)
- **Build tool**: Cargo (recommended) or cxxbridge CLI

---

## External Resources

- **Official Website**: https://cxx.rs
- **Repository**: https://github.com/dtolnay/cxx
- **API Documentation**: https://docs.rs/cxx
- **Crate**: https://crates.io/crates/cxx

---

## Navigation Guide

### I want to...

**Learn CXX basics**
→ Start with [01_getting_started.md](01_getting_started.md)

**Implement C++ code for Rust**
→ Read [02_writing_cpp_for_rust.md](02_writing_cpp_for_rust.md)

**Handle async operations**
→ Study [03_async_interop.md](03_async_interop.md)

**Set up my build system**
→ Check [04_build_integration.md](04_build_integration.md)

**Use advanced features (namespaces, enums, etc.)**
→ See [05_advanced_patterns.md](05_advanced_patterns.md)

**Debug build issues**
→ [04_build_integration.md](04_build_integration.md#troubleshooting)

**Optimize performance**
→ [05_advanced_patterns.md](05_advanced_patterns.md#performance-patterns)

**Write tests**
→ [05_advanced_patterns.md](05_advanced_patterns.md#testing-patterns)

---

## Documentation Focus

This documentation emphasizes:

1. **Writing C++ for Rust** - How to implement C++ code that Rust can safely call
2. **Async Interoperability** - Extensive coverage of async/await patterns
3. **Practical Examples** - Real-world code samples throughout
4. **Best Practices** - Guidance based on production usage
5. **Complete Coverage** - From basics to advanced patterns

---

*Documentation extracted from https://cxx.rs/ with extended async/await coverage for production Rust applications using C++ libraries.*
