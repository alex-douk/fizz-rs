# Build System Integration

This guide covers integrating CXX with various build systems, from Cargo to Bazel, CMake, and others.

---

## Cargo-based Build (Recommended)

### Basic Setup

**Cargo.toml:**
```toml
[package]
name = "my-crate"
version = "0.1.0"
edition = "2021"

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

    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/implementation.cc");
    println!("cargo:rerun-if-changed=include/mylib.h");
}
```

### Multiple Bridge Files

```rust
fn main() {
    // Build multiple bridges
    cxx_build::bridges(vec![
        "src/database.rs",
        "src/network.rs",
        "src/crypto.rs",
    ])
    .files(vec![
        "src/database.cc",
        "src/network.cc",
        "src/crypto.cc",
    ])
    .std("c++17")
    .compile("my-crate");

    // Rebuild triggers
    println!("cargo:rerun-if-changed=src/database.rs");
    println!("cargo:rerun-if-changed=src/network.rs");
    println!("cargo:rerun-if-changed=src/crypto.rs");
}
```

### Adding Include Directories

```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .include("include")           // Add include directory
        .include("/usr/local/include") // System includes
        .std("c++17")
        .compile("my-bridge");
}
```

### Compiler Flags

```rust
fn main() {
    let mut build = cxx_build::bridge("src/main.rs");

    build
        .file("src/mylib.cc")
        .flag("-Wall")
        .flag("-Wextra")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-O3");

    // Platform-specific flags
    if cfg!(target_os = "macos") {
        build.flag("-mmacosx-version-min=10.15");
    }

    build.compile("my-bridge");
}
```

### Linking External Libraries

```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .std("c++17")
        .compile("my-bridge");

    // Link system libraries
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    // Add library search path
    println!("cargo:rustc-link-search=/usr/local/lib");
}
```

### Custom Include Prefix

By default, C++ headers are accessed as `#include "crate-name/path/to/header.h"`. You can customize this:

```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .include_prefix("my-custom-prefix")  // Changes include path
        .compile("my-bridge");
}
```

To use an empty prefix (not recommended):

```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .include_prefix("")  // No prefix - risk of collisions
        .compile("my-bridge");
}
```

---

## Cross-Crate Dependencies

### Exporting Headers to Downstream Crates

When your crate provides C++ types that downstream crates need to use:

**Cargo.toml:**
```toml
[package]
name = "my-lib"
links = "mylib"  # Required for exporting headers

[dependencies]
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

**build.rs:**
```rust
fn main() {
    let mut build = cxx_build::bridge("src/lib.rs");

    build
        .file("src/mylib.cc")
        .include("include");

    // Export header directory to downstream crates
    build.exported_header_dirs(vec!["include"]);

    build.compile("mylib");

    // Make the link key available
    println!("cargo:rustc-link-lib=mylib");
}
```

**Downstream crate can now include:**
```cpp
#include "my-lib/include/mylib.h"
```

### Using Dependencies with Exported Headers

**Cargo.toml:**
```toml
[dependencies]
my-lib = "1.0"
cxx = "1.0"

[build-dependencies]
cxx-build = "1.0"
```

**build.rs:**
```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/main.cc")
        .compile("my-app");
}
```

**src/main.cc:**
```cpp
#include "my-lib/include/mylib.h"  // From dependency
#include "my-app/src/main.rs.h"    // Generated bridge
```

### Exporting Specific Dependencies

```rust
fn main() {
    let mut build = cxx_build::bridge("src/lib.rs");

    build
        .file("src/mylib.cc")
        .include("include")
        .include("third-party/boost");

    // Export specific header prefixes
    build.exported_header_prefixes(vec!["boost"]);

    // Or export by links key
    build.exported_header_links(vec!["boost"]);

    build.compile("mylib");
}
```

---

## Non-Cargo Build Systems

For projects not using Cargo, you need to:
1. Generate C++ bindings using `cxxbridge` CLI
2. Compile generated C++ code
3. Link everything together

### Installing cxxbridge CLI

```bash
cargo install cxxbridge-cmd
```

### Generating Bindings

**Generate header:**
```bash
cxxbridge src/main.rs --header > include/main.rs.h
```

**Generate implementation:**
```bash
cxxbridge src/main.rs > src/main.rs.cc
```

**Both at once:**
```bash
cxxbridge src/main.rs --header --output include/main.rs.h
cxxbridge src/main.rs --output src/main.rs.cc
```

### Version Matching

**Critical**: The `cxxbridge` version must match the `cxx` crate version used in your Rust code.

```bash
# Check versions match
cxxbridge --version
# Should match version in Cargo.toml
```

---

## CMake Integration

### Project Structure

```
my-project/
├── CMakeLists.txt
├── rust/
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
├── src/
│   ├── main.cpp
│   └── mylib.cc
└── include/
    └── mylib.h
```

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.15)
project(MyCxxProject CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Rust/Cargo
find_program(CARGO cargo REQUIRED)
find_program(CXXBRIDGE cxxbridge REQUIRED)

# Rust library target
set(RUST_LIB "${CMAKE_CURRENT_SOURCE_DIR}/rust")
set(RUST_TARGET_DIR "${CMAKE_BINARY_DIR}/rust")

# Build Rust library
add_custom_target(rust_lib ALL
    COMMAND ${CARGO} build --release --manifest-path ${RUST_LIB}/Cargo.toml
            --target-dir ${RUST_TARGET_DIR}
    WORKING_DIRECTORY ${RUST_LIB}
    COMMENT "Building Rust library"
)

# Generate CXX bridge
set(BRIDGE_HEADER "${CMAKE_BINARY_DIR}/include/lib.rs.h")
set(BRIDGE_SOURCE "${CMAKE_BINARY_DIR}/src/lib.rs.cc")

add_custom_command(
    OUTPUT ${BRIDGE_HEADER}
    COMMAND ${CXXBRIDGE} ${RUST_LIB}/src/lib.rs --header -o ${BRIDGE_HEADER}
    DEPENDS ${RUST_LIB}/src/lib.rs
    COMMENT "Generating CXX bridge header"
)

add_custom_command(
    OUTPUT ${BRIDGE_SOURCE}
    COMMAND ${CXXBRIDGE} ${RUST_LIB}/src/lib.rs -o ${BRIDGE_SOURCE}
    DEPENDS ${RUST_LIB}/src/lib.rs
    COMMENT "Generating CXX bridge source"
)

# C++ executable
add_executable(myapp
    src/main.cpp
    src/mylib.cc
    ${BRIDGE_SOURCE}
)

target_include_directories(myapp PRIVATE
    include
    ${CMAKE_BINARY_DIR}/include
    ${RUST_TARGET_DIR}/cxxbridge  # CXX runtime headers
)

# Link Rust library
if(WIN32)
    set(RUST_LIB_FILE "${RUST_TARGET_DIR}/release/my_rust_lib.lib")
else()
    set(RUST_LIB_FILE "${RUST_TARGET_DIR}/release/libmy_rust_lib.a")
endif()

target_link_libraries(myapp PRIVATE
    ${RUST_LIB_FILE}
    pthread
    dl
)

add_dependencies(myapp rust_lib)
```

### Building with CMake

```bash
mkdir build
cd build
cmake ..
cmake --build .
./myapp
```

---

## Bazel Integration

### WORKSPACE

```python
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Rust rules
http_archive(
    name = "rules_rust",
    sha256 = "...",
    urls = ["..."],
)

load("@rules_rust//rust:repositories.bzl", "rust_repositories")

rust_repositories()

# CXX
http_archive(
    name = "cxx.rs",
    urls = ["https://github.com/dtolnay/cxx/archive/refs/tags/1.0.XX.tar.gz"],
    strip_prefix = "cxx-1.0.XX",
)
```

### BUILD.bazel

```python
load("@rules_rust//rust:defs.bzl", "rust_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_binary")

# Rust library with CXX bridge
rust_library(
    name = "my_rust_lib",
    srcs = ["src/lib.rs"],
    deps = [
        "@cxx.rs//:cxx",
    ],
    edition = "2021",
)

# Generate CXX bridge
genrule(
    name = "gen_bridge",
    srcs = ["src/lib.rs"],
    outs = [
        "lib.rs.h",
        "lib.rs.cc",
    ],
    cmd = """
        $(location @cxx.rs//:cxxbridge) $(location src/lib.rs) --header > $(location lib.rs.h)
        $(location @cxx.rs//:cxxbridge) $(location src/lib.rs) > $(location lib.rs.cc)
    """,
    tools = ["@cxx.rs//:cxxbridge"],
)

# C++ library
cc_library(
    name = "mylib",
    srcs = [
        "src/mylib.cc",
        ":gen_bridge",
    ],
    hdrs = [
        "include/mylib.h",
    ],
    includes = [
        "include",
    ],
    deps = [
        "@cxx.rs//:cxx_cc",
    ],
)

# Final binary
cc_binary(
    name = "myapp",
    srcs = ["src/main.cpp"],
    deps = [
        ":mylib",
        ":my_rust_lib",
    ],
)
```

---

## Buck2 Integration

### BUCK

```python
rust_library(
    name = "my_rust_lib",
    srcs = ["src/lib.rs"],
    deps = [
        "//third-party:cxx",
    ],
)

cxx_bridge(
    name = "bridge",
    src = "src/lib.rs",
)

cxx_library(
    name = "mylib",
    srcs = [
        "src/mylib.cc",
        ":bridge[source]",
    ],
    headers = [
        "include/mylib.h",
        ":bridge[header]",
    ],
    deps = [
        "//third-party:cxx",
    ],
)

cxx_binary(
    name = "myapp",
    srcs = ["src/main.cpp"],
    deps = [
        ":mylib",
        ":my_rust_lib",
    ],
)
```

---

## Advanced Build Configurations

### Conditional Compilation

```rust
fn main() {
    let mut build = cxx_build::bridge("src/main.rs");

    build.file("src/common.cc");

    // Platform-specific files
    if cfg!(target_os = "linux") {
        build.file("src/linux.cc");
        println!("cargo:rustc-link-lib=pthread");
    } else if cfg!(target_os = "windows") {
        build.file("src/windows.cc");
        println!("cargo:rustc-link-lib=ws2_32");
    } else if cfg!(target_os = "macos") {
        build.file("src/macos.cc");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }

    // Feature gates
    if cfg!(feature = "networking") {
        build.file("src/network.cc");
        println!("cargo:rustc-link-lib=ssl");
    }

    build.compile("my-crate");
}
```

### Environment Variables

```rust
fn main() {
    let mut build = cxx_build::bridge("src/main.rs");

    // Use environment variable for custom includes
    if let Ok(custom_include) = std::env::var("CUSTOM_INCLUDE_PATH") {
        build.include(custom_include);
    }

    // Custom C++ standard
    let cpp_std = std::env::var("CPP_STD").unwrap_or_else(|_| "c++17".to_string());
    build.std(&cpp_std);

    build.file("src/mylib.cc").compile("my-crate");
}
```

### Warnings and Optimizations

```rust
fn main() {
    let mut build = cxx_build::bridge("src/main.rs");

    build
        .file("src/mylib.cc")
        .warnings(true)           // Enable warnings
        .warnings_into_errors(false)  // Don't fail on warnings
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wpedantic");

    // Optimization level
    if !cfg!(debug_assertions) {
        build.opt_level(3);
        build.flag("-O3");
    }

    build.compile("my-crate");
}
```

### Static vs Dynamic Linking

```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .compile("my-crate");

    // Static linking (default)
    println!("cargo:rustc-link-lib=static=myexternallib");

    // Dynamic linking
    println!("cargo:rustc-link-lib=dylib=ssl");

    // Framework (macOS)
    println!("cargo:rustc-link-lib=framework=Security");
}
```

---

## Troubleshooting

### Common Issues

#### 1. Include Path Not Found

```
error: 'mylib/myclass.h' file not found
```

**Solution:**
```rust
cxx_build::bridge("src/main.rs")
    .file("src/mylib.cc")
    .include("include")  // Add include directory
    .compile("my-crate");
```

#### 2. Linking Errors

```
undefined reference to `some_function`
```

**Solution:**
```rust
// Add library
println!("cargo:rustc-link-lib=mylib");

// Add search path
println!("cargo:rustc-link-search=/path/to/lib");
```

#### 3. C++ Standard Mismatch

```
error: use of undeclared identifier 'make_unique'
```

**Solution:**
```rust
cxx_build::bridge("src/main.rs")
    .file("src/mylib.cc")
    .std("c++14")  // Need C++14 for make_unique
    .compile("my-crate");
```

#### 4. Version Mismatch (Non-Cargo)

```
error: cxx version mismatch
```

**Solution:** Ensure `cxxbridge` version matches `cxx` crate version:
```bash
cargo install cxxbridge-cmd --version 1.0.XX
```

### Debug Build Output

```rust
fn main() {
    let mut build = cxx_build::bridge("src/main.rs");

    build
        .file("src/mylib.cc")
        .flag("-v")  // Verbose compilation
        .compile("my-crate");

    // Print generated files location
    println!("cargo:warning=Generated files in: target/cxxbridge/");
}
```

---

## Best Practices

### 1. Organized File Structure

```
my-crate/
├── Cargo.toml
├── build.rs
├── include/
│   └── my-crate/        # Namespace headers
│       ├── public.h
│       └── types.h
├── src/
│   ├── lib.rs           # Bridge definition
│   ├── implementation.cc # C++ implementation
│   └── helpers.cc        # Additional C++ files
└── tests/
    └── integration.rs
```

### 2. Rebuild Triggers

Always add rebuild triggers for all source files:

```rust
println!("cargo:rerun-if-changed=src/lib.rs");
println!("cargo:rerun-if-changed=src/mylib.cc");
println!("cargo:rerun-if-changed=include/mylib.h");
```

### 3. Feature Gates

```toml
[features]
default = []
networking = []
tls = ["networking"]
```

```rust
fn main() {
    let mut sources = vec!["src/core.cc"];

    if cfg!(feature = "networking") {
        sources.push("src/network.cc");
    }

    if cfg!(feature = "tls") {
        sources.push("src/tls.cc");
        println!("cargo:rustc-link-lib=ssl");
    }

    cxx_build::bridge("src/lib.rs")
        .files(sources)
        .compile("my-crate");
}
```

### 4. Cross-Platform Compatibility

```rust
fn main() {
    let mut build = cxx_build::bridge("src/lib.rs");

    build.file("src/common.cc");

    match std::env::consts::OS {
        "linux" => {
            build.file("src/platform/linux.cc");
            build.define("PLATFORM_LINUX", None);
        }
        "macos" => {
            build.file("src/platform/macos.cc");
            build.define("PLATFORM_MACOS", None);
        }
        "windows" => {
            build.file("src/platform/windows.cc");
            build.define("PLATFORM_WINDOWS", None);
        }
        _ => {}
    }

    build.compile("my-crate");
}
```
