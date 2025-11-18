fn main() {
    // Build the CXX bridge
    cxx_build::bridge("src/bridge.rs")
        // Add C++ FFI implementation files
        .file("src/ffi/certificates_ffi.cpp")
        .file("src/ffi/credentials_ffi.cpp")
        .file("src/ffi/server_tls_ffi.cpp")
        .file("src/ffi/client_tls_ffi.cpp")
        // Set C++ standard (Folly requires C++17)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("/std:c++17") // MSVC
        // Add include directories
        .include("include")
        .include("src")  // For ffi/*.h headers
        // Compile the bridge library
        .compile("fizz_rs_bridge");

    // Link against required libraries
    println!("cargo:rustc-link-lib=fizz");
    println!("cargo:rustc-link-lib=folly");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-lib=glog");
    println!("cargo:rustc-link-lib=gflags");
    println!("cargo:rustc-link-lib=sodium");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=boost_context");  // Required by Folly

    // Add library search paths (adjust as needed for your system)
    // These may need to be customized based on installation location
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/lib");

    // Rerun build script if any of these files change
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=src/ffi/certificates_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/credentials_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/server_tls_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/client_tls_ffi.cpp");
    println!("cargo:rerun-if-changed=include");
}
