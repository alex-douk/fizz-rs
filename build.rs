use std::fs;

fn main() {
    // Absolute paths to all the fizz dependencies in the scratch.
    let mut fizz_dependencies = Vec::new();
    for path in fs::read_dir("third_party/fizz-install/installed").unwrap() {
        let path = fs::canonicalize(path.unwrap().path()).unwrap();
        let path = path.to_str().unwrap();
        println!("cargo:warning={}", path);
        fizz_dependencies.push(path.to_owned());
    }

    // Build the CXX bridge
    let mut cxx = cxx_build::bridge("src/bridge.rs");

    // Add compiler flags.
    cxx.warnings(false)
        // Add C++ FFI implementation files
        .file("src/ffi/certificates_ffi.cpp")
        .file("src/ffi/credentials_ffi.cpp")
        .file("src/ffi/server_tls_ffi.cpp")
        .file("src/ffi/client_tls_ffi.cpp")
        // Set C++ standard (Folly requires C++17)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("/std:c++17") // MSVC
        // Add include directories
        .include("src");  // For ffi/*.h headers

    // Add include directory of all fizz dependencies
    for path in &fizz_dependencies {
        cxx.include(format!("{}/include", path));
    }

    // Compile the bridge library
    cxx.compile("fizz_rs_bridge");

    // Link against required libraries
    println!("cargo:rustc-link-lib=fizz");
    println!("cargo:rustc-link-lib=folly");
    //println!("cargo:rustc-link-lib=unwind");
    //println!("cargo:rustc-link-lib=lzma");
    //println!("cargo:rustc-link-lib=oqs");
    println!("cargo:rustc-link-lib=fmt");
    println!("cargo:rustc-link-lib=event");
    println!("cargo:rustc-link-lib=double-conversion");
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

    // Add lib directories fro all fizz dependencies
    for path in &fizz_dependencies {
        println!("cargo:rustc-link-search=native={}/lib", path);
        println!("cargo::rustc-link-arg=-Wl,-rpath,{}/lib", path);
    }

    // Rerun build script if any of these files change
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=src/ffi/certificates_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/credentials_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/server_tls_ffi.cpp");
    println!("cargo:rerun-if-changed=src/ffi/client_tls_ffi.cpp");
}
