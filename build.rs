use std::fs;
use std::fs::File;
use std::process::Command;

fn build_fizz() -> String {
    let fizz_rs_directory = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let fizz_directory = format!("{fizz_rs_directory}/third_party/fizz");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let install_dir = format!("{out_dir}/fizz-install");
    println!("cargo:warning=Building and installing fizz into {install_dir}");

    let output_file = File::create("/tmp/fizz.log")
        .expect("failed to create /tmp/fizz.log");

    let status = Command::new("python3")
        .current_dir(fizz_directory)
        .arg("build/fbcode_builder/getdeps.py")
        .args(&["--scratch-path", &install_dir])
        .arg("--allow-system-packages")
        .args(&["build", "fizz"])
        .stdout(output_file.try_clone().expect("could not clone /tmp/fizz.log"))
        .stderr(output_file)
        .status()
        .expect("Error executing build fizz command!");

    if !status.success() {
        println!("cargo::error=Could not build fizz, logs available at /tmp/fizz.log");
        panic!("Could not build fizz, logs available at /tmp/fizz.log. Make sure you installed system-wide dependencies first (check README file)");
    }

    install_dir
}

// Absolute paths to all the fizz dependencies in the scratch.
fn get_all_fizz_dependencies(fizz_install_dir: &str) -> Vec<String> {
    let mut fizz_dependencies = Vec::new();
    for path in fs::read_dir(format!("{fizz_install_dir}/installed")).unwrap() {
        let path = fs::canonicalize(path.unwrap().path()).unwrap();
        let path = path.to_str().unwrap();
        println!("cargo:warning={}", path);
        fizz_dependencies.push(path.to_owned());
    }
    fizz_dependencies
}

// Build our FFI bridge (src/bridge.rs and src/ffif/*.cpp) using cxx_build.
fn build_bridge(fizz_dependencies: &Vec<String>) {
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
    for path in fizz_dependencies {
        cxx.include(format!("{}/include", path));
    }

    // Compile the bridge library
    cxx.compile("fizz_rs_bridge");
}

fn main() {
    // Build fizz and install it and dependencies in the given directory.
    let fizz_install_dir = build_fizz();
    let fizz_dependencies = get_all_fizz_dependencies(&fizz_install_dir);

    // Build CXX bridge
    build_bridge(&fizz_dependencies);

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

    // Add lib directories for all fizz dependencies
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
