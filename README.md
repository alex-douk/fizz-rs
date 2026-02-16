# Fizz-rs

Rust FFI bindings for delegated credentials (DC) TLS with Fizz.

## Certificate and Keys

The underlying private key and SSL certificate must be explicilty configured to support delegated credentials (DC) at generation time.

We provide a `generate_certificate.sh` that generates a self-signed testing certificate with DC enabled.

Be sure to run the script to generate the testing certificate before running the example.
```bash
./generate_certificate.sh
cargo run --example generate_credential
```

### Dependencies

These dependencies need to be installed system-wide:

* [fizz](https://github.com/facebookincubator/fizz/): We used commit 2ba698d08cf0d42f4cfcb0a076e8a1ee8f3b8217, and added it as a gitsubmodule under `third_party/fizz/`.
* [folly](https://github.com/facebook/folly)
* glog, fmt
* libsodium, OpenSSL, libevent, and all other transitive dependencies of folly

We found that installing fizz's dependencies via the `build/fbcode_builder/getdeps.py` provided in fizz (see their repo for instructions) is sufficient to install all dependencies.

We recommend following these steps and seeing if they work. If not, you may need to do something more manual.

0. Ensure you ran `git clone` with `--recrusive` flag, or alternatively, that you updated all gitsubmodules

1. Build fizz and all its dependencies using our script (wrapper for `getdeps.py`)
```bash
cd third_party/ 
./build-fizz.sh
```

This may take a while, but when it is successfull, it will install some dependencies as system-wide dependencies (e.g. libevent), and build a handful of others and install them under `third_party/fizz-install`.

Our `build.rs` is configured to look for the `lib` and `include` subdirectories in that installation directory and add them.

If this does not work. Your best bet is to look at `build.rs` list of all libraries it needs to link with, and ensure they are installed as system wide dependencies.

2. Run `cargo build` to confirm include paths are set correctly.

3. Run `cargo test` and `cargo run --example generate_credential` to confirm everything works as intended.

### Notes

We used `-Wl,-rpath` to make sure that the generated binaries and tests can see `libglog.so.0`. This may not work
consistently when using this library as a transitive dependency with other cargo projects.

You may need to ensure that `LD_LIBRARY_PATH` is configured such that `libglog.so.0` is visible. You can find the exact version (or, retrieve and install the so youself) by looking at `third_party/fizz/glog-<hash>/lib`.
