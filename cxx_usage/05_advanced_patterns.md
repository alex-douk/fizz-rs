# Advanced CXX Patterns

This guide covers advanced usage patterns, best practices, and techniques for effective Rust-C++ interoperability.

---

## Namespaces

### Basic Namespace Usage

**Bridge:**
```rust
#[cxx::bridge(namespace = "mycompany::myapp")]
mod ffi {
    extern "Rust" {
        type RustType;
        fn rust_function() -> i32;
    }

    unsafe extern "C++" {
        include!("mylib.h");

        type CppType;
        fn cpp_function() -> i32;
    }
}
```

**Generated C++:**
```cpp
namespace mycompany {
namespace myapp {
    // Rust types and functions are in this namespace
    struct RustType;
    int32_t rust_function();
}
}
```

### Per-Block Namespaces

```rust
#[cxx::bridge]
mod ffi {
    #[namespace = "database"]
    unsafe extern "C++" {
        include!("db.h");
        type Connection;
        fn connect() -> UniquePtr<Connection>;
    }

    #[namespace = "network"]
    unsafe extern "C++" {
        include!("net.h");
        type Socket;
        fn bind(port: u16) -> UniquePtr<Socket>;
    }
}
```

### Per-Item Namespaces

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        #[namespace = "mycompany::v1"]
        type OldApi;

        #[namespace = "mycompany::v2"]
        type NewApi;

        #[namespace = "mycompany::v1"]
        fn old_function() -> i32;

        #[namespace = "mycompany::v2"]
        fn new_function() -> i32;
    }
}
```

### Nested Namespace Priority

```rust
// Bridge-level namespace
#[cxx::bridge(namespace = "company")]
mod ffi {
    // Block-level overrides bridge-level
    #[namespace = "company::app"]
    unsafe extern "C++" {
        include!("mylib.h");

        // Item-level overrides block-level
        #[namespace = "company::app::internal"]
        type InternalType;

        // Uses block-level namespace
        type PublicType;
    }
}
```

---

## Renaming Types and Functions

### C++ Name Different from Rust Name

**Use case**: Binding overloaded C++ functions or avoiding naming conflicts.

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        // C++ has process(int), process(double)
        #[cxx_name = "process"]
        fn process_int(value: i32) -> i32;

        #[cxx_name = "process"]
        fn process_double(value: f64) -> f64;

        // Rename type for clarity in Rust
        #[cxx_name = "DatabaseConnection"]
        type DbConn;
    }
}
```

**C++ side:**
```cpp
int32_t process(int32_t value);
double process(double value);

class DatabaseConnection {
    // ...
};
```

### Rust Name Different from C++ Name

```rust
#[cxx::bridge]
mod ffi {
    extern "Rust" {
        // Expose Rust function with different C++ name
        #[rust_name = "internal_process"]
        fn ProcessData(data: &[u8]) -> Vec<u8>;

        // Rust type with C++-style name for C++ consumers
        #[rust_name = "rust_logger"]
        type Logger;
    }
}

// Rust implementation
fn internal_process(data: &[u8]) -> Vec<u8> {
    // ...
}

struct RustLogger {
    // ...
}
```

**C++ sees:**
```cpp
rust::Vec<uint8_t> ProcessData(rust::Slice<const uint8_t> data);

class Logger {
    // ...
};
```

---

## Enums

### Simple C-like Enums

```rust
#[cxx::bridge]
mod ffi {
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Status {
        Pending,
        Running,
        Completed,
        Failed,
    }

    unsafe extern "C++" {
        include!("mylib.h");
        fn process_task(status: Status);
    }
}
```

**Generated C++:**
```cpp
enum class Status {
    Pending,
    Running,
    Completed,
    Failed,
};

void process_task(Status status);
```

### Enums with Explicit Discriminants

```rust
#[cxx::bridge]
mod ffi {
    #[repr(i32)]
    enum ErrorCode {
        Success = 0,
        InvalidInput = 1,
        NetworkError = 100,
        DatabaseError = 200,
        UnknownError = 999,
    }
}
```

**C++ usage:**
```cpp
ErrorCode code = ErrorCode::NetworkError;
if (static_cast<int32_t>(code) >= 100) {
    // Handle serious errors
}
```

### Pattern Matching with Enums

```rust
fn handle_status(status: ffi::Status) {
    use ffi::Status;

    match status {
        Status::Pending => println!("Waiting..."),
        Status::Running => println!("In progress"),
        Status::Completed => println!("Done!"),
        Status::Failed => println!("Error occurred"),
        _ => println!("Unknown status"),  // Important: C++ can have invalid values
    }
}
```

### Extern Enums (Defined in C++)

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        // Enum defined in C++ header
        type NativeEnum;
    }
}
```

**C++ header:**
```cpp
enum class NativeEnum : int32_t {
    Value1,
    Value2,
    Value3,
};
```

---

## Shared Structs with Complex Fields

### Nested Structs

```rust
#[cxx::bridge]
mod ffi {
    struct Point {
        x: f64,
        y: f64,
    }

    struct Circle {
        center: Point,
        radius: f64,
    }

    struct Scene {
        name: String,
        circles: Vec<Circle>,
    }
}
```

**C++ usage:**
```cpp
Point create_point(double x, double y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

Scene create_scene() {
    Scene scene;
    scene.name = rust::String("My Scene");

    Circle circle1;
    circle1.center = create_point(0.0, 0.0);
    circle1.radius = 5.0;
    scene.circles.push_back(circle1);

    Circle circle2;
    circle2.center = create_point(10.0, 10.0);
    circle2.radius = 3.0;
    scene.circles.push_back(circle2);

    return scene;
}
```

### Derived Traits

```rust
#[cxx::bridge]
mod ffi {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct Color {
        r: u8,
        g: u8,
        b: u8,
    }
}
```

**Rust usage:**
```rust
let red = ffi::Color { r: 255, g: 0, b: 0 };
let also_red = red;  // Copy

assert_eq!(red, also_red);  // PartialEq

let mut colors = std::collections::HashSet::new();
colors.insert(red);  // Hash
```

---

## Opaque Type Patterns

### Using ExternType for Multi-Module Types

When you need the same C++ type in multiple bridge modules:

**common.rs:**
```rust
#[repr(C)]
pub struct Database {
    _private: [u8; 0],
}

unsafe impl cxx::ExternType for Database {
    type Id = cxx::type_id!("myapp::Database");
    type Kind = cxx::kind::Opaque;
}
```

**module_a.rs:**
```rust
#[cxx::bridge]
mod ffi_a {
    unsafe extern "C++" {
        include!("database.h");

        type Database = crate::common::Database;
        fn connect(url: &str) -> UniquePtr<Database>;
    }
}
```

**module_b.rs:**
```rust
#[cxx::bridge]
mod ffi_b {
    unsafe extern "C++" {
        include!("database.h");

        type Database = crate::common::Database;
        fn execute(db: Pin<&mut Database>, sql: &str) -> Result<()>;
    }
}
```

**Usage:**
```rust
// Types are compatible across modules!
let db = ffi_a::connect("postgresql://localhost");
ffi_b::execute(db.pin_mut(), "SELECT * FROM users")?;
```

### Template Instantiations

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("containers.h");

        // Explicit instantiations of C++ templates
        type IntVector = crate::bindings::IntVector;
        type StringVector = crate::bindings::StringVector;

        fn create_int_vector() -> UniquePtr<IntVector>;
        fn create_string_vector() -> UniquePtr<StringVector>;
    }

    // Request instantiation of UniquePtr for these types
    impl UniquePtr<IntVector> {}
    impl UniquePtr<StringVector> {}
}
```

---

## Function Pointers and Callbacks

### Simple Function Pointers

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        fn process_data(
            data: &[u8],
            callback: fn(i32),
        );
    }
}
```

**C++ usage:**
```cpp
#include "my-crate/src/main.rs.h"

void process_data(
    rust::Slice<const uint8_t> data,
    rust::Fn<void(int32_t)> callback
) {
    for (size_t i = 0; i < data.size(); i++) {
        callback(static_cast<int32_t>(data[i]));
    }
}
```

**Rust usage:**
```rust
fn my_callback(value: i32) {
    println!("Received: {}", value);
}

let data = vec![1, 2, 3, 4, 5];
ffi::process_data(&data, my_callback);
```

### Stateful Callbacks with Context

```rust
#[cxx::bridge]
mod ffi {
    extern "Rust" {
        type CallbackContext;
    }

    unsafe extern "C++" {
        include!("mylib.h");

        fn process_async(
            data: &[u8],
            callback: fn(&mut CallbackContext, i32),
            context: Box<CallbackContext>,
        );
    }
}

pub struct CallbackContext {
    sum: i32,
}

fn handle_value(context: &mut CallbackContext, value: i32) {
    context.sum += value;
}
```

---

## Error Handling Patterns

### Custom Error Types

**Bridge:**
```rust
#[cxx::bridge]
mod ffi {
    struct ErrorInfo {
        code: i32,
        message: String,
        details: Vec<String>,
    }

    unsafe extern "C++" {
        include!("mylib.h");

        fn risky_operation() -> Result<i32>;
        fn operation_with_details() -> Result<ErrorInfo>;
    }
}
```

**C++ implementation:**
```cpp
#include <stdexcept>

int32_t risky_operation() {
    if (some_condition) {
        throw std::runtime_error("Operation failed");
    }
    return 42;
}

ErrorInfo operation_with_details() {
    if (error_occurred) {
        ErrorInfo info;
        info.code = 100;
        info.message = rust::String("Detailed error");
        info.details.push_back(rust::String("Reason 1"));
        info.details.push_back(rust::String("Reason 2"));
        throw std::runtime_error("Error with details");
    }

    ErrorInfo success;
    success.code = 0;
    success.message = rust::String("Success");
    return success;
}
```

### Wrapping Exceptions

```rust
#[derive(Debug)]
pub enum MyError {
    CppException(cxx::Exception),
    IoError(std::io::Error),
    Custom(String),
}

impl From<cxx::Exception> for MyError {
    fn from(e: cxx::Exception) -> Self {
        MyError::CppException(e)
    }
}

pub fn safe_operation() -> Result<i32, MyError> {
    let result = ffi::risky_operation()
        .map_err(MyError::from)?;

    if result < 0 {
        return Err(MyError::Custom("Invalid result".to_string()));
    }

    Ok(result)
}
```

---

## Resource Management Patterns

### RAII in C++ with Rust Ownership

**C++ class:**
```cpp
class FileHandle {
private:
    int fd_;

public:
    FileHandle(const std::string& path) {
        fd_ = open(path.c_str(), O_RDONLY);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to open file");
        }
    }

    ~FileHandle() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    // Delete copy, allow move
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    rust::Vec<uint8_t> read(size_t bytes);
};
```

**Rust usage:**
```rust
fn process_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = ffi::open_file(path)?;
    // file is automatically closed when dropped
    let data = file.read(1024);
    process_data(&data);
    Ok(())
}  // FileHandle destructor called here
```

### Shared Resources

```cpp
class ResourcePool {
private:
    std::shared_ptr<impl> impl_;

public:
    ResourcePool();

    std::shared_ptr<Resource> acquire() {
        return impl_->get_resource();
    }
};
```

**Bridge:**
```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("pool.h");

        type ResourcePool;
        type Resource;

        fn create_pool() -> UniquePtr<ResourcePool>;
        fn acquire(self: &ResourcePool) -> SharedPtr<Resource>;
        fn use_resource(res: &Resource);
    }
}
```

**Usage:**
```rust
let pool = ffi::create_pool();

// Multiple owners of the same resource
let res1 = pool.acquire();
let res2 = res1.clone();  // SharedPtr is cloneable

ffi::use_resource(&res1);
ffi::use_resource(&res2);

// Resource is freed when last SharedPtr is dropped
```

---

## Performance Patterns

### Zero-Copy with Slices

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("processor.h");

        // Zero-copy: C++ operates directly on Rust's buffer
        fn process_inplace(buffer: &mut [u8]);

        // Read-only access to Rust data
        fn analyze(data: &[u8]) -> i32;
    }
}
```

**C++ implementation:**
```cpp
void process_inplace(rust::Slice<uint8_t> buffer) {
    // Modify buffer in-place
    for (size_t i = 0; i < buffer.size(); i++) {
        buffer[i] = buffer[i] ^ 0xFF;  // Invert bits
    }
}

int32_t analyze(rust::Slice<const uint8_t> data) {
    int32_t sum = 0;
    for (uint8_t byte : data) {
        sum += byte;
    }
    return sum;
}
```

### Avoiding Allocations

```rust
#[cxx::bridge]
mod ffi {
    struct Point {
        x: f64,
        y: f64,
    }

    unsafe extern "C++" {
        include!("geometry.h");

        // Returns by value - no allocation
        fn midpoint(p1: Point, p2: Point) -> Point;

        // Operates on borrowed data
        fn distance(p1: &Point, p2: &Point) -> f64;
    }
}
```

### Bulk Operations

```cpp
// ✓ Good: Process all at once
void process_batch(rust::Slice<const DataItem> items) {
    std::vector<Result> results;
    results.reserve(items.size());

    for (const auto& item : items) {
        results.push_back(process_one(item));
    }

    return results;
}

// ✗ Less efficient: Multiple FFI calls
Result process_single(const DataItem& item);
```

---

## Testing Patterns

### Unit Testing C++ Implementation

**tests/cpp_test.cc:**
```cpp
#include "my-crate/include/mylib.h"
#include <cassert>
#include <iostream>

void test_basic_functionality() {
    auto obj = create_object();
    assert(obj != nullptr);
    assert(obj->get_value() == 0);

    obj->set_value(42);
    assert(obj->get_value() == 42);

    std::cout << "C++ tests passed!" << std::endl;
}

int main() {
    test_basic_functionality();
    return 0;
}
```

### Integration Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpp_integration() {
        let obj = ffi::create_object();
        assert_eq!(obj.get_value(), 0);

        obj.pin_mut().set_value(42);
        assert_eq!(obj.get_value(), 42);
    }

    #[test]
    fn test_error_handling() {
        let result = ffi::risky_operation();
        match result {
            Ok(value) => assert!(value >= 0),
            Err(e) => println!("Expected error: {}", e.what()),
        }
    }

    #[test]
    fn test_shared_struct() {
        let point = ffi::Point { x: 1.0, y: 2.0 };
        let result = ffi::process_point(point);
        assert_eq!(result.x, 1.0);
        assert_eq!(result.y, 2.0);
    }
}
```

### Property-Based Testing

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_add_commutative(a: i32, b: i32) {
            let result1 = ffi::add(a, b);
            let result2 = ffi::add(b, a);
            prop_assert_eq!(result1, result2);
        }

        #[test]
        fn test_string_roundtrip(s in "\\PC*") {
            let result = ffi::echo_string(&s);
            prop_assert_eq!(result, s);
        }
    }
}
```

---

## Debugging and Profiling

### Enabling Debug Symbols

**build.rs:**
```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/mylib.cc")
        .flag_if_supported("-g")      // GCC/Clang
        .flag_if_supported("/Zi")     // MSVC
        .debug(true)
        .compile("my-crate");
}
```

### Logging from C++

```cpp
#include <iostream>

void debug_function(rust::Str input) {
    #ifdef DEBUG
    std::cerr << "[C++] debug_function called with: " << input << std::endl;
    #endif

    // Function implementation...
}
```

### Profiling Integration

```rust
#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn start_profiling();
        fn stop_profiling();
    }

    unsafe extern "C++" {
        include!("mylib.h");
        fn expensive_operation();
    }
}

fn start_profiling() {
    // Initialize profiler
}

fn stop_profiling() {
    // Stop and save profile
}
```

**C++ usage:**
```cpp
void expensive_operation() {
    start_profiling();

    // ... expensive work ...

    stop_profiling();
}
```

---

## Best Practices Summary

### 1. Prefer Shared Structs for Data Transfer

```rust
// ✓ Good: Single shared struct
struct Config {
    host: String,
    port: u16,
    timeout_ms: u32,
    enable_tls: bool,
}

fn connect(config: Config) -> Result<Connection>;

// ✗ Less ideal: Many parameters
fn connect(host: &str, port: u16, timeout_ms: u32, enable_tls: bool) -> Result<Connection>;
```

### 2. Use Slices for Zero-Copy

```rust
// ✓ Good: Zero-copy
fn process(data: &[u8]) -> i32;

// ✗ Bad: Unnecessary copy
fn process(data: Vec<u8>) -> i32;
```

### 3. Keep Bridge Interface Minimal

```rust
// ✓ Good: Minimal surface area
unsafe extern "C++" {
    type Database;
    fn connect(url: &str) -> UniquePtr<Database>;
    fn execute(db: Pin<&mut Database>, sql: &str) -> Result<Vec<String>>;
}

// Do complex work in Rust or C++, not at the boundary
```

### 4. Document the Bridge

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        /// Opens a database connection.
        ///
        /// # Errors
        /// Throws if URL is invalid or connection fails.
        fn connect(url: &str) -> Result<UniquePtr<Database>>;
    }
}
```

### 5. Handle Errors Appropriately

```cpp
// ✓ Good: Descriptive errors
if (!validate(input)) {
    throw std::invalid_argument(
        "Invalid input: expected positive number, got " +
        std::to_string(input)
    );
}

// ✗ Bad: Generic errors
if (!validate(input)) {
    throw std::runtime_error("Error");
}
```
