# Writing C++ Code for Rust with CXX

This guide focuses on implementing C++ code that will be called from Rust using CXX.

## Core Principles

1. **Write idiomatic C++** - Don't dumb down your C++ to C-style code
2. **Let CXX handle the FFI** - Trust the generated bindings
3. **Use modern C++** features (C++11 or later)
4. **Leverage the type system** - Both C++ and Rust compilers will help you

---

## Setting Up Your C++ Files

### Directory Structure

```
my-crate/
├── Cargo.toml
├── build.rs
├── include/
│   └── mylib/
│       └── myclass.h      # C++ headers
├── src/
│   ├── main.rs            # Rust code with bridge
│   └── myclass.cc         # C++ implementation
```

### Header File Best Practices

**include/mylib/myclass.h:**
```cpp
#pragma once

#include "rust/cxx.h"  // Always include CXX runtime
#include <memory>
#include <string>
#include <vector>

// Forward declare generated types if needed
struct MySharedStruct;

class MyClass {
public:
    MyClass(const std::string& name);
    ~MyClass();

    // Methods matching bridge declarations
    int32_t get_value() const;
    void set_value(int32_t value);
    rust::String get_name() const;

private:
    class Impl;  // PIMPL pattern works great with CXX
    std::unique_ptr<Impl> impl_;
};

// Factory functions
std::unique_ptr<MyClass> create_myclass(rust::Str name);
```

### Implementation File

**src/myclass.cc:**
```cpp
#include "mylib/myclass.h"
#include "my-crate/src/main.rs.h"  // Generated bridge header

#include <iostream>

// PIMPL implementation
class MyClass::Impl {
public:
    std::string name;
    int32_t value = 0;
};

MyClass::MyClass(const std::string& name)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = name;
}

MyClass::~MyClass() = default;

int32_t MyClass::get_value() const {
    return impl_->value;
}

void MyClass::set_value(int32_t value) {
    impl_->value = value;
}

rust::String MyClass::get_name() const {
    return rust::String(impl_->name);
}

std::unique_ptr<MyClass> create_myclass(rust::Str name) {
    return std::make_unique<MyClass>(std::string(name));
}
```

---

## Working with CXX Types in C++

### String Types

#### rust::Str (equivalent to Rust `&str`)

**Properties:**
- Read-only string view
- No ownership
- UTF-8 encoded
- Similar to `std::string_view`

**Usage:**
```cpp
void process_string(rust::Str input) {
    // Access as pointer and length
    const char* data = input.data();
    size_t len = input.length();

    // Convert to std::string if needed
    std::string cpp_string(input);

    // Iterate
    for (char c : input) {
        std::cout << c;
    }

    // Compare
    if (input == "hello") {
        // ...
    }
}
```

#### rust::String (equivalent to Rust `String`)

**Properties:**
- Owned string
- UTF-8 encoded
- Movable but not copyable
- Heap-allocated

**Usage:**
```cpp
rust::String create_greeting(rust::Str name) {
    // Create from std::string
    std::string msg = "Hello, " + std::string(name);
    return rust::String(msg);
}

void modify_string(rust::String& str) {
    // Append
    str += " world";

    // Access
    std::cout << str << std::endl;

    // Convert to std::string
    std::string cpp = std::string(str);
}
```

### Vector Types

#### rust::Vec<T> (equivalent to Rust `Vec<T>`)

**Supported element types:**
- Primitives: `uint8_t`, `int32_t`, `float`, etc.
- `rust::String`
- Shared structs
- **Not supported:** Opaque types, pointers

**Usage:**
```cpp
#include "rust/cxx.h"

void process_numbers(const rust::Vec<int32_t>& numbers) {
    // Size
    size_t len = numbers.size();

    // Access elements
    for (size_t i = 0; i < numbers.size(); i++) {
        int32_t value = numbers[i];
        std::cout << value << " ";
    }

    // Range-based for loop
    for (int32_t num : numbers) {
        std::cout << num << " ";
    }
}

rust::Vec<rust::String> create_tags() {
    rust::Vec<rust::String> tags;
    tags.reserve(3);
    tags.push_back(rust::String("rust"));
    tags.push_back(rust::String("cpp"));
    tags.push_back(rust::String("ffi"));
    return tags;
}

void modify_vector(rust::Vec<uint8_t>& data) {
    data.push_back(42);
    data.clear();
    data.reserve(100);
}
```

#### rust::Slice<T> (equivalent to Rust `&[T]`)

**Properties:**
- Read-only view into contiguous memory
- No ownership
- Similar to `std::span` (C++20)

**Usage:**
```cpp
size_t sum_numbers(rust::Slice<const int32_t> numbers) {
    size_t sum = 0;
    for (int32_t num : numbers) {
        sum += num;
    }
    return sum;
}

void print_bytes(rust::Slice<const uint8_t> bytes) {
    const uint8_t* ptr = bytes.data();
    size_t len = bytes.length();

    for (size_t i = 0; i < len; i++) {
        printf("%02x ", ptr[i]);
    }
}
```

#### rust::Slice<T> (mutable, equivalent to Rust `&mut [T]`)

```cpp
void zero_fill(rust::Slice<uint8_t> buffer) {
    for (size_t i = 0; i < buffer.size(); i++) {
        buffer[i] = 0;
    }
}
```

### Box and Smart Pointers

#### rust::Box<T>

**Usage:**
```cpp
// Receive owned Rust type
void consume_rust_object(rust::Box<RustType> obj) {
    // obj is automatically destroyed when function returns
}

// Return owned Rust type (rare - usually created on Rust side)
// Not commonly used from C++
```

#### std::unique_ptr<T> (for C++ types)

**Most common pattern for returning C++ objects to Rust:**

```cpp
class Database {
public:
    Database(const std::string& url);
    void execute(rust::Str sql);
};

// Factory function
std::unique_ptr<Database> connect_database(rust::Str url) {
    return std::make_unique<Database>(std::string(url));
}

// Methods take self by reference
void Database::execute(rust::Str sql) {
    std::string query(sql);
    // Execute query...
}
```

**Bridge declaration:**
```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        type Database;
        fn connect_database(url: &str) -> UniquePtr<Database>;
        fn execute(self: Pin<&mut Database>, sql: &str);
    }
}
```

#### std::shared_ptr<T>

**For shared ownership across boundary:**

```cpp
class Cache {
    // ...
};

std::shared_ptr<Cache> get_global_cache() {
    static auto cache = std::make_shared<Cache>();
    return cache;
}
```

---

## Implementing Methods

### Non-static Member Functions

#### Const Methods (immutable reference)

**C++ signature:**
```cpp
class Widget {
public:
    int32_t get_value() const;
    rust::String get_name() const;
};
```

**Bridge:**
```rust
extern "C++" {
    type Widget;
    fn get_value(self: &Widget) -> i32;
    fn get_name(self: &Widget) -> String;
}
```

#### Non-const Methods (mutable reference)

**C++ signature:**
```cpp
class Widget {
public:
    void set_value(int32_t value);
    void clear();
};
```

**Bridge:**
```rust
extern "C++" {
    type Widget;
    fn set_value(self: Pin<&mut Widget>, value: i32);
    fn clear(self: Pin<&mut Widget>);
}
```

**Why Pin?** C++ objects may have internal pointers (self-referential). `Pin` prevents Rust from moving the object.

### Static Member Functions

**C++ signature:**
```cpp
class Config {
public:
    static Config default_config();
    static bool validate(rust::Str config_str);
};
```

**Bridge:**
```rust
extern "C++" {
    type Config;

    #[cxx_name = "default_config"]
    fn Config_default() -> UniquePtr<Config>;

    #[cxx_name = "validate"]
    fn Config_validate(config_str: &str) -> bool;
}
```

Or with Rust-side wrapper:
```rust
impl Config {
    fn default() -> UniquePtr<Config> {
        ffi::Config_default()
    }
}
```

---

## Exception Handling

### Throwing Exceptions from C++

When a C++ function throws, it becomes `Result<T>` in Rust.

**C++ implementation:**
```cpp
#include <stdexcept>

int32_t divide(int32_t a, int32_t b) {
    if (b == 0) {
        throw std::runtime_error("Division by zero");
    }
    return a / b;
}

void validate_config(rust::Str json) {
    if (json.empty()) {
        throw std::invalid_argument("Config cannot be empty");
    }
    // Parse and validate...
}
```

**Bridge:**
```rust
unsafe extern "C++" {
    fn divide(a: i32, b: i32) -> Result<i32>;
    fn validate_config(json: &str) -> Result<()>;
}
```

**Rust usage:**
```rust
match ffi::divide(10, 2) {
    Ok(result) => println!("Result: {}", result),
    Err(e) => eprintln!("Error: {}", e.what()),
}
```

### Exception Requirements

**Important:** Only exceptions derived from `std::exception` are caught and converted to `Result`.

```cpp
// ✓ Will be caught
throw std::runtime_error("error");
throw std::logic_error("error");
throw std::invalid_argument("error");

// ✗ Will cause undefined behavior
throw 42;
throw "error string";
```

### Custom Exception Types

```cpp
class DatabaseException : public std::exception {
private:
    std::string message_;

public:
    DatabaseException(const std::string& msg) : message_(msg) {}

    const char* what() const noexcept override {
        return message_.c_str();
    }
};

void query_database(rust::Str sql) {
    if (!is_connected()) {
        throw DatabaseException("Not connected to database");
    }
    // Execute query...
}
```

---

## Calling Rust from C++

### Calling Rust Functions

**Bridge:**
```rust
extern "Rust" {
    fn process_data(input: &[u8]) -> Vec<u8>;
    fn log_message(level: i32, msg: &str);
}

fn process_data(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.wrapping_add(1)).collect()
}

fn log_message(level: i32, msg: &str) {
    println!("[{}] {}", level, msg);
}
```

**C++ usage:**
```cpp
#include "my-crate/src/main.rs.h"

void do_work() {
    // Call Rust function
    log_message(1, "Starting work");

    // Pass data to Rust
    std::vector<uint8_t> input = {1, 2, 3, 4, 5};
    rust::Slice<const uint8_t> input_slice(input.data(), input.size());

    rust::Vec<uint8_t> result = process_data(input_slice);

    log_message(2, "Work complete");
}
```

### Calling Rust Methods

**Bridge:**
```rust
extern "Rust" {
    type Logger;

    fn create_logger(name: &str) -> Box<Logger>;
    fn log(self: &Logger, message: &str);
    fn set_level(self: &mut Logger, level: i32);
}

pub struct Logger {
    name: String,
    level: i32,
}

fn create_logger(name: &str) -> Box<Logger> {
    Box::new(Logger {
        name: name.to_string(),
        level: 0,
    })
}

impl Logger {
    fn log(&self, message: &str) {
        println!("[{}] {}", self.name, message);
    }

    fn set_level(&mut self, level: i32) {
        self.level = level;
    }
}
```

**C++ usage:**
```cpp
#include "my-crate/src/main.rs.h"

void example() {
    // Create Rust object
    rust::Box<Logger> logger = create_logger("app");

    // Call methods
    logger->log("Hello from C++");
    logger->set_level(2);
    logger->log("Debug message");
}
```

---

## Working with Shared Structs

### Defining Shared Structs

**Bridge:**
```rust
#[cxx::bridge]
mod ffi {
    struct Point {
        x: f64,
        y: f64,
    }

    struct Rectangle {
        top_left: Point,
        bottom_right: Point,
    }
}
```

**Generated C++:**
```cpp
struct Point {
    double x;
    double y;
};

struct Rectangle {
    Point top_left;
    Point bottom_right;
};
```

### Using Shared Structs in C++

```cpp
Point create_point(double x, double y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

double calculate_area(const Rectangle& rect) {
    double width = rect.bottom_right.x - rect.top_left.x;
    double height = rect.top_left.y - rect.bottom_right.y;
    return width * height;
}

Rectangle scale_rectangle(Rectangle rect, double factor) {
    rect.top_left.x *= factor;
    rect.top_left.y *= factor;
    rect.bottom_right.x *= factor;
    rect.bottom_right.y *= factor;
    return rect;
}
```

### Complex Shared Structs

```rust
struct UserInfo {
    id: u64,
    name: String,
    email: String,
    tags: Vec<String>,
    active: bool,
}
```

**C++ usage:**
```cpp
UserInfo create_user(uint64_t id, rust::Str name, rust::Str email) {
    UserInfo user;
    user.id = id;
    user.name = rust::String(name);
    user.email = rust::String(email);
    user.active = true;

    user.tags.push_back(rust::String("new"));
    user.tags.push_back(rust::String("pending"));

    return user;
}

void print_user(const UserInfo& user) {
    std::cout << "ID: " << user.id << std::endl;
    std::cout << "Name: " << user.name << std::endl;
    std::cout << "Email: " << user.email << std::endl;
    std::cout << "Active: " << (user.active ? "yes" : "no") << std::endl;

    std::cout << "Tags: ";
    for (const auto& tag : user.tags) {
        std::cout << tag << " ";
    }
    std::cout << std::endl;
}
```

---

## Advanced C++ Patterns

### PIMPL (Pointer to Implementation)

**Excellent pattern for CXX - keeps implementation details private:**

**Header:**
```cpp
class Database {
public:
    Database(rust::Str url);
    ~Database();

    void execute(rust::Str sql);
    rust::Vec<rust::String> query(rust::Str sql);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
```

**Implementation:**
```cpp
class Database::Impl {
public:
    std::string connection_url;
    void* native_handle;

    // Complex implementation details hidden
};

Database::Database(rust::Str url)
    : impl_(std::make_unique<Impl>()) {
    impl_->connection_url = std::string(url);
    // Connect...
}

Database::~Database() = default;  // Unique_ptr handles cleanup
```

### Resource Management (RAII)

```cpp
class FileHandle {
public:
    FileHandle(rust::Str path) {
        file_ = fopen(std::string(path).c_str(), "r");
        if (!file_) {
            throw std::runtime_error("Failed to open file");
        }
    }

    ~FileHandle() {
        if (file_) {
            fclose(file_);
        }
    }

    // Delete copy constructor/assignment
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    rust::Vec<uint8_t> read_all() {
        rust::Vec<uint8_t> data;
        // Read file into data...
        return data;
    }

private:
    FILE* file_;
};
```

### Template Instantiation

**CXX doesn't support templates directly, but you can expose specific instantiations:**

**C++ header:**
```cpp
template<typename T>
class Container {
public:
    void add(const T& item);
    size_t size() const;
};

// Explicit instantiations
using IntContainer = Container<int32_t>;
using StringContainer = Container<std::string>;
```

**Bridge:**
```rust
unsafe extern "C++" {
    type IntContainer;
    fn add(self: Pin<&mut IntContainer>, item: i32);
    fn size(self: &IntContainer) -> usize;
}
```

---

## Best Practices

### 1. Use Modern C++ Features

```cpp
// ✓ Good: Use auto, range-based for, smart pointers
auto process_items(const rust::Vec<Item>& items) {
    std::vector<Result> results;
    for (const auto& item : items) {
        results.push_back(transform(item));
    }
    return results;
}

// ✗ Avoid: C-style code
Result* process_items_old(const Item* items, size_t count) {
    Result* results = (Result*)malloc(count * sizeof(Result));
    for (size_t i = 0; i < count; i++) {
        results[i] = transform(items[i]);
    }
    return results;
}
```

### 2. Return by Value for Small Types

```cpp
// ✓ Good: Shared structs can be returned by value
Point calculate_center(const Rectangle& rect) {
    return Point{
        (rect.top_left.x + rect.bottom_right.x) / 2.0,
        (rect.top_left.y + rect.bottom_right.y) / 2.0
    };
}
```

### 3. Use UniquePtr for Factory Functions

```cpp
// ✓ Good: Clear ownership transfer
std::unique_ptr<Database> create_database(rust::Str url) {
    return std::make_unique<Database>(url);
}

// ✗ Avoid: Raw pointers
Database* create_database_bad(rust::Str url) {
    return new Database(url);  // Who owns this?
}
```

### 4. Descriptive Exception Messages

```cpp
// ✓ Good
if (!is_valid_url(url)) {
    throw std::invalid_argument(
        "Invalid URL format: " + std::string(url)
    );
}

// ✗ Bad
if (!is_valid_url(url)) {
    throw std::runtime_error("Error");
}
```

### 5. Const Correctness

```cpp
// ✓ Good: Proper const usage
class Widget {
public:
    int32_t get_value() const;  // Doesn't modify
    void set_value(int32_t value);  // Modifies
};

int32_t Widget::get_value() const {
    return value_;
}
```
