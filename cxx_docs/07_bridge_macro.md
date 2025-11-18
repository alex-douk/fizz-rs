# The `#[cxx::bridge]` Attribute Macro

## Overview
The `#[cxx::bridge]` macro is the core of CXX's safe Rust-C++ interoperability. It defines a module containing type and function declarations that bridge the two languages.

## Basic Syntax

```rust
#[cxx::bridge]
mod ffi {
    // Bridge declarations go here
}
```

## Core Functionality
The `#[bridge]` macro facilitates the declaration of:
- Types that exist on both the `extern "C++"` and `extern "Rust"` sides
- Functions that can be called across the language boundary
- Shared structs with identical memory layout in both languages

---

## Namespace Support

### Default Namespace
By default, Rust types and functions are placed in the global C++ namespace.

### Custom Namespace
Specify a C++ namespace for Rust items using the `namespace` parameter:

```rust
#[cxx::bridge(namespace = "mycompany::rust")]
mod ffi {
    extern "Rust" {
        // These will be in mycompany::rust namespace in C++
    }
}
```

**Effect**: Types and functions from the `extern "Rust"` side are placed into the specified namespace in the generated C++ code.

**Examples:**
```rust
// Single namespace
#[cxx::bridge(namespace = "myapp")]
mod ffi { /* ... */ }

// Nested namespaces
#[cxx::bridge(namespace = "org::mycompany::module")]
mod ffi { /* ... */ }

// No namespace (global)
#[cxx::bridge]
mod ffi { /* ... */ }
```

---

## Bridge Module Structure

A typical bridge module contains:

```rust
#[cxx::bridge]
mod ffi {
    // 1. Shared structs (visible to both languages)
    struct SharedData {
        field1: i32,
        field2: String,
    }

    // 2. C++ types and functions
    extern "C++" {
        include!("mylib.h");

        type CppType;

        fn cpp_function() -> i32;
    }

    // 3. Rust types and functions
    extern "Rust" {
        type RustType;

        fn rust_function() -> i32;
    }
}
```

---

## Shared Structs

Shared structs have identical memory layout in both Rust and C++.

### Defining Shared Structs

```rust
#[cxx::bridge]
mod ffi {
    struct Point {
        x: f64,
        y: f64,
    }

    struct Person {
        name: String,
        age: u32,
    }
}
```

### Generated C++ Code

```cpp
struct Point {
    double x;
    double y;
};

struct Person {
    rust::String name;
    uint32_t age;
};
```

### Supported Field Types
- Primitive types: `i32`, `u64`, `f64`, `bool`, etc.
- `String` (becomes `rust::String` in C++)
- `Vec<T>` (becomes `rust::Vec<T>` in C++)
- `Box<T>` (becomes `rust::Box<T>` in C++)
- Other shared structs
- UniquePtr, SharedPtr (in some contexts)

### Example Usage

```rust
#[cxx::bridge]
mod ffi {
    struct Config {
        host: String,
        port: u16,
        timeout: u32,
    }

    extern "C++" {
        include!("server.h");
        fn start_server(config: Config) -> bool;
    }
}

fn main() {
    let config = ffi::Config {
        host: "localhost".to_string(),
        port: 8080,
        timeout: 30,
    };

    if ffi::start_server(config) {
        println!("Server started successfully");
    }
}
```

---

## `extern "C++"` Block

Declares C++ types and functions that Rust can use.

### Type Declarations

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        // Opaque C++ type
        type CppClass;

        // With namespace
        type Database = crate::bindings::Database;
    }
}
```

### Function Declarations

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        // Free function
        fn create_widget() -> UniquePtr<Widget>;

        // Method on C++ type
        type Widget;
        fn get_name(self: &Widget) -> String;
        fn set_name(self: Pin<&mut Widget>, name: &str);

        // Static method
        fn Widget::default_name() -> String;
    }
}
```

### Include Directives

The `include!` macro specifies which C++ headers to include:

```rust
extern "C++" {
    include!("mylib.h");
    include!("other.h");
    include!(<vector>);  // Standard library headers
}
```

### Namespace Specification for C++ Types

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        // C++ type in myapp namespace
        #[namespace = "myapp"]
        type Database;

        #[namespace = "myapp"]
        fn connect(url: &str) -> UniquePtr<Database>;
    }
}
```

---

## `extern "Rust"` Block

Declares Rust types and functions that C++ can use.

### Type Declarations

```rust
#[cxx::bridge]
mod ffi {
    extern "Rust" {
        // Opaque Rust type (visible to C++)
        type RustLogger;
    }
}

// Implement in Rust
pub struct RustLogger {
    // Internal fields
}
```

### Function Declarations

```rust
#[cxx::bridge]
mod ffi {
    extern "Rust" {
        // Free function
        fn process_data(data: &[u8]) -> Vec<u8>;

        // Method on Rust type
        type RustLogger;
        fn log(self: &RustLogger, message: &str);
        fn log_mut(self: &mut RustLogger, level: i32, message: &str);
    }
}

// Implementation
fn process_data(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.wrapping_add(1)).collect()
}

impl RustLogger {
    fn log(&self, message: &str) {
        println!("{}", message);
    }

    fn log_mut(&mut self, level: i32, message: &str) {
        println!("[{}] {}", level, message);
    }
}
```

---

## Method Syntax

### Immutable Reference (`&self`)

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        type Widget;
        fn get_value(self: &Widget) -> i32;
    }
}
```

C++ signature: `int32_t Widget::get_value() const`

### Mutable Reference (`&mut self`)

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        type Widget;
        fn set_value(self: &mut Widget, value: i32);
    }
}
```

C++ signature: `void Widget::set_value(int32_t value)`

### Pinned Mutable Reference (`Pin<&mut self>`)

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        type Widget;
        fn modify(self: Pin<&mut Widget>);
    }
}
```

Required when C++ type is not moveable or has internal pointers.

### By-Value (`self`)

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        type Widget;
        fn consume(self: Widget);  // Takes ownership
    }
}
```

Only allowed for trivial types (types with `Kind = Trivial`).

---

## Complete Example

### Rust Code

```rust
#[cxx::bridge(namespace = "myapp::ffi")]
mod ffi {
    // Shared struct
    struct UserInfo {
        id: u64,
        name: String,
        email: String,
    }

    // C++ types and functions
    extern "C++" {
        include!("database.h");

        #[namespace = "myapp"]
        type Database;

        #[namespace = "myapp"]
        fn create_database(path: &str) -> Result<UniquePtr<Database>>;

        fn insert_user(self: Pin<&mut Database>, user: UserInfo) -> Result<u64>;
        fn find_user(self: &Database, id: u64) -> Result<UserInfo>;
        fn delete_user(self: Pin<&mut Database>, id: u64) -> Result<bool>;
    }

    // Rust types and functions
    extern "Rust" {
        type Logger;

        fn create_logger(name: &str) -> Box<Logger>;
        fn log_info(self: &Logger, message: &str);
        fn log_error(self: &Logger, message: &str);
    }
}

// Rust implementation
pub struct Logger {
    name: String,
}

fn create_logger(name: &str) -> Box<Logger> {
    Box::new(Logger {
        name: name.to_string(),
    })
}

impl Logger {
    fn log_info(&self, message: &str) {
        println!("[{}] INFO: {}", self.name, message);
    }

    fn log_error(&self, message: &str) {
        eprintln!("[{}] ERROR: {}", self.name, message);
    }
}

// Usage
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let logger = ffi::create_logger("app");

    let mut db = ffi::create_database("users.db")?;

    logger.log_info("Database opened");

    let user = ffi::UserInfo {
        id: 0,
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };

    let user_id = db.pin_mut().insert_user(user)?;
    logger.log_info(&format!("User created with ID: {}", user_id));

    let retrieved = db.find_user(user_id)?;
    logger.log_info(&format!("Retrieved user: {}", retrieved.name));

    Ok(())
}
```

### C++ Implementation

```cpp
// database.h
#pragma once
#include "rust/cxx.h"
#include "myapp/ffi.rs.h"  // Generated by CXX
#include <memory>
#include <map>

namespace myapp {

class Database {
private:
    std::string path_;
    std::map<uint64_t, myapp::ffi::UserInfo> users_;
    uint64_t next_id_ = 1;

public:
    Database(const std::string& path) : path_(path) {}

    uint64_t insert_user(myapp::ffi::UserInfo user);
    myapp::ffi::UserInfo find_user(uint64_t id) const;
    bool delete_user(uint64_t id);
};

std::unique_ptr<Database> create_database(rust::Str path);

}  // namespace myapp
```

```cpp
// database.cpp
#include "database.h"
#include <stdexcept>

namespace myapp {

std::unique_ptr<Database> create_database(rust::Str path) {
    return std::make_unique<Database>(std::string(path));
}

uint64_t Database::insert_user(myapp::ffi::UserInfo user) {
    uint64_t id = next_id_++;
    user.id = id;
    users_[id] = std::move(user);
    return id;
}

myapp::ffi::UserInfo Database::find_user(uint64_t id) const {
    auto it = users_.find(id);
    if (it == users_.end()) {
        throw std::runtime_error("User not found");
    }
    return it->second;
}

bool Database::delete_user(uint64_t id) {
    return users_.erase(id) > 0;
}

}  // namespace myapp
```

---

## Advanced Features

### Generic Functions (Limited Support)

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("templates.h");

        // Explicit instantiation
        fn process_i32(value: i32) -> i32;
        fn process_f64(value: f64) -> f64;
    }
}
```

CXX doesn't support C++ templates directly, but you can bridge specific instantiations.

### Enum Support

```rust
#[cxx::bridge]
mod ffi {
    enum Color {
        Red,
        Green,
        Blue,
    }

    extern "C++" {
        fn set_color(color: Color);
    }
}
```

### Result Types for Error Handling

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        fn risky_operation() -> Result<i32>;
        // Exceptions become Result<T, cxx::Exception>
    }
}
```

---

## Best Practices

### 1. Minimize Bridge Surface
Keep the bridge interface as small as possible. Do complex work on one side and expose simple functions.

### 2. Use Shared Structs for Data Transfer
Prefer shared structs over multiple parameters:

```rust
// Good
struct Options {
    timeout: u32,
    retries: u32,
    verbose: bool,
}
fn connect(opts: Options) -> Result<Connection>;

// Less ideal
fn connect(timeout: u32, retries: u32, verbose: bool) -> Result<Connection>;
```

### 3. Document the Bridge
```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        /// Opens a database connection.
        ///
        /// # Errors
        /// Throws exception if the path is invalid or database is corrupted.
        fn open_database(path: &str) -> Result<UniquePtr<Database>>;
    }
}
```

### 4. Use Appropriate Ownership
- `UniquePtr<T>` for exclusive ownership
- `SharedPtr<T>` for shared ownership
- `&T` for borrowing
- `Pin<&mut T>` for mutable non-moveable references

### 5. Separate Bridge per Module
Create separate bridge modules for different subsystems:

```rust
// database.rs
#[cxx::bridge(namespace = "myapp::db")]
mod db_ffi { /* ... */ }

// networking.rs
#[cxx::bridge(namespace = "myapp::net")]
mod net_ffi { /* ... */ }
```
