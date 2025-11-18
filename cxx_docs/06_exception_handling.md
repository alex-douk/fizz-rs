# CXX Exception Handling

## `Exception` Struct

### Overview
The `Exception` struct represents exceptions thrown from `extern "C++"` functions in the CXX library. It enables safe interoperability between C++ exception handling and Rust's error handling model.

**Availability**: Only available when the `alloc` feature is enabled (enabled by default).

### Definition

```rust
pub struct Exception {
    // Private fields
}
```

### Primary Use Case
This type enables safe interoperability between Rust and C++ by allowing Rust code to catch and handle C++ exceptions in a type-safe manner, converting them into Rust's `Result`-based error handling model.

---

## Methods

### `what(&self) -> &str`
Retrieves the exception message as a string slice.

**Signature:**
```rust
pub fn what(&self) -> &str
```

**Returns:** A string slice containing the exception message from C++'s `std::exception::what()`.

**Example:**
```rust
match call_cpp_function() {
    Ok(value) => println!("Success: {}", value),
    Err(e) => println!("C++ exception: {}", e.what()),
}
```

---

## Trait Implementations

### `Debug`
Enables formatted debug output.

```rust
eprintln!("Exception: {:?}", exception);
```

### `Display`
Enables user-friendly display output.

```rust
println!("Error: {}", exception);
```

### `Error` (std::error::Error)
Makes `Exception` compatible with Rust's error handling ecosystem.

**Capabilities:**
- Can be used with `?` operator
- Can be converted to `Box<dyn Error>`
- Can be chained with other errors
- Compatible with error handling libraries (anyhow, thiserror, etc.)

```rust
use std::error::Error;

fn process() -> Result<(), Box<dyn Error>> {
    let result = ffi::cpp_function()?;  // Exception converts to Error
    Ok(())
}
```

### Thread Safety Traits
- **`Send`** - Can be sent across thread boundaries
- **`Sync`** - Can be shared between threads
- **`Unpin`** - Can be safely moved
- **`UnwindSafe`** - Safe across panic boundaries

---

## Exception Handling Patterns

### Basic Try-Catch Pattern

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        fn risky_operation(value: i32) -> Result<i32>;
    }
}

fn example() {
    match ffi::risky_operation(42) {
        Ok(result) => println!("Success: {}", result),
        Err(exception) => {
            eprintln!("C++ threw exception: {}", exception.what());
        }
    }
}
```

### Using `?` Operator

```rust
fn process_data(input: i32) -> Result<i32, cxx::Exception> {
    let step1 = ffi::step_one(input)?;
    let step2 = ffi::step_two(step1)?;
    let result = ffi::step_three(step2)?;
    Ok(result)
}
```

### Converting to Custom Error Types

```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum AppError {
    #[error("C++ error: {0}")]
    CppError(String),
    #[error("Rust error: {0}")]
    RustError(String),
}

impl From<cxx::Exception> for AppError {
    fn from(e: cxx::Exception) -> Self {
        AppError::CppError(e.what().to_string())
    }
}

fn process() -> Result<(), AppError> {
    ffi::cpp_function()?;  // Automatically converts Exception to AppError
    Ok(())
}
```

### With `anyhow`

```rust
use anyhow::{Context, Result};

fn process() -> Result<()> {
    let result = ffi::cpp_function()
        .context("Failed to execute C++ function")?;
    Ok(())
}
```

---

## C++ Side Exception Handling

### Basic Exception Throwing

```cpp
// C++ implementation
#include "mylib.h"
#include <stdexcept>

int risky_operation(int value) {
    if (value < 0) {
        throw std::runtime_error("Value must be non-negative");
    }
    return value * 2;
}
```

### Custom Exception Types

```cpp
class DatabaseException : public std::exception {
private:
    std::string message;
public:
    DatabaseException(const std::string& msg) : message(msg) {}

    const char* what() const noexcept override {
        return message.c_str();
    }
};

void connect_database(const std::string& url) {
    if (url.empty()) {
        throw DatabaseException("Database URL cannot be empty");
    }
    // ... connection logic
}
```

All C++ exceptions derived from `std::exception` are caught and converted to `cxx::Exception` on the Rust side.

---

## Complete Example

### Rust Bridge Definition

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("calculator.h");

        fn divide(a: i32, b: i32) -> Result<i32>;
        fn parse_number(s: &str) -> Result<i32>;
    }
}

fn safe_calculation(a: i32, b: i32) -> Result<i32, Box<dyn std::error::Error>> {
    match ffi::divide(a, b) {
        Ok(result) => {
            println!("{} / {} = {}", a, b, result);
            Ok(result)
        }
        Err(e) => {
            eprintln!("Division failed: {}", e.what());
            Err(Box::new(e))
        }
    }
}

fn parse_and_divide(s1: &str, s2: &str) -> Result<i32, cxx::Exception> {
    let a = ffi::parse_number(s1)?;
    let b = ffi::parse_number(s2)?;
    ffi::divide(a, b)
}

fn main() {
    // Example 1: Basic error handling
    if let Err(e) = safe_calculation(10, 0) {
        println!("Error occurred: {}", e);
    }

    // Example 2: Using ? operator
    match parse_and_divide("10", "2") {
        Ok(result) => println!("Result: {}", result),
        Err(e) => println!("Parsing or division failed: {}", e.what()),
    }
}
```

### C++ Implementation

```cpp
// calculator.h
#pragma once
#include <string>

int divide(int a, int b);
int parse_number(const std::string& s);
```

```cpp
// calculator.cpp
#include "calculator.h"
#include <stdexcept>

int divide(int a, int b) {
    if (b == 0) {
        throw std::runtime_error("Division by zero");
    }
    return a / b;
}

int parse_number(const std::string& s) {
    try {
        return std::stoi(s);
    } catch (const std::invalid_argument& e) {
        throw std::runtime_error("Invalid number format: " + s);
    } catch (const std::out_of_range& e) {
        throw std::runtime_error("Number out of range: " + s);
    }
}
```

---

## Important Considerations

### 1. Only `std::exception` Derived Exceptions
CXX can only catch C++ exceptions that derive from `std::exception`. Other exception types will cause undefined behavior.

**Safe:**
```cpp
throw std::runtime_error("Error message");  // ✓
throw std::logic_error("Logic error");      // ✓
throw CustomException("...");               // ✓ if derives from std::exception
```

**Unsafe:**
```cpp
throw 42;                    // ✗ Not derived from std::exception
throw "error";               // ✗ Not derived from std::exception
throw SomeOtherClass();      // ✗ Not derived from std::exception
```

### 2. Performance Impact
Exception handling has a performance cost:
- Zero overhead when no exception is thrown (C++ guarantee)
- Significant overhead when exception is thrown and caught
- Consider using `Result` types for expected errors instead

### 3. Exception Safety Guarantees
When C++ throws an exception across the FFI boundary:
- All C++ objects are properly destroyed (RAII works correctly)
- Rust side receives the exception as `Err(cxx::Exception)`
- Stack unwinding happens safely

### 4. No Panic Catching
CXX does **not** catch Rust panics and convert them to C++ exceptions. If Rust code panics:
- The panic will propagate through the Rust stack
- It will **not** cross into C++ as an exception
- Use `std::panic::catch_unwind` if you need to prevent panics from crossing FFI

```rust
use std::panic;

fn safe_rust_function() -> Result<i32, cxx::Exception> {
    // This will NOT be caught by C++ exception handlers
    panic!("Rust panic");  // Propagates as Rust panic, not C++ exception
}
```

### 5. Error Message Encoding
The `what()` message must be valid UTF-8. If the C++ exception message contains invalid UTF-8, it will be converted using lossy UTF-8 conversion.

---

## Best Practices

### 1. Use Descriptive Error Messages

```cpp
// Good: Descriptive message
throw std::runtime_error("Failed to open file: " + filename + " - " + strerror(errno));

// Bad: Vague message
throw std::runtime_error("Error");
```

### 2. Document Exception Conditions

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        /// Opens a database connection.
        ///
        /// # Errors
        /// Returns `Err` if:
        /// - The URL is invalid
        /// - The database server is unreachable
        /// - Authentication fails
        fn connect(url: &str) -> Result<UniquePtr<Database>>;
    }
}
```

### 3. Handle Errors Appropriately

```rust
fn process() -> Result<(), Box<dyn std::error::Error>> {
    let db = ffi::connect("localhost:5432")
        .map_err(|e| format!("Database connection failed: {}", e.what()))?;

    // Continue processing...
    Ok(())
}
```

### 4. Consider Error Type Conversions

```rust
// Convert to your application's error type
match ffi::cpp_operation() {
    Ok(value) => Ok(value),
    Err(e) => Err(AppError::ExternalError {
        source: "C++ library",
        message: e.what().to_string(),
    }),
}
```

### 5. Test Exception Paths

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_division_by_zero() {
        let result = ffi::divide(10, 0);
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.what().contains("zero"));
        }
    }

    #[test]
    fn test_invalid_input() {
        let result = ffi::parse_number("not a number");
        assert!(result.is_err());
    }
}
```
