# CXX String Types

## `CxxString`

### Overview
`CxxString` is a Rust binding to C++'s `std::string`, enabling safe interoperability between Rust and C++ code. The structure is defined with `#[repr(C)]` and uses opaque private fields.

### Key Invariant
**In Rust code we can never obtain a `CxxString` by value** due to C++'s move constructor requirements and potential internal pointers. Access only occurs through references (`&CxxString`) or smart pointers (`UniquePtr<CxxString>`).

### Primary Methods

#### Length and Capacity
- **`len(&self) -> usize`** - Returns byte length, matching C++ `std::string::size()`
- **`is_empty(&self) -> bool`** - Checks for zero-length strings
- **`clear(&mut self)`** - Removes all characters; note capacity behavior differs from Rust
- **`reserve(&mut self, additional: usize)`** - Allocates extra capacity (follows Rust semantics, not C++)

#### Access Methods
- **`as_bytes(&self) -> &[u8]`** - Provides byte slice access to the string contents
- **`as_ptr(&self) -> *const u8`** - Returns pointer to first character (read-only)
- **`as_c_str(&self) -> &CStr`** - Yields null-terminated C string view

#### Conversion Methods
- **`to_str(&self) -> Result<&str, Utf8Error>`** - Validates UTF-8 and returns `Result<&str>`
- **`to_string_lossy(&self) -> Cow<str>`** - Converts with replacement characters for invalid UTF-8

#### Modification Methods
- **`push_str(&mut self, s: &str)`** - Appends string slice
- **`push_bytes(&mut self, bytes: &[u8])`** - Appends arbitrary bytes

### Example Usage

```rust
use cxx::CxxString;
use cxx::UniquePtr;

fn process_cpp_string(s: &CxxString) {
    println!("Length: {}", s.len());
    println!("Is empty: {}", s.is_empty());

    // Convert to Rust str if valid UTF-8
    if let Ok(rust_str) = s.to_str() {
        println!("Content: {}", rust_str);
    }

    // Access as bytes
    let bytes = s.as_bytes();
    println!("First byte: {:?}", bytes.get(0));
}

fn create_cpp_string() -> UniquePtr<CxxString> {
    // CxxString must be created through UniquePtr
    // Typically created by C++ code or through bridge functions
    todo!("Created by C++ code")
}

fn modify_cpp_string(mut s: Pin<&mut CxxString>) {
    s.clear();
    s.push_str("Hello, ");
    s.push_str("World!");
    assert_eq!(s.len(), 13);
}
```

### Trait Implementations

#### Comparison Traits
- `Eq`, `PartialEq` - Equality comparison
- `Ord`, `PartialOrd` - Ordering comparison

#### Formatting Traits
- `Debug` - Debug formatting
- `Display` - Display formatting

#### Other Traits
- `Hash` - Hashing support
- `!Unpin` - Cannot be moved after pinning
- `Send` + `Sync` - Thread-safe when properly accessed

### Smart Pointer Compatibility
`CxxString` can be used with:
- `UniquePtr<CxxString>` - Exclusive ownership
- `SharedPtr<CxxString>` - Shared ownership
- `WeakPtr<CxxString>` - Non-owning reference
- `CxxVector<CxxString>` - Vector of strings

### Important Notes

1. **No By-Value Access**: You cannot create a `CxxString` by value in Rust. Always use references or smart pointers.

2. **UTF-8 Not Guaranteed**: Unlike Rust's `String`, `CxxString` may contain invalid UTF-8. Always use `to_str()` or `to_string_lossy()` for safe UTF-8 conversion.

3. **Capacity Behavior**: The `clear()` method behavior differs from Rust's `String::clear()` regarding capacity retention. The `reserve()` method follows Rust conventions, not C++ conventions.

4. **Null Termination**: When using `as_c_str()`, the string is guaranteed to be null-terminated, making it safe for C FFI.

5. **Thread Safety**: `CxxString` is `Send` and `Sync`, allowing it to be shared across threads when properly synchronized.

---

## `let_cxx_string!` Macro

### Overview
The `let_cxx_string!` macro provides a convenient way to construct C++ `std::string` objects on the Rust stack.

### Syntax
```rust
let_cxx_string!(var = expression);
```

The expression can be any type implementing `AsRef<[u8]>`, including:
- String literals (`"hello"`)
- `&[u8]` byte slices
- `String` (Rust string)
- `&str` string slices
- Any other type implementing `AsRef<[u8]>`

### Return Type
The macro expands to roughly:
```rust
let $var: Pin<&mut CxxString> = /* ... */;
```

The resulting `Pin` can be dereferenced to `&CxxString` as needed.

### Example Usage

```rust
use cxx::{let_cxx_string, CxxString};

fn f(s: &CxxString) {
    println!("String: {}", s.to_string_lossy());
}

fn main() {
    // Create from string literal
    let_cxx_string!(s1 = "example");
    f(&s1);

    // Create from Rust String
    let rust_string = String::from("hello");
    let_cxx_string!(s2 = rust_string);
    f(&s2);

    // Create from byte slice
    let bytes = b"world";
    let_cxx_string!(s3 = bytes);
    f(&s3);
}
```

### Use Cases

1. **Temporary String for C++ Functions**: When you need to pass a Rust string to a C++ function that expects `&CxxString`.

2. **Stack Allocation**: Creates the `CxxString` on the stack, avoiding heap allocation in simple cases.

3. **FFI Bridge**: Useful when bridging Rust data to C++ functions without creating long-lived `UniquePtr<CxxString>`.

### Important Considerations

- The `CxxString` created by this macro is stack-allocated and has a limited lifetime
- The resulting pinned reference cannot be moved
- For long-lived strings, consider using `UniquePtr<CxxString>` instead
- The macro is most useful for temporary conversions when calling C++ functions

### Complete Example with Bridge

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");
        fn process_string(s: &CxxString);
    }
}

fn example() {
    // Convert Rust string to CxxString for C++ function
    let name = "Alice";
    let_cxx_string!(cpp_name = name);
    ffi::process_string(&cpp_name);

    // Create from computed value
    let message = format!("Hello, {}!", name);
    let_cxx_string!(cpp_message = message);
    ffi::process_string(&cpp_message);
}
```

### Performance Note
The `let_cxx_string!` macro is optimized for temporary conversions. For strings that need to persist or be modified extensively, use `UniquePtr<CxxString>` instead, which allows full ownership and modification.
