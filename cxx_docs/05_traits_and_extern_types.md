# CXX Traits and Extern Types

## `ExternType` Trait

### Overview
`ExternType` is an **unsafe trait** in the CXX crate that defines types whose layout is determined by C++ definitions. It enables safe Rust-C++ interoperability by unifying type representations across multiple bridge invocations.

### Trait Definition

```rust
pub unsafe trait ExternType {
    type Id;
    type Kind;
}
```

### Required Associated Types

#### `Id: TypeId`
A type-level representation of the C++ namespace and type name.

**Defined using the `type_id!` macro:**
```rust
type Id = cxx::type_id!("name::space::TypeName");
```

**Format:**
- Full C++ namespace path
- Double colons for namespace separation
- Exact C++ type name

**Examples:**
```rust
type Id = cxx::type_id!("MyType");                    // Global namespace
type Id = cxx::type_id!("mycompany::MyType");         // Single namespace
type Id = cxx::type_id!("org::project::module::Type"); // Nested namespaces
```

#### `Kind: Kind`
Specifies either `cxx::kind::Opaque` or `cxx::kind::Trivial`.

**`Trivial`:**
- Type has a trivial move constructor and no destructor
- Can be passed by value across FFI boundary
- Can be held in Rust structs directly
- Safe to move in Rust without calling C++ move constructor
- Examples: POD types, primitive types

**`Opaque`:**
- Type has non-trivial move constructor or destructor
- Cannot be passed by value in Rust
- Requires indirection: `&T`, `&mut T`, `Pin<&mut T>`, or `UniquePtr<T>`
- Examples: Most C++ classes with constructors/destructors

### Core Purposes

#### 1. Unifying Type Occurrences
Enables the same extern C++ type to be safely referenced across different `#[cxx::bridge]` invocations, preventing compiler errors from duplicate type definitions.

**Without ExternType (Error):**
```rust
// file1.rs
#[cxx::bridge]
mod ffi1 {
    extern "C++" {
        type MyType;  // First definition
    }
}

// file2.rs
#[cxx::bridge]
mod ffi2 {
    extern "C++" {
        type MyType;  // Error: duplicate definition!
    }
}
```

**With ExternType (Correct):**
```rust
// mytype.rs
#[repr(C)]
pub struct MyType {
    _private: [u8; 0],
}

unsafe impl cxx::ExternType for MyType {
    type Id = cxx::type_id!("MyType");
    type Kind = cxx::kind::Opaque;
}

// file1.rs
#[cxx::bridge]
mod ffi1 {
    extern "C++" {
        type MyType = crate::mytype::MyType;
    }
}

// file2.rs
#[cxx::bridge]
mod ffi2 {
    extern "C++" {
        type MyType = crate::mytype::MyType;  // OK: same Rust type
    }
}
```

#### 2. Bindgen Integration
Allows handwritten `ExternType` implementations to integrate bindgen-generated data structures with CXX-defined C++ types.

### Foreign Type Implementations

CXX provides built-in `ExternType` implementations for:

**Primitive Types (Trivial):**
- `bool`
- `f32`, `f64`
- `i8`, `i16`, `i32`, `i64`, `i128`
- `u8`, `u16`, `u32`, `u64`, `u128`
- `isize`, `usize`

**String Types:**
- `String` - Implemented as `Trivial` (Rust's owned string)
- `CxxString` - Implemented as `Opaque` (C++ `std::string`)

### Implementation Examples

#### Opaque Type (C++ Class)

```rust
// Rust side
#[repr(C)]
pub struct DatabaseConnection {
    _private: [u8; 0],
}

unsafe impl cxx::ExternType for DatabaseConnection {
    type Id = cxx::type_id!("myapp::DatabaseConnection");
    type Kind = cxx::kind::Opaque;
}

#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("database.h");

        type DatabaseConnection = crate::DatabaseConnection;

        fn connect(url: &str) -> UniquePtr<DatabaseConnection>;
        fn query(conn: &DatabaseConnection, sql: &str) -> String;
    }
}
```

```cpp
// C++ side (database.h)
namespace myapp {
    class DatabaseConnection {
    private:
        // Internal state
        std::string connection_string;
        void* handle;
    public:
        DatabaseConnection(const std::string& url);
        ~DatabaseConnection();
        std::string query(const std::string& sql);
    };
}
```

#### Trivial Type (POD Struct)

```rust
// Rust side
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

unsafe impl cxx::ExternType for Point {
    type Id = cxx::type_id!("geometry::Point");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("geometry.h");

        type Point = crate::Point;

        fn distance(p1: Point, p2: Point) -> f64;
    }
}

fn example() {
    let p1 = Point { x: 0.0, y: 0.0 };
    let p2 = Point { x: 3.0, y: 4.0 };

    // Can pass by value because it's Trivial
    let dist = ffi::distance(p1, p2);
    println!("Distance: {}", dist);
}
```

```cpp
// C++ side (geometry.h)
namespace geometry {
    struct Point {
        double x;
        double y;
    };

    double distance(Point p1, Point p2);
}
```

#### Multiple Bridge Modules

```rust
// common.rs
#[repr(C)]
pub struct Config {
    _private: [u8; 0],
}

unsafe impl cxx::ExternType for Config {
    type Id = cxx::type_id!("app::Config");
    type Kind = cxx::kind::Opaque;
}

// module_a.rs
#[cxx::bridge]
mod ffi_a {
    extern "C++" {
        include!("config.h");
        type Config = crate::common::Config;
        fn load_config(path: &str) -> UniquePtr<Config>;
    }
}

// module_b.rs
#[cxx::bridge]
mod ffi_b {
    extern "C++" {
        include!("config.h");
        type Config = crate::common::Config;  // Same type!
        fn save_config(config: &Config, path: &str);
    }
}

// Both modules can use the same Config type
fn example() {
    let config = ffi_a::load_config("config.json");
    ffi_b::save_config(&config, "backup.json");  // Works!
}
```

### Safety Considerations

#### Why `unsafe`?
Implementing `ExternType` is marked `unsafe` because programmers must correctly assert that:

1. **Layout Matches**: The Rust type's layout matches the C++ type's layout
2. **Alignment Matches**: The alignment requirements are compatible
3. **ABI Compatible**: The type can be safely passed across the FFI boundary
4. **Correct Kind**: The `Kind` (Trivial vs Opaque) accurately reflects the C++ type's properties

#### Common Mistakes

**Incorrect Layout:**
```rust
// WRONG: Rust and C++ layouts don't match
#[repr(C)]
pub struct Point {
    pub x: f32,  // C++ uses double (f64)!
    pub y: f32,
}

unsafe impl cxx::ExternType for Point {
    type Id = cxx::type_id!("Point");
    type Kind = cxx::kind::Trivial;  // UNSAFE!
}
```

**Wrong Kind:**
```rust
// WRONG: Type has non-trivial destructor
#[repr(C)]
pub struct Resource {
    _private: [u8; 0],
}

unsafe impl cxx::ExternType for Resource {
    type Id = cxx::type_id!("Resource");
    type Kind = cxx::kind::Trivial;  // WRONG! Should be Opaque
}
```

**Namespace Mismatch:**
```rust
// WRONG: Namespace doesn't match C++
unsafe impl cxx::ExternType for MyType {
    type Id = cxx::type_id!("MyType");  // C++ is actually myns::MyType
    type Kind = cxx::kind::Opaque;
}
```

### Best Practices

#### 1. Use `#[repr(C)]`
Always use `#[repr(C)]` for extern types to ensure compatible layout:

```rust
#[repr(C)]
pub struct MyType {
    _private: [u8; 0],
}
```

#### 2. Private Fields for Opaque Types
For opaque types, use zero-sized private fields to prevent construction in Rust:

```rust
#[repr(C)]
pub struct OpaqueType {
    _private: [u8; 0],
}
```

#### 3. Match C++ Exactly
Ensure field types, order, and padding match the C++ definition exactly for trivial types:

```rust
// C++: struct Data { int32_t x; int64_t y; };
#[repr(C)]
pub struct Data {
    pub x: i32,
    pub y: i64,  // Correct: matches C++ exactly
}
```

#### 4. Document Invariants
Document the C++ type being bridged and any invariants:

```rust
/// Rust binding to C++ `mycompany::Database`.
///
/// This type has a non-trivial destructor and must be used
/// through UniquePtr or references only.
#[repr(C)]
pub struct Database {
    _private: [u8; 0],
}

unsafe impl cxx::ExternType for Database {
    type Id = cxx::type_id!("mycompany::Database");
    type Kind = cxx::kind::Opaque;
}
```

#### 5. Verify with Tests
Create integration tests to verify the binding works correctly:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_use() {
        let obj = ffi::create_object();
        assert!(!obj.is_null());
        ffi::use_object(&obj);
    }
}
```

### Advanced: Bindgen Integration

CXX can work with bindgen-generated types:

```rust
// Build script generates bindings
// build.rs
fn main() {
    bindgen::Builder::default()
        .header("native.h")
        .generate()
        .unwrap()
        .write_to_file("bindings.rs")
        .unwrap();
}

// Use bindgen type with CXX
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

unsafe impl cxx::ExternType for bindings::NativeStruct {
    type Id = cxx::type_id!("NativeStruct");
    type Kind = cxx::kind::Trivial;  // Or Opaque, depending on the type
}

#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("native.h");
        type NativeStruct = crate::bindings::NativeStruct;
        fn process(s: &NativeStruct);
    }
}
```

---

## `type_id!` Macro

### Overview
The `type_id!` macro is used exclusively in implementations of the `ExternType` trait to specify the C++ type's fully-qualified name.

### Syntax

```rust
type Id = cxx::type_id!("namespace::TypeName");
```

### Format Rules

1. **Namespace Separator**: Use `::` for C++ namespace separation
2. **Exact Name**: Must match the C++ type name exactly (case-sensitive)
3. **Full Path**: Include the complete namespace path
4. **No Template Arguments**: Template specialization not included in the identifier

### Examples

#### Global Namespace
```rust
type Id = cxx::type_id!("MyClass");
```

Corresponds to:
```cpp
class MyClass { /* ... */ };
```

#### Single Namespace
```rust
type Id = cxx::type_id!("myapp::Database");
```

Corresponds to:
```cpp
namespace myapp {
    class Database { /* ... */ };
}
```

#### Nested Namespaces
```rust
type Id = cxx::type_id!("org::mycompany::product::Component");
```

Corresponds to:
```cpp
namespace org {
namespace mycompany {
namespace product {
    class Component { /* ... */ };
}}}
```

#### C++ Standard Library Types
```rust
// For custom wrappers, not std::string (use CxxString instead)
type Id = cxx::type_id!("std::vector");  // Example only
```

### Common Mistakes

#### Incorrect Namespace
```rust
// WRONG: Missing namespace
type Id = cxx::type_id!("Config");

// Correct: Include namespace
type Id = cxx::type_id!("app::Config");
```

#### Wrong Separator
```rust
// WRONG: Using dot separator
type Id = cxx::type_id!("app.Config");

// Correct: Use double colon
type Id = cxx::type_id!("app::Config");
```

#### Template Arguments
```rust
// WRONG: Including template arguments
type Id = cxx::type_id!("Container<int>");

// Correct: Just the base name
type Id = cxx::type_id!("Container");
```

### Usage Pattern

Always use in conjunction with `ExternType`:

```rust
unsafe impl cxx::ExternType for MyType {
    type Id = cxx::type_id!("cpp::namespace::MyType");
    type Kind = cxx::kind::Opaque;
}
```
