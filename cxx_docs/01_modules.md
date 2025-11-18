# CXX Modules

## Module: `cxx::kind`

### Purpose
The `kind` module provides marker types that identify Rust's knowledge about extern C++ types. These markers are used in the `Kind` associated type of the `ExternType` trait implementation.

### Types Defined

#### Enum: `Opaque`
Represents an opaque type that cannot be passed or held by value within Rust code. Opaque types require indirection (references or smart pointers like `UniquePtr`) for use in Rust.

**Characteristics:**
- Cannot be stored by value in Rust structs
- Must be accessed through `&T`, `&mut T`, `Pin<&mut T>`, or `UniquePtr<T>`
- Typical for C++ types with non-trivial move constructors or destructors

**Example Usage:**
```rust
unsafe impl ExternType for MyCppType {
    type Id = type_id!("MyCppType");
    type Kind = cxx::kind::Opaque;
}
```

#### Enum: `Trivial`
Represents a type with a trivial move constructor and no destructor. Trivial types can be owned and moved within Rust without indirection.

**Characteristics:**
- Can be passed by value across the FFI boundary
- Can be stored directly in Rust structs
- Safe to move in Rust without calling C++ move constructors
- Typical for POD (Plain Old Data) types

**Example Usage:**
```rust
unsafe impl ExternType for MyPodType {
    type Id = type_id!("MyPodType");
    type Kind = cxx::kind::Trivial;
}
```

#### Trait: `Kind`
The foundational trait for marking extern type characteristics. Used to distinguish between different categories of C++ type interoperability.

### Context
This module is essential for the type safety guarantees provided by CXX. By explicitly marking whether a type is `Opaque` or `Trivial`, the framework can enforce correct usage patterns at compile time.

---

## Module: `cxx::memory`

### Purpose
This module provides less commonly used details related to smart pointer types in the CXX crate. The main pointer types (`UniquePtr` and `SharedPtr`) are exposed at the crate root level for convenience.

### Re-exports
- **`SharedPtr`**: Smart pointer for shared C++ object ownership
- **`UniquePtr`**: Smart pointer for exclusive C++ object ownership

### Traits Defined

#### Trait: `SharedPtrTarget`
**Description:** "Trait bound for types which may be used as the `T` inside of a `SharedPtr<T>`"

**Purpose:** Enables generic code using shared pointers. Types implementing this trait can be wrapped in `SharedPtr`.

**Example:**
```rust
fn process_shared<T: SharedPtrTarget>(ptr: SharedPtr<T>) {
    // Generic function working with any SharedPtr-compatible type
}
```

#### Trait: `UniquePtrTarget`
**Description:** "Trait bound for types which may be used as the `T` inside of a `UniquePtr<T>`"

**Purpose:** Enables generic code using unique pointers. Types implementing this trait can be wrapped in `UniquePtr`.

**Example:**
```rust
fn create_unique<T: UniquePtrTarget>(value: T) -> UniquePtr<T> {
    UniquePtr::new(value)
}
```

#### Trait: `WeakPtrTarget`
**Description:** "Trait bound for types which may be used as the `T` inside of a `WeakPtr<T>`"

**Purpose:** Supports weak reference semantics for shared pointers. Types implementing this trait can have weak references created from their shared pointers.

**Example:**
```rust
fn downgrade<T: WeakPtrTarget>(shared: &SharedPtr<T>) -> WeakPtr<T> {
    shared.downgrade()
}
```

### Summary
The `memory` module serves as a specialized namespace for trait bounds and implementation details supporting Rust-C++ interoperability through smart pointer abstractions. It allows developers to write generic functions and types that work with CXX's memory management types.

---

## Module: `cxx::vector`

### Purpose
This module contains less frequently used details and utilities related to `CxxVector`. The main `CxxVector` type itself is exposed at the crate root level for convenience.

### Defined Types

#### Struct: `Iter`
**Description:** "Iterator over elements of a `CxxVector` by shared reference."

**Characteristics:**
- Provides immutable iteration over `CxxVector<T>`
- Returns `&T` for each element
- Standard Rust iterator semantics

**Usage:**
```rust
let vec: UniquePtr<CxxVector<i32>> = CxxVector::new();
for item in vec.iter() {
    println!("{}", item);
}
```

#### Struct: `IterMut`
**Description:** "Iterator over elements of a `CxxVector` by pinned mutable reference."

**Characteristics:**
- Provides mutable iteration over `CxxVector<T>`
- Returns `Pin<&mut T>` for each element
- Respects Rust's pinning guarantees for safety

**Usage:**
```rust
let mut vec: UniquePtr<CxxVector<i32>> = CxxVector::new();
for item in vec.iter_mut() {
    *item += 1;
}
```

#### Trait: `VectorElement`
**Description:** "Trait bound for types which may be used as the `T` inside of a `CxxVector<T>` in generic code."

**Purpose:** Constrains which types can serve as vector elements in generic contexts. This ensures type safety when working with generic `CxxVector` operations.

**Example:**
```rust
fn sum_vector<T: VectorElement>(vec: &CxxVector<T>) -> T {
    // Generic function working with any VectorElement-compatible type
}
```

#### Type Alias: `Vector`
**Description:** A synonym for `CxxVector`, providing an alternative naming convention.

**Usage:**
```rust
use cxx::Vector;

fn process(vec: &Vector<i32>) {
    // Same as CxxVector<i32>
}
```

### Re-exports
The module re-exports `CxxVector` from the parent crate namespace, making it accessible through both the root level (`cxx::CxxVector`) and this submodule (`cxx::vector::CxxVector`).

### Summary
The `vector` module provides iterator types and trait bounds necessary for working with C++ vectors in generic Rust code. While most users will interact with `CxxVector` directly from the crate root, this module exposes the underlying machinery for advanced use cases.
