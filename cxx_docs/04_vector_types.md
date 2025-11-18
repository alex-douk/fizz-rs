# CXX Vector Types

## `CxxVector<T>`

### Overview
`CxxVector<T>` is a Rust binding to C++ `std::vector<T, std::allocator<T>>`, enabling safe interoperability between Rust and C++.

### Key Invariant
In Rust code, you cannot obtain a `CxxVector` by value. Instead, it's always accessed through references (`&CxxVector<T>`) or smart pointers like `UniquePtr<CxxVector<T>>`.

### Type Aliases
- **`cxx::Vector<T>`** - Synonym for `CxxVector<T>`
- **`cxx::vector::Vector<T>`** - Also available from the vector module

---

## Construction & Capacity

### `new() -> UniquePtr<CxxVector<T>>`
Creates a heap-allocated empty vector wrapped in `UniquePtr`.

```rust
use cxx::CxxVector;

let vec: UniquePtr<CxxVector<i32>> = CxxVector::new();
assert!(vec.is_empty());
```

### `len(&self) -> usize`
Returns the number of elements.

```rust
let vec = CxxVector::new();
assert_eq!(vec.len(), 0);
```

### `capacity(&self) -> usize`
Returns the current capacity (number of elements that can be stored without reallocation).

```rust
let mut vec = CxxVector::new();
vec.reserve(10);
assert!(vec.capacity() >= 10);
```

### `is_empty(&self) -> bool`
Checks if vector contains no elements.

```rust
let vec = CxxVector::new();
assert!(vec.is_empty());
```

### `reserve(&mut self, additional: usize)`
Ensures capacity for `additional` more elements. **Follows Rust convention** (additional elements), not C++ convention (total capacity).

```rust
let mut vec = CxxVector::new();
let current_len = vec.len();
vec.reserve(10);
assert!(vec.capacity() >= current_len + 10);
```

---

## Element Access

### `get(&self, pos: usize) -> Option<&T>`
Safe bounds-checked access returning `Option<&T>`.

```rust
let vec = CxxVector::new();
// ... add elements ...
if let Some(element) = vec.get(0) {
    println!("First element: {:?}", element);
}
```

### `index_mut(&mut self, pos: usize) -> Option<Pin<&mut T>>`
Pinned mutable reference with bounds checking. Returns `None` if out of bounds.

```rust
let mut vec = CxxVector::new();
// ... add elements ...
if let Some(mut element) = vec.index_mut(0) {
    // element is Pin<&mut T>
    *element = new_value;
}
```

### `get_unchecked(&self, pos: usize) -> &T` (unsafe)
Unsafe unbounded access. Caller must ensure `pos < len()`.

```rust
let vec = CxxVector::new();
// ... add elements ...
unsafe {
    let element = vec.get_unchecked(0);
}
```

### `as_slice(&self) -> &[T]` (for trivial types)
### `as_mut_slice(&mut self) -> &mut [T]` (for trivial types)
Provides contiguous array access for trivial types (types with `Kind = Trivial`).

```rust
let vec = CxxVector::new();
// ... add i32 elements (trivial type) ...
let slice: &[i32] = vec.as_slice();
println!("Elements: {:?}", slice);
```

**Note:** Only available for types with trivial move constructors.

---

## Iteration

### `iter(&self) -> Iter<'_, T>`
Returns iterator over `&T`.

```rust
let vec = CxxVector::new();
// ... add elements ...
for element in vec.iter() {
    println!("{:?}", element);
}
```

### `iter_mut(&mut self) -> IterMut<'_, T>`
Returns iterator over `Pin<&mut T>`.

```rust
let mut vec = CxxVector::new();
// ... add elements ...
for element in vec.iter_mut() {
    // element is Pin<&mut T>
    *element += 1;
}
```

### `IntoIterator` Implementation
Both shared and mutable iteration supported through `IntoIterator` trait.

```rust
// Immutable iteration
for element in &*vec {
    println!("{:?}", element);
}

// Mutable iteration
for element in vec.pin_mut().iter_mut() {
    *element += 1;
}
```

---

## Modification

### `push(&mut self, value: T)`
Appends element to the end.

```rust
let mut vec = CxxVector::new();
vec.push(42);
vec.push(100);
assert_eq!(vec.len(), 2);
```

### `pop(&mut self) -> Option<T>`
Removes and returns last element, or `None` if empty.

```rust
let mut vec = CxxVector::new();
vec.push(42);
vec.push(100);

assert_eq!(vec.pop(), Some(100));
assert_eq!(vec.pop(), Some(42));
assert_eq!(vec.pop(), None);
```

---

## Trait Implementations

### `Debug`
Formatted output support.

```rust
let vec = CxxVector::new();
println!("{:?}", vec);
```

### `Extend<T>`
Support for iterator extension.

```rust
let mut vec = CxxVector::new();
let items = vec![1, 2, 3, 4, 5];
vec.extend(items);
```

### `IntoIterator`
Both shared and mutable iteration.

```rust
let vec = CxxVector::new();
for item in &*vec {
    println!("{:?}", item);
}
```

### `UniquePtrTarget`
Smart pointer compatibility - `CxxVector<T>` can be wrapped in `UniquePtr`.

```rust
let vec: UniquePtr<CxxVector<i32>> = CxxVector::new();
```

---

## Example Usage

### Basic Vector Operations

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        type CppObject;

        fn create_object(id: i32) -> UniquePtr<CppObject>;
    }
}

fn example() {
    // Create vector of integers
    let mut numbers = CxxVector::new();
    numbers.push(1);
    numbers.push(2);
    numbers.push(3);

    // Access elements
    assert_eq!(numbers.get(0), Some(&1));
    assert_eq!(numbers.get(1), Some(&2));

    // Iterate
    for num in numbers.iter() {
        println!("Number: {}", num);
    }

    // Modify elements
    if let Some(mut first) = numbers.index_mut(0) {
        *first = 10;
    }

    // Pop elements
    while let Some(num) = numbers.pop() {
        println!("Popped: {}", num);
    }
}
```

### Vector of C++ Objects

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        type DataPoint;

        fn get_data_points() -> UniquePtr<CxxVector<DataPoint>>;
        fn process_point(point: &DataPoint);
    }
}

fn process_all_points() {
    let points = ffi::get_data_points();

    // Iterate through points
    for point in points.iter() {
        ffi::process_point(point);
    }

    println!("Processed {} points", points.len());
}
```

### Building a Vector from Rust

```rust
fn build_vector() -> UniquePtr<CxxVector<i32>> {
    let mut vec = CxxVector::new();

    // Reserve capacity for efficiency
    vec.reserve(100);

    // Fill with values
    for i in 0..100 {
        vec.push(i);
    }

    vec
}
```

### Passing Vector to C++

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        fn process_numbers(numbers: &CxxVector<i32>) -> i32;
        fn sort_numbers(numbers: Pin<&mut CxxVector<i32>>);
    }
}

fn example() {
    let mut numbers = CxxVector::new();
    numbers.extend(vec![5, 2, 8, 1, 9]);

    // Pass immutable reference
    let sum = ffi::process_numbers(&numbers);
    println!("Sum: {}", sum);

    // Pass mutable reference for modification
    ffi::sort_numbers(numbers.pin_mut());

    // Verify sorted
    for num in numbers.iter() {
        println!("{}", num);
    }
}
```

---

## Important Notes

### 1. No By-Value Access
You cannot create a `CxxVector<T>` by value in Rust. Always use:
- `&CxxVector<T>` for immutable access
- `Pin<&mut CxxVector<T>>` for mutable access
- `UniquePtr<CxxVector<T>>` for ownership

### 2. Trivial vs Opaque Types
**Trivial types** (e.g., `i32`, `f64`, `bool`):
- Can use `as_slice()` and `as_mut_slice()`
- Can be copied freely
- Have simpler memory semantics

**Opaque types** (most C++ classes):
- Must be accessed element-by-element
- Cannot be copied (may require `UniquePtr` or `SharedPtr`)
- May have special C++ semantics

### 3. Mutable Access Uses Pin
All mutable access returns `Pin<&mut T>` to prevent moving types that shouldn't be moved (C++ types with move constructors or internal pointers).

```rust
// Correct
if let Some(mut element) = vec.index_mut(0) {
    *element = new_value;  // Dereference Pin to modify
}

// Incorrect - cannot move out of Pin
// let element = vec.index_mut(0).unwrap();
// let moved = *element;  // Error!
```

### 4. API Follows Rust Conventions
- `len()` instead of C++'s `size()`
- `reserve(additional)` reserves space for *additional* elements (Rust), not total capacity (C++)
- `is_empty()` instead of checking `size() == 0`

### 5. Performance Considerations
- Use `reserve()` before bulk insertions to avoid multiple reallocations
- For trivial types, `as_slice()` provides zero-cost access to underlying memory
- Iterator overhead is minimal - comparable to C++ iterators

### 6. Thread Safety
`CxxVector<T>` is:
- `Send` when `T: Send` - can be moved to another thread
- `Sync` when `T: Sync` - can be shared across threads (with proper synchronization)

### 7. Memory Management
`CxxVector<T>` manages memory using C++ `std::allocator`. When wrapped in `UniquePtr`, the vector is automatically destroyed when the `UniquePtr` is dropped.

---

## Advanced Patterns

### Vector of Vectors

```rust
let mut matrix: UniquePtr<CxxVector<CxxVector<i32>>> = CxxVector::new();
// Note: This requires special bridge setup for nested vectors
```

### Converting to/from Rust Vec

```rust
// Rust Vec to CxxVector
fn rust_to_cxx(rust_vec: Vec<i32>) -> UniquePtr<CxxVector<i32>> {
    let mut cxx_vec = CxxVector::new();
    cxx_vec.extend(rust_vec);
    cxx_vec
}

// CxxVector to Rust Vec (for trivial types)
fn cxx_to_rust(cxx_vec: &CxxVector<i32>) -> Vec<i32> {
    cxx_vec.as_slice().to_vec()
}
```

### Generic Functions

```rust
use cxx::vector::VectorElement;

fn print_vector<T: VectorElement + std::fmt::Debug>(vec: &CxxVector<T>) {
    for element in vec.iter() {
        println!("{:?}", element);
    }
}
```
