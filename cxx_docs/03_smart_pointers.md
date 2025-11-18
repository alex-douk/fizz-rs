# CXX Smart Pointers

## `UniquePtr<T>`

### Overview
`UniquePtr<T>` is a Rust binding to C++'s `std::unique_ptr<T, std::default_delete<T>>`, enabling safe interoperability between Rust and C++ for exclusive ownership pointers.

### Key Invariant
`UniquePtr<T>` represents exclusive ownership of a heap-allocated C++ object. When the `UniquePtr` is dropped, the underlying C++ object is destroyed.

### Creation & Null Checks

#### `null() -> UniquePtr<T>`
Creates a null UniquePtr (matches C++ default construction).

```rust
let ptr: UniquePtr<MyCppType> = UniquePtr::null();
assert!(ptr.is_null());
```

#### `new(value: T) -> UniquePtr<T>`
Allocates heap memory and wraps it in a `UniquePtr`.

```rust
// For trivial types
let ptr = UniquePtr::new(42i32);
```

#### `is_null(&self) -> bool`
Returns `true` if the pointer is null.

```rust
let ptr: UniquePtr<MyCppType> = UniquePtr::null();
if ptr.is_null() {
    println!("Pointer is null");
}
```

### Access Methods

#### `as_ref(&self) -> Option<&T>`
Returns `Option<&T>` - `Some(&T)` if non-null, `None` if null.

```rust
if let Some(value) = ptr.as_ref() {
    println!("Value: {:?}", value);
}
```

#### `as_mut(&mut self) -> Option<Pin<&mut T>>`
Returns `Option<Pin<&mut T>>` for mutable access. Returns pinned mutable reference due to C++ semantics.

```rust
if let Some(mut value) = ptr.as_mut() {
    // value is Pin<&mut T>
    value.modify();
}
```

#### `pin_mut(&mut self) -> Pin<&mut T>`
Returns pinned mutable reference, **panics if null**.

```rust
let mut ptr = UniquePtr::new(42);
let pinned = ptr.pin_mut();
*pinned = 100;
```

#### `as_ptr(&self) -> *const T`
#### `as_mut_ptr(&mut self) -> *mut T`
Raw pointer access for unsafe operations.

```rust
let ptr = UniquePtr::new(42);
let raw_ptr: *const i32 = ptr.as_ptr();
```

### Ownership Transfer

#### `into_raw(self) -> *mut T`
Consumes the `UniquePtr` and releases ownership, returning a raw pointer. The caller becomes responsible for freeing the memory.

```rust
let ptr = UniquePtr::new(42);
let raw = ptr.into_raw();
// Must manually free or reconstruct UniquePtr
```

#### `from_raw(ptr: *mut T) -> UniquePtr<T>` (unsafe)
Unsafe constructor that retakes ownership of a raw pointer.

```rust
unsafe {
    let raw_ptr = some_cpp_function();
    let ptr = UniquePtr::from_raw(raw_ptr);
    // ptr now owns the memory
}
```

### Trait Implementations

#### Smart Pointer Traits
- **`Deref`** - Dereference to `&T`
- **`DerefMut`** - Mutable dereference (returns `Pin<&mut T>`)
- **`Drop`** - Automatically destroys the C++ object

#### Comparison Traits
- **`Debug`**, **`Display`** - Formatting
- **`PartialEq`**, **`Eq`** - Equality comparison
- **`PartialOrd`**, **`Ord`** - Ordering comparison
- **`Hash`** - Hashing support

#### I/O Traits
- **`Read`**, **`Write`**, **`Seek`** - Forwarded like `Box<T>`
- **Note:** I/O trait implementations panic on null pointers

#### Safety Traits
- **`Send`**, **`Sync`** - Thread safety when `T: Send`/`Sync`
- **`Unpin`** - Can be safely moved

### Conversions

#### To `SharedPtr<T>`
```rust
use cxx::{UniquePtr, SharedPtr};

let unique = UniquePtr::new(42);
let shared: SharedPtr<i32> = unique.into();
```

### Example Usage

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        type MyCppClass;

        fn create_object() -> UniquePtr<MyCppClass>;
        fn process(obj: UniquePtr<MyCppClass>);
        fn get_value(obj: &MyCppClass) -> i32;
    }
}

fn example() {
    // Create object from C++
    let obj = ffi::create_object();

    // Check if null
    if obj.is_null() {
        println!("Failed to create object");
        return;
    }

    // Access through reference
    if let Some(obj_ref) = obj.as_ref() {
        let value = ffi::get_value(obj_ref);
        println!("Value: {}", value);
    }

    // Transfer ownership to C++
    ffi::process(obj); // obj is consumed
}
```

### Important Notes

1. **Mutable Access Requires Pinning**: Due to C++ move semantics, mutable access always returns `Pin<&mut T>`.

2. **Null Pointer Safety**: Many methods return `Option` to handle null pointers safely. Methods like `pin_mut()` panic on null.

3. **Ownership Semantics**: `UniquePtr` has move semantics - transferring it consumes the original.

4. **Thread Safety**: `UniquePtr<T>` is `Send` and `Sync` when `T` is, allowing safe use across threads.

5. **ABI Compatibility**: Uses `#[repr(C)]` for FFI compatibility with C++ `std::unique_ptr`.

---

## `SharedPtr<T>`

### Overview
`SharedPtr<T>` is a Rust binding to C++'s `std::shared_ptr<T>`, enabling safe interoperability between Rust and C++ for shared ownership through reference counting.

### Key Distinction from Rust's `Arc<T>`
Unlike Rust's `Arc<T>`, C++ shared pointers maintain **two separate pointers**:
- **Managed pointer**: Controls reference counting and deletion
- **Stored pointer**: The pointer actually accessed through dereferencing

This architectural difference means a `SharedPtr` can be:
- **Empty** (refcount = 0) while remaining **nonnull** (stored pointer is non-null)
- **Null** (stored pointer is null) while **nonempty** (refcount > 0)

All four combinations (empty/nonempty × null/nonnull) are possible.

### Creation Methods

#### `null() -> SharedPtr<T>`
Creates an empty, null `SharedPtr`.

```rust
let ptr: SharedPtr<MyCppType> = SharedPtr::null();
assert!(ptr.is_null());
```

#### `new(value: T) -> SharedPtr<T>`
Allocates on heap with `SharedPtr` ownership.

```rust
let ptr = SharedPtr::new(42);
```

#### `from_raw(ptr: *mut T) -> SharedPtr<T>` (unsafe)
Wraps a C++ heap-allocated pointer in a `SharedPtr`.

```rust
unsafe {
    let raw = some_cpp_allocation();
    let shared = SharedPtr::from_raw(raw);
}
```

### Access Methods

#### `is_null(&self) -> bool`
Checks if the stored pointer is null (not whether it's empty).

```rust
if ptr.is_null() {
    println!("Stored pointer is null");
}
```

#### `as_ref(&self) -> Option<&T>`
Returns `Some(&T)` if nonnull, `None` if null.

```rust
if let Some(value) = ptr.as_ref() {
    println!("Value: {:?}", value);
}
```

#### `as_ptr(&self) -> *const T`
#### `as_mut_ptr(&mut self) -> *mut T`
Raw pointer access.

```rust
let raw_ptr = ptr.as_ptr();
```

### Weak References

#### `downgrade(&self) -> WeakPtr<T>`
Creates an associated `WeakPtr` that doesn't prevent deallocation.

```rust
let shared = SharedPtr::new(42);
let weak = shared.downgrade();

// Later, try to upgrade
if let Some(strong) = weak.upgrade() {
    println!("Object still alive");
}
```

### Unsafe Mutable Access

#### `pin_mut_unchecked(&mut self) -> Pin<&mut T>` (unsafe)
Returns mutable pinned reference without null checking. **Unsafe** - caller must ensure non-null.

```rust
unsafe {
    let mut ptr = SharedPtr::new(42);
    let pinned = ptr.pin_mut_unchecked();
    *pinned = 100;
}
```

### Trait Implementations

#### Reference Counting
- **`Clone`** - Increments reference count
- **`Drop`** - Decrements reference count, destroys object when count reaches zero

#### Comparison and Formatting
- **`Debug`**, **`Display`** - Formatting support
- **`Eq`**, **`PartialEq`** - Equality comparison
- **`Ord`**, **`PartialOrd`** - Ordering comparison
- **`Hash`** - Hashing support

#### Smart Pointer
- **`Deref`** - Dereference to `&T`

#### Safety
- **`Send`**, **`Sync`** - Thread-safe when `T: Send`/`Sync`
- **`Unpin`** - Can be safely moved

### Conversions

#### From `UniquePtr<T>`
```rust
let unique = UniquePtr::new(42);
let shared: SharedPtr<i32> = unique.into();
```

### Example Usage

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        type Resource;

        fn create_shared_resource() -> SharedPtr<Resource>;
        fn use_resource(res: &Resource);
        fn share_resource(res: SharedPtr<Resource>);
    }
}

fn example() {
    // Create shared resource
    let resource = ffi::create_shared_resource();

    // Clone for multiple ownership
    let resource2 = resource.clone();

    // Access through reference
    if let Some(res_ref) = resource.as_ref() {
        ffi::use_resource(res_ref);
    }

    // Create weak reference
    let weak = resource.downgrade();

    // Share with C++ (reference count incremented)
    ffi::share_resource(resource2);

    // Try to access through weak pointer
    if let Some(strong) = weak.upgrade() {
        println!("Resource still available");
    }
}
```

### Important Notes

1. **Reference Counting**: `SharedPtr` uses atomic reference counting, making it thread-safe.

2. **Empty vs Null**: A `SharedPtr` can be empty (no managed object) but non-null (stored pointer set), or vice versa. Check both states when needed.

3. **Weak Pointers**: Use `downgrade()` to create weak references that don't prevent deallocation.

4. **Thread Safety**: Like C++ `shared_ptr`, `SharedPtr<T>` is thread-safe for the reference count, but concurrent access to `T` requires synchronization.

5. **Conversion from Unique**: `UniquePtr<T>` can be converted to `SharedPtr<T>`, but not vice versa.

---

## `WeakPtr<T>`

### Overview
`WeakPtr<T>` is a Rust binding to C++ `std::weak_ptr<T>`, enabling safe interoperability between Rust and C++ for non-owning references.

### Purpose
Weak pointers provide non-owning references to objects managed by `SharedPtr`. They don't prevent the object from being destroyed, and must be "upgraded" to `SharedPtr` to access the object.

### Typical Usage
The typical way to construct a `WeakPtr` from Rust is by downgrading from a `SharedPtr`:

```rust
let shared = SharedPtr::new(42);
let weak = shared.downgrade();
```

### Core Methods

#### `null() -> WeakPtr<T>`
Creates a null `WeakPtr`, matching default C++ construction behavior.

```rust
let weak: WeakPtr<MyCppType> = WeakPtr::null();
```

#### `upgrade(&self) -> SharedPtr<T>`
Converts a weak reference to an owning `SharedPtr` if the underlying object still exists, otherwise returns null `SharedPtr`.

```rust
let shared = SharedPtr::new(42);
let weak = shared.downgrade();

// Object still exists
let shared2 = weak.upgrade();
assert!(!shared2.is_null());

drop(shared);
drop(shared2);

// Object has been destroyed
let shared3 = weak.upgrade();
assert!(shared3.is_null());
```

### Trait Implementations

#### Essential Traits
- **`Clone`** - Duplicates the weak pointer
- **`Drop`** - Properly releases the weak reference
- **`Debug`** - Enables formatted output

#### Thread Safety
- **`Send`** - Can be sent across threads when `T: Send`
- **`Sync`** - Can be shared across threads when `T: Sync`

#### Auto Traits
- **`Freeze`** - Immutable once created
- **`Unpin`** - Can be moved safely
- **`RefUnwindSafe`** - Safe across panic boundaries
- **`UnwindSafe`** - Won't cause memory unsafety during unwinding

### Generic Constraints
- The type requires `T: WeakPtrTarget`
- The `upgrade()` method additionally requires `T: SharedPtrTarget`

### Example Usage

```rust
#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("mylib.h");

        type Cache;

        fn create_cache() -> SharedPtr<Cache>;
        fn get_cached_value(cache: &Cache) -> i32;
    }
}

use std::collections::HashMap;

struct CacheManager {
    caches: HashMap<String, WeakPtr<ffi::Cache>>,
}

impl CacheManager {
    fn new() -> Self {
        Self {
            caches: HashMap::new(),
        }
    }

    fn register_cache(&mut self, name: String, cache: &SharedPtr<ffi::Cache>) {
        // Store weak pointer to avoid keeping caches alive
        self.caches.insert(name, cache.downgrade());
    }

    fn get_cache(&self, name: &str) -> Option<SharedPtr<ffi::Cache>> {
        if let Some(weak) = self.caches.get(name) {
            let shared = weak.upgrade();
            if !shared.is_null() {
                return Some(shared);
            }
        }
        None
    }

    fn cleanup_dead_caches(&mut self) {
        self.caches.retain(|_, weak| {
            !weak.upgrade().is_null()
        });
    }
}

fn example() {
    let mut manager = CacheManager::new();

    // Create and register a cache
    let cache = ffi::create_cache();
    manager.register_cache("main".to_string(), &cache);

    // Access cache through weak pointer
    if let Some(cache_ref) = manager.get_cache("main") {
        if let Some(c) = cache_ref.as_ref() {
            let value = ffi::get_cached_value(c);
            println!("Cached value: {}", value);
        }
    }

    // Drop the strong reference
    drop(cache);

    // Weak pointer now points to destroyed object
    assert!(manager.get_cache("main").is_none());

    // Clean up dead references
    manager.cleanup_dead_caches();
}
```

### Important Notes

1. **Non-Owning**: `WeakPtr` does not prevent object destruction. Always check the result of `upgrade()`.

2. **Upgrade Pattern**: The standard pattern is:
   ```rust
   let shared = weak.upgrade();
   if !shared.is_null() {
       // Use shared
   }
   ```

3. **Cache-Like Structures**: `WeakPtr` is ideal for cache-like structures where you want to track objects without keeping them alive.

4. **Thread Safety**: Like `SharedPtr`, `WeakPtr` is thread-safe for the reference count operations.

5. **Cycle Breaking**: Use `WeakPtr` to break reference cycles in data structures that would otherwise leak memory.

### Common Patterns

#### Observer Pattern
```rust
struct Observable {
    observers: Vec<WeakPtr<Observer>>,
}

impl Observable {
    fn notify(&mut self) {
        // Automatically skip destroyed observers
        self.observers.retain(|weak| {
            let observer = weak.upgrade();
            if !observer.is_null() {
                // Notify observer
                true
            } else {
                false // Remove dead observer
            }
        });
    }
}
```

#### Parent-Child Relationships
```rust
struct Node {
    parent: WeakPtr<Node>,
    children: Vec<SharedPtr<Node>>,
}

// Children hold strong references to prevent destruction
// Parent holds weak reference to avoid cycles
```
