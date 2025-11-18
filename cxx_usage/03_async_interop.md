# Async/Await Interoperability with CXX

This guide provides comprehensive documentation on writing asynchronous code that bridges Rust's async/await with C++ code.

## Current Status

**Native async support is not yet implemented in CXX.** The eventual goal is to support:

```rust
// Future syntax (not yet available)
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        async fn do_async_thing(arg: Arg) -> Ret;  // Not yet supported
    }
}
```

This would allow calling C++20 coroutines directly from Rust async code.

**However**, there are established patterns to bridge async operations between Rust and C++ today.

---

## Conceptual Background

### Rust Async Model

Rust's async/await is based on:
- **Futures**: Lazy computations that produce values asynchronously
- **Poll-based**: Futures are polled until completion
- **Zero-cost**: No built-in runtime; executors are pluggable
- **Tokio/async-std**: Popular runtime choices

```rust
async fn fetch_data(url: &str) -> Result<Vec<u8>, Error> {
    // Async operations
    let response = http_client.get(url).await?;
    response.bytes().await
}
```

### C++ Async Models

C++ has several async patterns:

#### 1. Callbacks
```cpp
void fetch_data(const std::string& url,
                std::function<void(std::vector<uint8_t>)> callback) {
    // Async operation calls callback when done
}
```

#### 2. Futures (std::future)
```cpp
std::future<std::vector<uint8_t>> fetch_data(const std::string& url) {
    return std::async(std::launch::async, [url]() {
        // Perform operation
    });
}
```

#### 3. Coroutines (C++20)
```cpp
#include <coroutine>

Task<std::vector<uint8_t>> fetch_data(std::string url) {
    co_return perform_fetch(url);
}
```

#### 4. Promise-based (custom or library)
```cpp
Promise<std::vector<uint8_t>> fetch_data(const std::string& url);
```

---

## Pattern 1: Oneshot Channel (Single Result)

**Use case**: C++ performs an async operation and returns a single result to Rust.

This is the **recommended pattern** for bridging C++ async operations to Rust futures.

### Rust Side Setup

```rust
use futures::channel::oneshot;

#[cxx::bridge]
mod ffi {
    // Opaque context type holding the channel sender
    extern "Rust" {
        type AsyncContext;
    }

    // C++ function that accepts a callback
    unsafe extern "C++" {
        include!("mylib.h");

        fn fetch_data_async(
            url: &str,
            callback: fn(context: Box<AsyncContext>, result: Vec<u8>),
            context: Box<AsyncContext>,
        );
    }
}

// The context holds a oneshot sender
pub struct AsyncContext {
    sender: oneshot::Sender<Result<Vec<u8>, String>>,
}

// High-level Rust async function
pub async fn fetch_data(url: &str) -> Result<Vec<u8>, String> {
    let (sender, receiver) = oneshot::channel();

    let context = Box::new(AsyncContext { sender });

    // Call C++ async function
    ffi::fetch_data_async(
        url,
        handle_fetch_result,  // Callback function
        context,
    );

    // Await the result
    receiver.await
        .map_err(|_| "Channel closed".to_string())?
}

// Callback invoked by C++ when operation completes
fn handle_fetch_result(context: Box<AsyncContext>, result: Vec<u8>) {
    // Send result through the channel
    let _ = context.sender.send(Ok(result));
}
```

### C++ Side Implementation

```cpp
#include "my-crate/src/main.rs.h"
#include <thread>
#include <chrono>

// Type alias for callback
using ResultCallback = rust::Fn<void(
    rust::Box<AsyncContext>,
    rust::Vec<uint8_t>
)>;

void fetch_data_async(
    rust::Str url,
    ResultCallback callback,
    rust::Box<AsyncContext> context
) {
    // Spawn async operation (e.g., in a thread pool)
    std::thread([
        url = std::string(url),
        callback = std::move(callback),
        context = std::move(context)
    ]() mutable {
        // Simulate async work
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Perform the actual operation
        rust::Vec<uint8_t> result;
        result.push_back(0x48);  // 'H'
        result.push_back(0x69);  // 'i'

        // Invoke callback with result
        callback(std::move(context), std::move(result));
    }).detach();
}
```

### Usage from Async Rust

```rust
#[tokio::main]
async fn main() {
    let url = "https://example.com/data";

    match fetch_data(url).await {
        Ok(data) => {
            println!("Received {} bytes", data.len());
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
```

---

## Pattern 2: Multi-shot Channel (Stream of Results)

**Use case**: C++ produces multiple results over time (e.g., streaming data, events).

### Rust Side Setup

```rust
use futures::channel::mpsc;
use futures::StreamExt;

#[cxx::bridge]
mod ffi {
    extern "Rust" {
        type StreamContext;
    }

    unsafe extern "C++" {
        include!("mylib.h");

        fn subscribe_events(
            callback: fn(context: &StreamContext, event: String),
            context: Box<StreamContext>,
        );
    }
}

pub struct StreamContext {
    sender: mpsc::UnboundedSender<String>,
}

// Create a stream of events from C++
pub fn event_stream() -> mpsc::UnboundedReceiver<String> {
    let (sender, receiver) = mpsc::unbounded();

    let context = Box::new(StreamContext { sender });

    ffi::subscribe_events(handle_event, context);

    receiver
}

// Callback for each event
fn handle_event(context: &StreamContext, event: String) {
    // Send event through the channel
    let _ = context.sender.unbounded_send(event);
}
```

### C++ Side Implementation

```cpp
#include "my-crate/src/main.rs.h"
#include <thread>
#include <chrono>

using EventCallback = rust::Fn<void(
    const StreamContext&,
    rust::String
)>;

void subscribe_events(
    EventCallback callback,
    rust::Box<StreamContext> context
) {
    // In a real implementation, this would register with an event system
    std::thread([
        callback = std::move(callback),
        context = std::move(context)
    ]() {
        // Simulate events
        for (int i = 0; i < 10; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            std::string event = "Event #" + std::to_string(i);
            callback(*context, rust::String(event));
        }
    }).detach();
}
```

### Consuming the Stream

```rust
#[tokio::main]
async fn main() {
    let mut events = event_stream();

    while let Some(event) = events.next().await {
        println!("Received: {}", event);
    }
}
```

---

## Pattern 3: Blocking Bridge (Spawn Blocking)

**Use case**: C++ has a blocking operation you want to call from async Rust without blocking the runtime.

### Rust Side

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("mylib.h");

        // Blocking C++ function
        fn perform_blocking_work(data: &[u8]) -> Vec<u8>;
    }
}

// Async wrapper using spawn_blocking
pub async fn async_work(data: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(move || {
        let slice = data.as_slice();
        Ok(ffi::perform_blocking_work(slice))
    })
    .await?
}
```

### C++ Side

```cpp
#include "my-crate/src/main.rs.h"
#include <algorithm>

rust::Vec<uint8_t> perform_blocking_work(rust::Slice<const uint8_t> data) {
    // This function can block - Rust will call it in a blocking thread pool
    rust::Vec<uint8_t> result;

    // Simulate expensive blocking operation
    for (size_t i = 0; i < data.size(); i++) {
        // Some CPU-intensive work
        result.push_back(data[i] * 2);
    }

    return result;
}
```

---

## Pattern 4: Future Executor Bridge

**Use case**: Run Rust async code from C++ callbacks.

### Rust Side

```rust
use tokio::runtime::Runtime;
use std::sync::Arc;

#[cxx::bridge]
mod ffi {
    extern "Rust" {
        type RuntimeHandle;

        fn create_runtime() -> Box<RuntimeHandle>;
        fn spawn_task(
            runtime: &RuntimeHandle,
            url: String,
        ) -> u64;  // Task ID
    }

    unsafe extern "C++" {
        include!("mylib.h");

        fn register_callback(runtime: &RuntimeHandle);
    }
}

pub struct RuntimeHandle {
    runtime: Arc<Runtime>,
}

fn create_runtime() -> Box<RuntimeHandle> {
    let runtime = Runtime::new().unwrap();
    Box::new(RuntimeHandle {
        runtime: Arc::new(runtime),
    })
}

fn spawn_task(runtime: &RuntimeHandle, url: String) -> u64 {
    let handle = runtime.runtime.spawn(async move {
        // Perform async work
        fetch_data_internal(&url).await
    });

    // Return task ID (simplified)
    0
}

async fn fetch_data_internal(url: &str) -> Vec<u8> {
    // Actual async implementation
    vec![1, 2, 3]
}
```

### C++ Side

```cpp
#include "my-crate/src/main.rs.h"

void register_callback(const RuntimeHandle& runtime) {
    // When an event occurs in C++, spawn a Rust async task
    auto on_event = [&runtime](const std::string& url) {
        spawn_task(runtime, rust::String(url));
    };

    // Register with your C++ event system
    // event_system.on_data(on_event);
}
```

---

## Pattern 5: C++20 Coroutines to Rust Futures

**Use case**: Bridge C++20 coroutines to Rust async (advanced).

This requires a C++20 coroutine library and careful integration.

### C++ Coroutine Setup

```cpp
#include <coroutine>
#include <memory>

// Simple coroutine task type
template<typename T>
struct Task {
    struct promise_type {
        T value;

        Task get_return_object() {
            return Task{
                std::coroutine_handle<promise_type>::from_promise(*this)
            };
        }

        std::suspend_never initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }

        void return_value(T v) { value = std::move(v); }
        void unhandled_exception() { std::terminate(); }
    };

    std::coroutine_handle<promise_type> handle;

    T get_result() {
        return handle.promise().value;
    }

    ~Task() {
        if (handle) handle.destroy();
    }
};

// Coroutine function
Task<rust::Vec<uint8_t>> fetch_data_coro(std::string url) {
    // Simulate async work
    // co_await some_async_operation();

    rust::Vec<uint8_t> result;
    result.push_back(42);

    co_return result;
}
```

### Bridging to Rust

```cpp
// Adapter function that bridges coroutine to callback
void fetch_data_async_coro(
    rust::Str url,
    rust::Fn<void(rust::Box<AsyncContext>, rust::Vec<uint8_t>)> callback,
    rust::Box<AsyncContext> context
) {
    std::thread([
        url = std::string(url),
        callback = std::move(callback),
        context = std::move(context)
    ]() mutable {
        // Start coroutine
        auto task = fetch_data_coro(url);

        // Get result (simplified - real implementation needs proper awaiting)
        auto result = task.get_result();

        // Invoke callback
        callback(std::move(context), std::move(result));
    }).detach();
}
```

---

## Complete Example: Async HTTP Client

### Project Structure

```
async-http-client/
├── Cargo.toml
├── build.rs
├── include/
│   └── http_client.h
├── src/
│   ├── main.rs
│   └── http_client.cc
```

### Cargo.toml

```toml
[package]
name = "async-http-client"
version = "0.1.0"
edition = "2021"

[dependencies]
cxx = "1.0"
tokio = { version = "1", features = ["full"] }
futures = "0.3"

[build-dependencies]
cxx-build = "1.0"
```

### build.rs

```rust
fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/http_client.cc")
        .std("c++17")
        .compile("async-http-client");

    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/http_client.cc");
    println!("cargo:rerun-if-changed=include/http_client.h");
}
```

### src/main.rs

```rust
use futures::channel::oneshot;

#[cxx::bridge]
mod ffi {
    // Request/Response types
    struct HttpRequest {
        url: String,
        method: String,
        headers: Vec<String>,
        body: Vec<u8>,
    }

    struct HttpResponse {
        status: i32,
        headers: Vec<String>,
        body: Vec<u8>,
    }

    // Context for async operation
    extern "Rust" {
        type HttpContext;
    }

    // C++ async HTTP client
    unsafe extern "C++" {
        include!("http_client.h");

        fn http_request_async(
            request: HttpRequest,
            callback: fn(
                context: Box<HttpContext>,
                response: HttpResponse,
            ),
            context: Box<HttpContext>,
        );
    }
}

// Context holding the oneshot sender
pub struct HttpContext {
    sender: oneshot::Sender<Result<ffi::HttpResponse, String>>,
}

// High-level async function
pub async fn http_get(url: &str) -> Result<ffi::HttpResponse, String> {
    let (sender, receiver) = oneshot::channel();

    let request = ffi::HttpRequest {
        url: url.to_string(),
        method: "GET".to_string(),
        headers: vec![],
        body: vec![],
    };

    let context = Box::new(HttpContext { sender });

    ffi::http_request_async(
        request,
        handle_http_response,
        context,
    );

    receiver.await
        .map_err(|_| "Response channel closed".to_string())?
}

pub async fn http_post(
    url: &str,
    body: Vec<u8>,
) -> Result<ffi::HttpResponse, String> {
    let (sender, receiver) = oneshot::channel();

    let request = ffi::HttpRequest {
        url: url.to_string(),
        method: "POST".to_string(),
        headers: vec!["Content-Type: application/octet-stream".to_string()],
        body,
    };

    let context = Box::new(HttpContext { sender });

    ffi::http_request_async(
        request,
        handle_http_response,
        context,
    );

    receiver.await
        .map_err(|_| "Response channel closed".to_string())?
}

// Callback function
fn handle_http_response(
    context: Box<HttpContext>,
    response: ffi::HttpResponse,
) {
    let _ = context.sender.send(Ok(response));
}

// Usage example
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fetch data asynchronously
    let response = http_get("https://api.example.com/data").await?;

    println!("Status: {}", response.status);
    println!("Body size: {} bytes", response.body.len());

    // Post data
    let data = vec![1, 2, 3, 4, 5];
    let post_response = http_post("https://api.example.com/upload", data).await?;

    println!("Upload status: {}", post_response.status);

    Ok(())
}
```

### include/http_client.h

```cpp
#pragma once
#include "rust/cxx.h"
#include "async-http-client/src/main.rs.h"

void http_request_async(
    HttpRequest request,
    rust::Fn<void(rust::Box<HttpContext>, HttpResponse)> callback,
    rust::Box<HttpContext> context
);
```

### src/http_client.cc

```cpp
#include "http_client.h"
#include <thread>
#include <chrono>
#include <iostream>

// Simulate async HTTP library
void perform_http_request(
    const HttpRequest& request,
    rust::Fn<void(rust::Box<HttpContext>, HttpResponse)> callback,
    rust::Box<HttpContext> context
) {
    // In a real implementation, this would use libcurl, Boost.Beast, etc.
    std::thread([
        url = std::string(request.url),
        method = std::string(request.method),
        callback = std::move(callback),
        context = std::move(context)
    ]() mutable {
        // Simulate network delay
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Create response
        HttpResponse response;
        response.status = 200;

        // Add some headers
        response.headers.push_back(rust::String("Content-Type: application/json"));

        // Simulate response body
        std::string body = R"({"message": "Hello from C++"})";
        for (char c : body) {
            response.body.push_back(static_cast<uint8_t>(c));
        }

        // Invoke callback
        callback(std::move(context), std::move(response));
    }).detach();
}

void http_request_async(
    HttpRequest request,
    rust::Fn<void(rust::Box<HttpContext>, HttpResponse)> callback,
    rust::Box<HttpContext> context
) {
    perform_http_request(request, std::move(callback), std::move(context));
}
```

---

## Best Practices for Async Interop

### 1. Use Oneshot for Single Results

```rust
// ✓ Good: Clear ownership, single result
let (sender, receiver) = oneshot::channel();
// ... call C++, await receiver
```

### 2. Use MPSC for Streams

```rust
// ✓ Good: Multiple results over time
let (sender, receiver) = mpsc::unbounded();
// ... call C++, stream from receiver
```

### 3. Handle Cancellation

```rust
pub async fn fetch_with_timeout(url: &str) -> Result<Vec<u8>, String> {
    tokio::time::timeout(
        Duration::from_secs(5),
        fetch_data(url),
    )
    .await
    .map_err(|_| "Timeout".to_string())?
}
```

### 4. Error Propagation

```rust
// Modify callback to handle errors
fn handle_result(
    context: Box<AsyncContext>,
    success: bool,
    data: Vec<u8>,
    error: String,
) {
    let result = if success {
        Ok(data)
    } else {
        Err(error)
    };
    let _ = context.sender.send(result);
}
```

### 5. Thread Safety

```cpp
// ✓ Good: Move ownership into thread
std::thread([
    callback = std::move(callback),
    context = std::move(context)
]() mutable {
    // Use callback and context
}).detach();

// ✗ Bad: Dangling references
std::thread([&callback, &context]() {
    // callback and context may be destroyed!
}).detach();
```

### 6. Resource Cleanup

```rust
// Ensure channels are dropped properly
impl Drop for AsyncContext {
    fn drop(&mut self) {
        // Cleanup if needed
    }
}
```

---

## Common Pitfalls

### 1. Blocking the Async Runtime

```rust
// ✗ Bad: Blocks the runtime
async fn bad_async_call() -> Vec<u8> {
    ffi::blocking_cpp_function()  // Blocks!
}

// ✓ Good: Use spawn_blocking
async fn good_async_call() -> Vec<u8> {
    tokio::task::spawn_blocking(|| {
        ffi::blocking_cpp_function()
    })
    .await
    .unwrap()
}
```

### 2. Forgetting to Send Result

```rust
// ✗ Bad: Sender is dropped without sending
fn bad_callback(context: Box<AsyncContext>, result: Vec<u8>) {
    // Sender is dropped, receiver gets error!
}

// ✓ Good: Always send result
fn good_callback(context: Box<AsyncContext>, result: Vec<u8>) {
    let _ = context.sender.send(Ok(result));
}
```

### 3. Lifetime Issues

```cpp
// ✗ Bad: Context outlives the callback
void bad_async_call(rust::Box<Context> context) {
    std::thread([&context]() {  // Dangling reference!
        // ...
    }).detach();
}

// ✓ Good: Move ownership
void good_async_call(rust::Box<Context> context) {
    std::thread([context = std::move(context)]() mutable {
        // context is owned by the thread
    }).detach();
}
```

---

## Future: Native Async Support

When native async support lands in CXX, the syntax will be much simpler:

```rust
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        async fn fetch_data(url: &str) -> Vec<u8>;
    }
}

// Usage
let data = ffi::fetch_data("https://example.com").await;
```

Until then, the channel-based patterns provide a robust bridge between Rust futures and C++ async operations.
