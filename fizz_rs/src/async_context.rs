//! Async I/O context types for channel-based communication with C++
//!
//! This module implements the oneshot channel pattern for bridging C++ async operations
//! to Rust futures, following CXX best practices (Pattern 1 from cxx.rs documentation).

use futures::channel::oneshot;

/// Context for async I/O operations (handshake, read, write)
///
/// Holds a oneshot sender that receives the result from C++ callbacks.
/// The C++ side invokes `handle_io_result` when the operation completes.
///
/// Note: This type is exposed to C++ via the CXX bridge.
pub struct IoContext {
    pub(crate) sender: oneshot::Sender<Result<usize, String>>,
}

impl IoContext {
    /// Create a new IoContext with a oneshot channel
    pub fn new() -> (Self, oneshot::Receiver<Result<usize, String>>) {
        let (sender, receiver) = oneshot::channel();
        (Self { sender }, receiver)
    }
}

/// Callback invoked by C++ when an async I/O operation completes
///
/// # Parameters
/// - `context`: The IoContext containing the result sender
/// - `bytes`: Number of bytes transferred (or 0 for handshake success)
/// - `error`: Error message if operation failed, empty string on success
///
/// # C++ Usage
/// ```cpp
/// callback(std::move(context), bytes_transferred, rust::String(""));  // Success
/// callback(std::move(context), 0, rust::String("Connection closed")); // Error
/// ```
pub fn handle_io_result(context: Box<IoContext>, bytes: usize, error: String) {
    let result = if error.is_empty() {
        Ok(bytes)
    } else {
        Err(error)
    };

    // Send result through channel (ignore error if receiver was dropped)
    let _ = context.sender.send(result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_io_context_success() {
        let (context, receiver) = IoContext::new();

        // Simulate C++ callback
        handle_io_result(Box::new(context), 42, String::new());

        let result = receiver.await.unwrap();
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_io_context_error() {
        let (context, receiver) = IoContext::new();

        // Simulate C++ callback with error
        handle_io_result(Box::new(context), 0, "Connection failed".to_string());

        let result = receiver.await.unwrap();
        assert_eq!(result, Err("Connection failed".to_string()));
    }
}
