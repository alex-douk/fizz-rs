/*
 * server_tls_ffi.cpp
 *
 * Implementation of server-side TLS FFI functions with delegated credentials.
 */

#define GLOG_USE_GLOG_EXPORT

#include "ffi/server_tls_ffi.h"
#include "fizz_rs/src/bridge.rs.h"
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/server/TicketTypes.h>
#include <fizz/server/AeadTicketCipher.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialFactory.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/Serialization.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/IOBufQueue.h>
#include <stdexcept>
#include <chrono>
#include <iostream>
#include <thread>
#include <array>
#include <iterator>
#include <variant>

//TODO(douk): Maybe session resumption with ticket cipher
static std::shared_ptr<fizz::server::TicketCipher> createTicketCipher() {
    return nullptr;
}

//TODO: Shared EVB (Lazy start at first connection establishment could cause handshake timeout issue.)
// const std::shared_ptr<folly::EventBase> SHARED_EVENT_BASE = std::make_shared<folly::EventBase>();
//
// void start_shared_evb() {
//
// }

// ============================================================================
// Server Context Creation
// ============================================================================

std::unique_ptr<FizzServerContext> new_server_tls_context(
    const CertificatePublic& parent_cert,
    const ServiceCredential& delegated_cred) {
    try {
        auto context = std::make_unique<FizzServerContext>();

        // Create Fizz server context
        context->ctx = std::make_shared<fizz::server::FizzServerContext>();

        // Load delegated credential from PEM
        // CRITICAL: Parent cert MUST come BEFORE delegated credential PEM
        // This matches Fizz's loadDCFromPEM() expectations and the C++ reference implementation
        std::string combinedPEM = std::string(parent_cert.cert_pem) +
                                  std::string(delegated_cred.credential_pem);

        auto dcCert = fizz::extensions::loadDCFromPEM(
            combinedPEM,
            fizz::extensions::DelegatedCredentialMode::Server);

        if (!dcCert) {
            throw std::runtime_error("Failed to load delegated credential from PEM");
        }

        // Create delegated credential cert manager
        context->certManager = std::make_unique<
            fizz::extensions::DelegatedCredentialCertManager>();

        context->certManager->addDelegatedCredentialAndSetDefault(
            std::shared_ptr<fizz::extensions::SelfDelegatedCredential>(
                std::move(dcCert)));

        // Set cert manager in context
        context->ctx->setCertManager(std::move(context->certManager));

        // Create and set ticket cipher for session resumption
        context->ticketCipher = createTicketCipher();
        context->ctx->setTicketCipher(context->ticketCipher);

        // Configure supported versions
        context->ctx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});

        // Configure supported ciphers
        context->ctx->setSupportedCiphers({{
            fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
            fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
            fizz::CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        }});

        // Configure supported signature schemes
        context->ctx->setSupportedSigSchemes({{
            fizz::SignatureScheme::ecdsa_secp256r1_sha256,
            fizz::SignatureScheme::ecdsa_secp384r1_sha384,
            fizz::SignatureScheme::ecdsa_secp521r1_sha512,
            fizz::SignatureScheme::rsa_pss_sha256
        }});

        // Configure supported groups
        context->ctx->setSupportedGroups({{
            fizz::NamedGroup::secp256r1,
            fizz::NamedGroup::secp384r1,
            fizz::NamedGroup::secp521r1,
            fizz::NamedGroup::x25519
        }});

        // Initialize ALPN protocols list (empty for now, can be set later)
        context->alpnProtocols = {};

        return context;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create server TLS context: " + std::string(e.what()));
    }
}

void server_context_set_alpn_protocols(
    FizzServerContext& ctx,
    rust::Vec<rust::String> protocols) {
    try {
        ctx.alpnProtocols.clear();
        for (const auto& proto : protocols) {
            ctx.alpnProtocols.push_back(std::string(proto));
        }

        if (!ctx.alpnProtocols.empty()) {
            ctx.ctx->setSupportedAlpns(ctx.alpnProtocols);
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to set ALPN protocols: " + std::string(e.what()));
    }
}

// ============================================================================
// Server Connection Management
// ============================================================================

// Destructor for FizzServerConnection - ensures EventBase thread is cleaned up
FizzServerConnection::~FizzServerConnection() {
    try {
        // Stop EventBase thread if it's running
        if (evb_thread && evb_thread->joinable()) {
            if (evb) {
                evb->terminateLoopSoon();
            }
            evb_thread->join();
        }

    } catch (...) {
        // Swallow exceptions in destructor to avoid std::terminate
    }
}

void FizzServerConnection::getReadBuffer(void** bufReturn, size_t* lenReturn) {
  // Preallocate buffer in the queue - min 4096 bytes
  auto result = readBufQueue_.preallocate(4096, 65536);
  *bufReturn = result.first;
  *lenReturn = result.second;
}

void FizzServerConnection::readDataAvailable(size_t len) noexcept {
    std::cout << "Server: Reading data of size " << len << std::endl;
    // Commit the bytes that were read into the queue
    readBufQueue_.postallocate(len);
    bytesRead += len;

}

void FizzServerConnection::readEOF() noexcept {
    auto* transport_ = static_cast<fizz::server::AsyncFizzServer*>(transport);
    std::cout << "Client closed connection" << std::endl;
    transport_->closeNow();
}

void FizzServerConnection::readErr(const folly::AsyncSocketException& ex) noexcept {
    errorMessage = ex.what();
    std::cerr << "Got error" << errorMessage << std::endl;
    auto* transport_ = static_cast<fizz::server::AsyncFizzServer*>(transport);
    transport_->closeNow();
}

std::unique_ptr<FizzServerConnection> server_accept_connection(
    const FizzServerContext& ctx,
    int32_t fd) {
    try {
        auto conn = std::make_unique<FizzServerConnection>();

        // Create EventBase for this connection
        conn->evb = std::make_unique<folly::EventBase>();
        conn->fd = fd;
        conn->handshakeComplete = false;
        conn->errorMessage.clear();
        conn->bytesRead = 0;

        // Create AsyncSocket from file descriptor
        // Note: AsyncSocket takes ownership of the FD
        folly::NetworkSocket networkSocket(fd);
        auto socket = folly::AsyncSocket::newSocket(conn->evb.get(), networkSocket);

        // Create AsyncFizzServer with the socket and context
        auto fizzServer = fizz::server::AsyncFizzServer::UniquePtr(
            new fizz::server::AsyncFizzServer(
                std::move(socket),
                ctx.ctx
            )
        );

        // Store transport pointer (cast to void* to avoid header dependency)
        conn->transport = fizzServer.release();

        // Start EventBase thread to process async operations
        // This thread will run the event loop until the connection is closed
        auto evb_ptr = conn->evb.get();
        conn->evb_thread = std::make_unique<std::thread>([evb_ptr]() {
            // Run the EventBase loop forever (until terminateLoopSoon() is called)
            evb_ptr->loopForever();
        });

        return conn;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to accept connection: " + std::string(e.what()));
    }
}

void server_connection_handshake(FizzServerConnection& conn) {
    try {
        if (!conn.transport) {
            throw std::runtime_error("No transport available");
        }
        


        auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);

        // Handshake callback implementation
        class ServerHandshakeCallback : public fizz::server::AsyncFizzServer::HandshakeCallback {
            bool& complete_;
            std::string& error_;
            FizzServerConnection* conn_;

        public:
            ServerHandshakeCallback(bool& complete, std::string& error, FizzServerConnection* conn)
                : complete_(complete), error_(error), conn_(conn){}

            void fizzHandshakeSuccess(fizz::server::AsyncFizzServer* server) noexcept override {
                std::cout << "Server: Handshake complete" << std::endl;
                complete_ = true;
                server->setReadCB(conn_);
            }

            void fizzHandshakeError(
                fizz::server::AsyncFizzServer*,
                folly::exception_wrapper ex) noexcept override {
                std::cout << "Getting an error during handshake" << std::endl;
                error_ = ex.what().toStdString();
            }

            void fizzHandshakeAttemptFallback(fizz::server::AttemptVersionFallback fallback) noexcept override {
                // We don't support version fallback - treat as error
                error_ = "Version fallback attempted";
                complete_ = true;
            }
        };


        auto* callback = new ServerHandshakeCallback(
            conn.handshakeComplete,
            conn.errorMessage,
            &conn
        );

        conn.evb->runInEventBaseThreadAndWait([&]() {
          transport->accept(callback);
        });

        // Wait for handshake to complete (processed by EventBase thread)
        auto startTime = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(5); // 5 second timeout

        while (!conn.handshakeComplete && conn.errorMessage.empty()) {
            // Check timeout
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                throw std::runtime_error("Handshake timed out after 5 seconds");
            }

            // Just sleep - EventBase thread will process the handshake
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // Check for errors
        if (!conn.errorMessage.empty()) {
            throw std::runtime_error("Handshake failed: " + conn.errorMessage);
        }

        if (!conn.handshakeComplete) {
            throw std::runtime_error("Handshake did not complete");
        }

    } catch (const std::exception& e) {
        conn.handshakeComplete = false;
        throw std::runtime_error("Server handshake failed: " + std::string(e.what()));
    }
}

bool server_connection_is_open(const FizzServerConnection& conn) {
    if (!conn.handshakeComplete) {
        return false;
    }

    try {
        auto* transport = static_cast<const fizz::server::AsyncFizzServer*>(conn.transport);
        return transport != nullptr && transport->good();
    } catch (...) {
        return false;
    }
}

void server_connection_close(FizzServerConnection& conn) {
    try {
        if (conn.transport) {
            auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
            if (transport->good()) {
              conn.evb->runInEventBaseThreadAndWait([&]() {
                  transport->close();
              });
            }
        }

        // Stop EventBase thread and join it
        if (conn.evb_thread && conn.evb_thread->joinable()) {
            // Signal EventBase to terminate
            conn.evb->terminateLoopSoon();
            // Wait for thread to finish
            conn.evb_thread->join();
            conn.evb_thread.reset();
        }
    } catch (const std::exception& e) {
        // Log error but don't throw on cleanup
        LOG(WARNING) << "Error closing connection: " << e.what();
    }
}

size_t server_connection_read(
    FizzServerConnection& conn,
    rust::Slice<uint8_t> buf) {
    try {
        if (!conn.handshakeComplete) {
            throw std::runtime_error("Cannot read: handshake not complete");
        }

        if (!conn.transport) {
            throw std::runtime_error("No transport available");
        }


        //No read happened.
        size_t bytesRead_ = conn.bytesRead;
        if (bytesRead_ == 0) {
            return 0;
        }

        std::cout << "Trying to read from IOBufQueue" << std::endl;

        // Split the requested bytes from the queue
        size_t toRead = std::min(bytesRead_, buf.size());
        auto data = conn.readBufQueue_.split(toRead);

        // Copy data from IOBuf chain to Rust buffer
        size_t copied = 0;
        for (const auto& bufNode : *data) {
            size_t toCopy = std::min(bufNode.size(), buf.size() - copied);
            std::memcpy(const_cast<uint8_t*>(buf.data()) + copied, bufNode.data(), toCopy);
            copied += toCopy;
        }

        conn.bytesRead -= toRead;
        std::printf("Server read %zu bytes from queue\n", copied);
        return copied;

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to read: " + std::string(e.what()));
    }
}


size_t server_read_size_hint(FizzServerConnection& conn) {
    return conn.bytesRead;
}

size_t server_connection_write(
    FizzServerConnection& conn,
    rust::Slice<const uint8_t> buf) {
      if (!conn.handshakeComplete) {
          throw std::runtime_error("Cannot write: handshake not complete");
      }

      if (!conn.transport) {
          throw std::runtime_error("No transport available");
      }

      auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
      // // Create IOBuf from the data
      // auto iobuf = folly::IOBuf::copyBuffer(buf.data(), buf.size());
      //
      class WriteCallback : public folly::AsyncTransportWrapper::WriteCallback {
        std::string& ex_string_;
        bool& error_;
        fizz::server::AsyncFizzServer* transport_;

        public:
            WriteCallback(std::string& ex_string, bool& error, fizz::server::AsyncFizzServer* transport): ex_string_(ex_string), error_(error), transport_(transport) {}

            void writeSuccess() noexcept override {
            }

            void writeErr(size_t /*bytesWritten*/, const folly::AsyncSocketException& ex) noexcept override {
                std::cerr << "Write failed" << std::endl;
                ex_string_ = std::string(ex.what());
                error_ = true;
                transport_->closeNow();
            }
      };

      std::string err_str;
      bool error = false;

      auto wr_cb = WriteCallback(err_str, error, transport);

      // std::cout << "Server: Sync Write" << std::endl;
      auto buf_ = folly::IOBuf::copyBuffer(buf.data(), buf.size());
      conn.evb->runInEventBaseThreadAndWait([&]() {
        transport->writeChain(&wr_cb, std::move(buf_));
      });

      if (error) {
        throw std::runtime_error("Write failed" + err_str);
      }
      // std::cout << "Server: Sync Write complete" << std::endl;
      // Return number of bytes written
      return buf.size();
}

// ============================================================================
// Async I/O Operations (Channel-based, zero busy-wait)
// ============================================================================

// void server_connection_handshake_async(
//     FizzServerConnection& conn,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context) {
//
//     // Handshake callback - self-deleting after invocation
//     class AsyncHandshakeCallback : public fizz::server::AsyncFizzServer::HandshakeCallback {
//         rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback_;
//         rust::Box<IoContext> context_;
//
//     public:
//         AsyncHandshakeCallback(
//             rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//             rust::Box<IoContext> context
//         ) : callback_(std::move(callback)), context_(std::move(context)) {}
//
//         void fizzHandshakeSuccess(fizz::server::AsyncFizzServer* /*transport*/) noexcept override {
//             // Success - invoke Rust callback with 0 bytes and empty error
//             callback_(std::move(context_), 0, rust::String(""));
//             //Add read CB here, with the server owning a buffer, and the callback copies data
//             //from the folly-owned buffer into the connection-owned buffer.
//
//             // std::cout << "Async handshake successful!" << std::endl;
//         }
//
//         void fizzHandshakeError(
//             fizz::server::AsyncFizzServer*,
//             folly::exception_wrapper ex) noexcept override {
//             // Error - invoke callback with error message
//             std::string error = ex.what().toStdString();
//             callback_(std::move(context_), 0, rust::String(error));
//             delete this;
//         }
//
//         void fizzHandshakeAttemptFallback(fizz::server::AttemptVersionFallback) noexcept override {
//             callback_(std::move(context_), 0, rust::String("Fallback not supported"));
//             delete this;
//         }
//     };
//
//     // Post callback registration to EventBase thread for thread-safe execution
//     auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
//     auto* cb = new AsyncHandshakeCallback(std::move(callback), std::move(context));
//
//     conn.evb->runInEventBaseThread([transport, cb]() {
//         // Start handshake on EventBase thread - Fizz takes ownership of callback
//         transport->accept(cb);
//     });
// }
//
// void server_connection_read_async(
//     FizzServerConnection& conn,
//     rust::Slice<uint8_t> buf,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context) {
//
//     // Read callback - owns buffer to avoid Rust lifetime issues
//     class AsyncReadCallback : public folly::AsyncTransportWrapper::ReadCallback {
//         FizzServerConnection* conn_;
//         std::vector<uint8_t> owned_buffer_;  // C++-owned buffer
//         rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback_;
//         rust::Box<IoContext> context_;
//         folly::AsyncTransportWrapper* transport_;
//         bool callback_invoked_;
//
//     public:
//         AsyncReadCallback(
//             FizzServerConnection* conn,
//             size_t buffer_size,
//             rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//             rust::Box<IoContext> context,
//             folly::AsyncTransportWrapper* transport
//         ) : conn_(conn), owned_buffer_(buffer_size),
//             callback_(std::move(callback)), context_(std::move(context)),
//             transport_(transport), callback_invoked_(false) {}
//
//         void getReadBuffer(void** bufOut, size_t* lenOut) override {
//             *bufOut = owned_buffer_.data();
//             *lenOut = owned_buffer_.size();
//         }
//
//         void readDataAvailable(size_t len) noexcept override {
//           // std::cout << "Reading server available data" << std::endl;
//             if (!callback_invoked_) {
//                 callback_invoked_ = true;
//
//                 // Store data in connection for Rust to retrieve
//                 {
//                     std::lock_guard<std::mutex> lock(conn_->read_mutex);
//
//                     // std::cout << "Inside conn mutex for read" << std::endl;
//                     conn_->pending_read_data.assign(
//                         owned_buffer_.begin(),
//                         owned_buffer_.begin() + len);
//                 }
//
//                 // Unregister callback before notifying Rust
//                 transport_->setReadCB(nullptr);
//
//                 // Notify Rust that data is ready
//                 callback_(std::move(context_), len, rust::String(""));
//                 delete this;
//             }
//         }
//
//         void readEOF() noexcept override {
//             if (!callback_invoked_) {
//                 callback_invoked_ = true;
//                 transport_->setReadCB(nullptr);
//                 callback_(std::move(context_), 0, rust::String("EOF"));
//                 delete this;
//             }
//         }
//
//         void readErr(const folly::AsyncSocketException& ex) noexcept override {
//             if (!callback_invoked_) {
//                 callback_invoked_ = true;
//                 transport_->setReadCB(nullptr);
//                 callback_(std::move(context_), 0, rust::String(ex.what()));
//                 delete this;
//             }
//         }
//
//         bool isBufferMovable() noexcept override {
//             return false;
//         }
//
//         void readBufferAvailable(std::unique_ptr<folly::IOBuf>) noexcept override {
//             // Not used for non-movable buffers
//         }
//     };
//
//     auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
//     auto* cb = new AsyncReadCallback(
//         &conn, buf.size(),
//         std::move(callback), std::move(context), transport);
//
//     // Post read callback registration to EventBase thread
//     conn.evb->runInEventBaseThread([transport, cb]() {
//         transport->setReadCB(cb);
//     });
// }
//
// void server_connection_copy_read_data(
//     FizzServerConnection& conn,
//     rust::Slice<uint8_t> dest) {
//
//     std::lock_guard<std::mutex> lock(conn.read_mutex);
//
//     if (conn.pending_read_data.empty()) {
//         return;
//     }
//
//     size_t to_copy = std::min(dest.size(), conn.pending_read_data.size());
//     std::memcpy(const_cast<uint8_t*>(dest.data()),
//                 conn.pending_read_data.data(),
//                 to_copy);
//
//     // Clear the pending data after copying
//     conn.pending_read_data.clear();
// }
//
// void server_connection_write_async(
//     FizzServerConnection& conn,
//     rust::Slice<const uint8_t> buf,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context) {
//
//     // Write callback - self-deleting after invocation
//     class AsyncWriteCallback : public folly::AsyncTransportWrapper::WriteCallback {
//         size_t bytes_written_;
//         rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback_;
//         rust::Box<IoContext> context_;
//
//     public:
//         AsyncWriteCallback(
//             size_t bytes,
//             rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//             rust::Box<IoContext> context
//         ) : bytes_written_(bytes),
//             callback_(std::move(callback)), context_(std::move(context)) {}
//
//         void writeSuccess() noexcept override {
//             callback_(std::move(context_), bytes_written_, rust::String(""));
//             delete this;
//         }
//
//         void writeErr(size_t /*bytesWritten*/, const folly::AsyncSocketException& ex) noexcept override {
//             callback_(std::move(context_), 0, rust::String(ex.what()));
//             delete this;
//         }
//     };
//
//     auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
//     auto* cb = new AsyncWriteCallback(buf.size(), std::move(callback), std::move(context));
//
//     // OPTIMIZATION: Use wrapBuffer for zero-copy write
//     // Note: We need to copy the buffer data since it may not remain valid
//     // after this function returns. The Rust side can free it.
//     auto iobuf = folly::IOBuf::copyBuffer(buf.data(), buf.size());
//
//     // Post write operation to EventBase thread
//     conn.evb->runInEventBaseThread([transport, cb, iobuf = std::move(iobuf)]() mutable {
//         transport->writeChain(cb, std::move(iobuf));
//     });
// }
