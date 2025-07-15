// Re-export core modules for compatibility
pub use wacore::{binary, crypto, proto_helpers, signal, store::traits};

// Core types are re-exported, but events (with EventBus) remain here for platform-specific functionality
pub mod types {
    pub use wacore::types::*;
    pub mod events;
}

// Platform-specific modules remain here
pub mod appstate;
pub mod appstate_sync;
pub mod client;
pub mod download;
pub mod error;
pub mod handlers;
pub mod handshake;
pub mod keepalive;
pub mod mediaconn;
pub mod message;
pub mod pair;
pub mod qrcode;
pub mod request;
pub mod send;
pub mod socket;
pub mod store;

// New modules
pub mod prekeys;
pub mod receipt;
pub mod retry;
