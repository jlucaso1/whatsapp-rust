//! Message handling module for WhatsApp messages.
//!
//! This module contains the core message handling logic including:
//! - Encrypted message decryption (Signal protocol)
//! - Sender key distribution message processing
//! - Message parsing and routing
//! - Retry logic for failed decryptions
//!
//! The module is split into focused submodules:
//! - `decrypt`: Message decryption handlers for session and group messages
//! - `parsing`: Message info parsing from incoming nodes
//! - `retry`: Retry receipt handling for failed decryptions
//! - `sender_key`: Sender key distribution message processing

mod decrypt;
mod parsing;
mod retry;
mod sender_key;

// Re-export commonly used items at the module level for convenience
pub use wacore::types::message::{HIGH_RETRY_COUNT_THRESHOLD, MAX_DECRYPT_RETRIES, RetryReason};

#[cfg(test)]
mod tests;
