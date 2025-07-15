// Re-export core appstate modules
pub use wacore::appstate::{errors, hash, keys, lthash};

// Platform-specific processor wrapper
pub mod processor;
