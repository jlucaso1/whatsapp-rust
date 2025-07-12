// Re-export core appstate modules
pub use whatsapp_core::appstate::{errors, hash, keys, lthash};

// Platform-specific processor wrapper  
pub mod processor;
