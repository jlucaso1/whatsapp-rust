//! WhatsApp client wrapper
//!
//! This module handles all communication with the WhatsApp service,
//! keeping the async/network logic separate from the UI.

mod media_callback;
mod whatsapp;

pub use whatsapp::WhatsAppClient;
