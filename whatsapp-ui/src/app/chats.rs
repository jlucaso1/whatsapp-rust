//! Chat list management types
//!
//! This module contains types related to chat list management.
//! The actual chat list logic is in WhatsAppApp for now, but these types
//! are extracted here as a first step toward a more modular architecture.

use std::rc::Rc;
use std::sync::Arc;

use gpui::{Pixels, Size};

use crate::state::Chat;

/// Cached data for chat list rendering to avoid recomputing on every frame.
#[derive(Clone)]
pub struct ChatListCache {
    /// Chat count when cache was created (invalidation check)
    pub chat_count: usize,
    /// Pre-computed item sizes for virtual list
    pub item_sizes: Rc<Vec<Size<Pixels>>>,
    /// Shared chats reference (filtered if search is active)
    pub chats: Arc<[Chat]>,
}
