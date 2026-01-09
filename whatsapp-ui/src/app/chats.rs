//! Chat list management types

use std::sync::Arc;

use crate::state::Chat;

/// Cached data for chat list rendering to avoid recomputing on every frame.
/// Item sizes are computed at render time based on ResponsiveLayout.
#[derive(Clone)]
pub struct ChatListCache {
    /// Chat count when cache was created (invalidation check)
    pub chat_count: usize,
    /// Shared chats reference (filtered if search is active)
    pub chats: Arc<[Chat]>,
}
