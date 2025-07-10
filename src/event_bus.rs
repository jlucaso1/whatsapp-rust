use crate::types::events::Event; // Assuming Event type is defined here
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

// Copied from client.rs, assuming it's the same
pub type EventHandler = Box<dyn Fn(Arc<Event>) + Send + Sync>;
pub(crate) struct WrappedHandler {
    pub(crate) id: usize,
    handler: EventHandler,
}
static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1);

pub struct EventBus {
    pub(crate) handlers: RwLock<Vec<WrappedHandler>>,
    next_handler_id: AtomicUsize, // Moved static NEXT_HANDLER_ID here
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(Vec::new()),
            next_handler_id: AtomicUsize::new(1), // Initialize here
        }
    }

    pub async fn add_handler(&self, handler: EventHandler) -> usize {
        let id = self.next_handler_id.fetch_add(1, Ordering::Relaxed);
        let wrapped = WrappedHandler { id, handler };
        self.handlers.write().await.push(wrapped);
        id
    }

    pub async fn remove_handler(&self, id: usize) -> bool {
        let mut handlers = self.handlers.write().await;
        let initial_len = handlers.len();
        handlers.retain(|h| h.id != id);
        handlers.len() < initial_len
    }

    pub async fn dispatch(&self, event: Arc<Event>) {
        // Takes Arc<Event>
        let handlers_guard = self.handlers.read().await;
        for wrapped_handler in handlers_guard.iter() {
            (wrapped_handler.handler)(event.clone());
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// Moved from client.rs, ensure it's defined once, preferably here.
// pub type EventHandler = Box<dyn Fn(Arc<Event>) + Send + Sync>;
// pub(crate) struct WrappedHandler {
//    pub(crate) id: usize,
//    handler: EventHandler,
// }
// static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1); // Moved into EventBus struct
