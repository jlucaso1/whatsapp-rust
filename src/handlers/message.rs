use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::warn;
use std::sync::Arc;
use tokio::sync::mpsc;
use wacore_binary::node::Node;

/// Handler for `<message>` stanzas.
///
/// Processes incoming WhatsApp messages, including:
/// - Text messages
/// - Media messages (images, videos, documents, etc.)
/// - System messages
/// - Group messages
///
/// Messages are processed sequentially per-chat using a mailbox pattern to prevent
/// race conditions where a later message could be processed before the PreKey
/// message that establishes the Signal session.
#[derive(Default)]
pub struct MessageHandler;

#[async_trait]
impl StanzaHandler for MessageHandler {
    fn tag(&self) -> &'static str {
        "message"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        // Extract the chat ID to serialize processing for this chat.
        // This prevents race conditions where a later message is processed before
        // the PreKey message that establishes the session.
        let chat_id = match node.attrs().optional_jid("from") {
            Some(jid) => jid.to_string(),
            None => {
                warn!("Message stanza missing required 'from' attribute");
                return false;
            }
        };

        // CRITICAL: Acquire the enqueue lock BEFORE getting/creating the queue.
        // This ensures that messages are enqueued in the exact order they arrive,
        // even when multiple messages arrive concurrently and the queue needs
        // to be created for the first time.
        //
        // The key insight is that get_with (for the lock) establishes ordering
        // based on who calls it first, and then the mutex.lock() preserves that
        // ordering since we hold the lock for the entire enqueue operation.
        let enqueue_mutex = client
            .message_enqueue_locks
            .get_with_by_ref(&chat_id, async { Arc::new(tokio::sync::Mutex::new(())) })
            .await;

        // Acquire the lock - this serializes all enqueue operations for this chat
        let _enqueue_guard = enqueue_mutex.lock().await;

        // Now get or create the worker queue for this chat
        let tx = client
            .message_queues
            .get_with_by_ref(&chat_id, async {
                // Create a channel with backpressure
                // Increased capacity to handle high message rates without blocking
                let (tx, mut rx) = mpsc::channel::<Arc<Node>>(10000);

                let client_for_worker = client.clone();

                // Clone these for cleanup when the worker exits
                let chat_id_for_cleanup = chat_id.clone();
                let queues_for_cleanup = client.message_queues.clone();

                // Spawn a worker task that processes messages sequentially for this chat
                tokio::spawn(async move {
                    while let Some(msg_node) = rx.recv().await {
                        let client = client_for_worker.clone();
                        Box::pin(client.handle_incoming_message(msg_node)).await;
                    }
                    // Clean up when channel closes to prevent memory leaks
                    queues_for_cleanup.invalidate(&chat_id_for_cleanup).await;
                });

                tx
            })
            .await;

        // Send the message to the queue - just clones the Arc, not the Node!
        if let Err(e) = tx.send(node).await {
            warn!("Failed to enqueue message for processing: {e}");
        }

        // Lock is released here when _enqueue_guard is dropped

        true
    }
}
