use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::warn;
use std::sync::Arc;

/// WA Web: `WAWebMessageQueue` uses `promiseTimeout(r(), 2e4)` per queued handler.
const MAX_MESSAGE_DELAY_MS: u64 = 20_000;

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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StanzaHandler for MessageHandler {
    fn tag(&self) -> &'static str {
        "message"
    }

    async fn handle(
        &self,
        client: Arc<Client>,
        node: Arc<wacore_binary::OwnedNodeRef>,
        _cancelled: &mut bool,
    ) -> bool {
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
            .get_with_by_ref(&chat_id, async { Arc::new(async_lock::Mutex::new(())) })
            .await;

        // Acquire the lock - this serializes all enqueue operations for this chat
        let _enqueue_guard = enqueue_mutex.lock().await;

        // Now get or create the worker queue for this chat
        let tx = client
            .message_queues
            .get_with_by_ref(&chat_id, async {
                // Unbounded so the read loop never blocks on a full channel.
                // WA Web uses unbounded promise chains for the same reason.
                let (tx, rx) = async_channel::unbounded::<Arc<wacore_binary::OwnedNodeRef>>();

                let client_for_worker = client.clone();
                let spawn_generation = client
                    .connection_generation
                    .load(std::sync::atomic::Ordering::Acquire);

                // Spawn a worker task that processes messages sequentially for this chat.
                // The worker exits when all tx senders are dropped (cache TTI expiry drops
                // the cached tx, and any cloned tx's are short-lived). No explicit
                // invalidate() here — that would race with new queue entries under the
                // same key (see bug audit #27).
                client
                    .runtime
                    .spawn(Box::pin(async move {
                        while let Ok(msg_node) = rx.recv().await {
                            // Exit if the connection changed — prevents stale workers
                            // from processing messages with outdated crypto state.
                            if client_for_worker
                                .connection_generation
                                .load(std::sync::atomic::Ordering::Acquire)
                                != spawn_generation
                            {
                                log::debug!(target: "MessageQueue", "Stale worker exiting; remaining messages will be redelivered by server");
                                break;
                            }
                            let start = wacore::time::now_millis() as u64;
                            let client = client_for_worker.clone();
                            Box::pin(client.handle_incoming_message(msg_node)).await;
                            let elapsed = (wacore::time::now_millis() as u64).saturating_sub(start);
                            if elapsed > MAX_MESSAGE_DELAY_MS {
                                warn!(
                                    target: "MessageQueue",
                                    "Message processing took {:.1}s (MAX_MESSAGE_DELAY is {}s)",
                                    elapsed as f64 / 1000.0,
                                    MAX_MESSAGE_DELAY_MS / 1000
                                );
                            }
                        }
                    }))
                    .detach();

                tx
            })
            .await;

        // Synchronous enqueue — try_send on unbounded never fails due to capacity.
        if let Err(e) = tx.try_send(node) {
            warn!("Failed to enqueue message for processing: {e}");
        }

        // Lock is released here when _enqueue_guard is dropped

        true
    }
}
