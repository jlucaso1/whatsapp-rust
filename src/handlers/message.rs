use super::traits::StanzaHandler;
use crate::client::{ChatLane, Client};
use async_trait::async_trait;
use log::warn;
use std::sync::Arc;

/// WA Web: `WAWebMessageQueue` uses `promiseTimeout(r(), 2e4)` per queued handler.
const MAX_MESSAGE_DELAY_MS: u64 = 20_000;

/// Handler for `<message>` stanzas.
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
        let chat_jid = match node.attrs().optional_jid("from") {
            Some(jid) => jid,
            None => {
                warn!("Message stanza missing required 'from' attribute");
                return false;
            }
        };

        // Single cache lookup: get or create the lane (lock + queue + worker).
        let lane = client
            .chat_lanes
            .get_with_by_ref(&chat_jid, async {
                let (tx, rx) = async_channel::unbounded::<Arc<wacore_binary::OwnedNodeRef>>();

                let client_for_worker = client.clone();
                let spawn_generation = client
                    .connection_generation
                    .load(std::sync::atomic::Ordering::Acquire);

                client
                    .runtime
                    .spawn(Box::pin(async move {
                        while let Ok(msg_node) = rx.recv().await {
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
                            let elapsed =
                                (wacore::time::now_millis() as u64).saturating_sub(start);
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

                ChatLane {
                    enqueue_lock: Arc::new(async_lock::Mutex::new(())),
                    queue_tx: tx,
                }
            })
            .await;

        // Lock serializes enqueue order for this chat
        let _guard = lane.enqueue_lock.lock().await;

        if let Err(e) = lane.queue_tx.try_send(node) {
            warn!("Failed to enqueue message for processing: {e}");
        }

        true
    }
}
