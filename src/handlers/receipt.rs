use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use std::sync::Arc;

/// Handler for `<receipt>` stanzas.
///
/// Processes delivery and read receipts for sent messages, including:
/// - Message delivery confirmations
/// - Read receipts
/// - Played receipts (for voice messages and media)
#[derive(Default)]
pub struct ReceiptHandler;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StanzaHandler for ReceiptHandler {
    fn tag(&self) -> &'static str {
        "receipt"
    }

    async fn handle(
        &self,
        client: Arc<Client>,
        node: Arc<wacore_binary::OwnedNodeRef>,
        _cancelled: &mut bool,
    ) -> bool {
        client.handle_receipt(node).await;
        true
    }
}
