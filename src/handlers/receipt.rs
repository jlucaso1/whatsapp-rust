use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Handler for `<receipt>` stanzas.
///
/// Processes delivery and read receipts for sent messages, including:
/// - Message delivery confirmations
/// - Read receipts
/// - Played receipts (for voice messages and media)
#[derive(Default)]
pub struct ReceiptHandler;

#[async_trait]
impl StanzaHandler for ReceiptHandler {
    fn tag(&self) -> &'static str {
        "receipt"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_receipt(node).await;
        true
    }
}
