use crate::client::Client;
use log::{debug, info, warn};
use wacore::StringEnum;
use wacore_binary::builder::NodeBuilder;

/// Presence status for online/offline state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum PresenceStatus {
    #[str = "available"]
    Available,
    #[str = "unavailable"]
    Unavailable,
}

impl From<crate::types::presence::Presence> for PresenceStatus {
    fn from(p: crate::types::presence::Presence) -> Self {
        match p {
            crate::types::presence::Presence::Available => PresenceStatus::Available,
            crate::types::presence::Presence::Unavailable => PresenceStatus::Unavailable,
        }
    }
}

/// Feature handle for presence operations.
pub struct Presence<'a> {
    client: &'a Client,
}

impl<'a> Presence<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Set the presence status.
    pub async fn set(&self, status: PresenceStatus) -> Result<(), anyhow::Error> {
        let device_snapshot = self
            .client
            .persistence_manager()
            .get_device_snapshot()
            .await;

        debug!(
            "send_presence called with push_name: '{}'",
            device_snapshot.push_name
        );

        if device_snapshot.push_name.is_empty() {
            warn!("Cannot send presence: push_name is empty!");
            return Err(anyhow::anyhow!(
                "Cannot send presence without a push name set"
            ));
        }

        let presence_type = status.as_str();

        let node = NodeBuilder::new("presence")
            .attr("type", presence_type)
            .attr("name", &device_snapshot.push_name)
            .build();

        info!(
            "Sending presence stanza: <presence type=\"{}\" name=\"{}\"/>",
            presence_type,
            node.attrs.get("name").map_or("", |s| s.as_str())
        );

        self.client.send_node(node).await.map_err(|e| e.into())
    }

    /// Set presence to available (online).
    pub async fn set_available(&self) -> Result<(), anyhow::Error> {
        self.set(PresenceStatus::Available).await
    }

    /// Set presence to unavailable (offline).
    pub async fn set_unavailable(&self) -> Result<(), anyhow::Error> {
        self.set(PresenceStatus::Unavailable).await
    }
}

impl Client {
    /// Access presence operations.
    #[allow(clippy::wrong_self_convention)]
    pub fn presence(&self) -> Presence<'_> {
        Presence::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bot::Bot;
    use crate::http::{HttpClient, HttpRequest, HttpResponse};
    use crate::store::SqliteStore;
    use crate::store::commands::DeviceCommand;
    use anyhow::Result;
    use std::sync::Arc;
    use wacore::store::traits::Backend;
    use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;

    // Mock HTTP client for testing
    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl HttpClient for MockHttpClient {
        async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse> {
            Ok(HttpResponse {
                status_code: 200,
                body: br#"self.__swData=JSON.parse(/*BTDS*/"{\"dynamic_data\":{\"SiteData\":{\"server_revision\":1026131876,\"client_revision\":1026131876}}}");"#.to_vec(),
            })
        }
    }

    async fn create_test_backend() -> Arc<dyn Backend> {
        let temp_db = format!(
            "file:memdb_presence_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        Arc::new(
            SqliteStore::new(&temp_db)
                .await
                .expect("Failed to create test SqliteStore"),
        ) as Arc<dyn Backend>
    }

    /// Integration test: Presence returns error when pushname is empty
    ///
    /// This verifies the WhatsApp Web behavior where presence is deferred
    /// until pushname is available (either from storage or app state sync).
    #[tokio::test]
    async fn test_presence_rejected_when_pushname_empty() {
        // Create a bot with an empty device (no pushname set)
        let backend = create_test_backend().await;
        let transport = TokioWebSocketTransportFactory::new();

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(MockHttpClient)
            .build()
            .await
            .expect("Failed to build bot");

        let client = bot.client();

        // Verify pushname is empty initially
        let snapshot = client.persistence_manager().get_device_snapshot().await;
        assert!(
            snapshot.push_name.is_empty(),
            "Pushname should be empty on fresh device"
        );

        // Attempt to set presence - should fail with empty pushname
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;

        assert!(
            result.is_err(),
            "Presence should fail when pushname is empty"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Cannot send presence without a push name set"),
            "Error message should indicate missing pushname: {}",
            err_msg
        );
    }

    /// Integration test: Presence succeeds after pushname is set
    ///
    /// This simulates the flow where pushname arrives from app state sync
    /// (setting_pushName mutation) and presence can then be sent.
    #[tokio::test]
    async fn test_presence_succeeds_after_pushname_set() {
        let backend = create_test_backend().await;
        let transport = TokioWebSocketTransportFactory::new();

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(MockHttpClient)
            .build()
            .await
            .expect("Failed to build bot");

        let client = bot.client();

        // Set pushname via DeviceCommand (simulates receiving setting_pushName from app state sync)
        client
            .persistence_manager()
            .process_command(DeviceCommand::SetPushName("Test User".to_string()))
            .await;

        // Verify pushname was set
        let snapshot = client.persistence_manager().get_device_snapshot().await;
        assert_eq!(snapshot.push_name, "Test User");

        // Now presence would succeed (but fails at send_node since we're not connected)
        // The validation passes, so we check the error is about connection, not pushname
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;

        // The error should be about not being connected, not about missing pushname
        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("Cannot send presence without a push name set"),
                "Should not fail due to missing pushname after it was set: {}",
                err_msg
            );
            // Expected: connection-related error since we're not actually connected
            assert!(
                err_msg.contains("not connected") || err_msg.contains("NotConnected"),
                "Expected connection error, got: {}",
                err_msg
            );
        }
        // If somehow it succeeds (unlikely without connection), that's also fine
    }

    /// Integration test: Verify pushname flow matches WhatsApp Web
    ///
    /// WhatsApp Web flow (WAWebPushNameSync.js):
    /// 1. Fresh pairing: pushname is empty
    /// 2. App state sync sends setting_pushName mutation
    /// 3. Presence is sent immediately after receiving pushname
    #[tokio::test]
    async fn test_pushname_presence_flow_matches_whatsapp_web() {
        let backend = create_test_backend().await;
        let transport = TokioWebSocketTransportFactory::new();

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(MockHttpClient)
            .build()
            .await
            .expect("Failed to build bot");

        let client = bot.client();

        // Step 1: Fresh device has empty pushname
        let snapshot = client.persistence_manager().get_device_snapshot().await;
        assert!(
            snapshot.push_name.is_empty(),
            "Fresh device should have empty pushname"
        );

        // Step 2: Presence fails with empty pushname (matches WhatsApp Web deferring presence)
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;
        assert!(
            result.is_err(),
            "Presence should be deferred when pushname is empty"
        );

        // Step 3: Pushname arrives (simulates setting_pushName from app state sync)
        client
            .persistence_manager()
            .process_command(DeviceCommand::SetPushName("WhatsApp User".to_string()))
            .await;

        // Step 4: Now presence validation passes (actual send fails due to no connection)
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;

        // Should NOT be a pushname error
        if let Err(e) = result {
            assert!(
                !e.to_string().contains("push name"),
                "After setting pushname, error should be connection-related, not pushname: {}",
                e
            );
        }
    }
}
