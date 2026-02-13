use crate::client::Client;
use log::{debug, warn};
use wacore::StringEnum;
use wacore::iq::tctoken::build_tc_token_node;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

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

        if status == PresenceStatus::Available {
            self.client.send_unified_session().await;
        }

        let presence_type = status.as_str();

        let node = NodeBuilder::new("presence")
            .attr("type", presence_type)
            .attr("name", &device_snapshot.push_name)
            .build();

        debug!(
            "Sending presence stanza: <presence type=\"{}\" name=\"{}\"/>",
            presence_type,
            node.attrs
                .get("name")
                .and_then(|s| s.as_str())
                .unwrap_or("")
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

    /// Subscribe to a contact's presence updates.
    ///
    /// Sends a `<presence type="subscribe">` stanza to the target JID.
    /// If a valid tctoken exists for the contact, it is included as a child node.
    ///
    /// ## Wire Format
    /// ```xml
    /// <presence type="subscribe" to="user@s.whatsapp.net">
    ///   <tctoken><!-- raw token bytes --></tctoken>
    /// </presence>
    /// ```
    pub async fn subscribe(&self, jid: &Jid) -> Result<(), anyhow::Error> {
        debug!("presence subscribe: subscribing to {}", jid);

        let mut builder = NodeBuilder::new("presence")
            .attr("type", "subscribe")
            .attr("to", jid.to_string());

        // Include tctoken if available (no t attribute, matching WhatsApp Web)
        if let Some(token) = self.client.lookup_tc_token_for_jid(jid).await {
            builder = builder.children([build_tc_token_node(&token)]);
        }

        let node = builder.build();
        self.client.send_node(node).await.map_err(|e| e.into())
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

    /// Verifies WhatsApp Web behavior: presence deferred until pushname available.
    #[tokio::test]
    async fn test_presence_rejected_when_pushname_empty() {
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

        let snapshot = client.persistence_manager().get_device_snapshot().await;
        assert!(
            snapshot.push_name.is_empty(),
            "Pushname should be empty on fresh device"
        );

        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;

        assert!(
            result.is_err(),
            "Presence should fail when pushname is empty"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cannot send presence without a push name set"),
            "Error should indicate missing pushname"
        );
    }

    /// Simulates pushname arriving from app state sync (setting_pushName mutation).
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

        client
            .persistence_manager()
            .process_command(DeviceCommand::SetPushName("Test User".to_string()))
            .await;

        let snapshot = client.persistence_manager().get_device_snapshot().await;
        assert_eq!(snapshot.push_name, "Test User");

        // Validation passes; error should be connection-related, not pushname
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;

        if let Err(e) = result {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("push name"),
                "Should not fail due to pushname: {}",
                err_msg
            );
            assert!(
                err_msg.contains("not connected") || err_msg.contains("NotConnected"),
                "Expected connection error, got: {}",
                err_msg
            );
        }
    }

    /// Matches WAWebPushNameSync.js: fresh pairing -> app state sync -> presence.
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

        // Fresh device has empty pushname
        let snapshot = client.persistence_manager().get_device_snapshot().await;
        assert!(snapshot.push_name.is_empty());

        // Presence deferred when pushname empty
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;
        assert!(result.is_err());

        // Pushname arrives via app state sync
        client
            .persistence_manager()
            .process_command(DeviceCommand::SetPushName("WhatsApp User".to_string()))
            .await;

        // Now presence validation passes
        let result: Result<(), anyhow::Error> =
            client.presence().set(PresenceStatus::Available).await;

        if let Err(e) = result {
            assert!(
                !e.to_string().contains("push name"),
                "Error should be connection-related: {}",
                e
            );
        }
    }
}
