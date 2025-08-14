use crate::client::Client;
use crate::types::presence::Presence;
use log::{debug, info, warn};
use wacore::binary::builder::NodeBuilder;

impl Client {
    pub async fn send_presence(&self, presence: Presence) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        debug!(
            "🔍 send_presence called with push_name: '{}'",
            device_snapshot.push_name
        );
        if device_snapshot.push_name.is_empty() {
            warn!("❌ Cannot send presence: push_name is empty!");
            return Err(anyhow::anyhow!(
                "Cannot send presence without a push name set"
            ));
        }
        let presence_type = match presence {
            Presence::Available => "available",
            Presence::Unavailable => "unavailable",
        };
        let node = NodeBuilder::new("presence")
            .attr("type", presence_type)
            .attr("name", device_snapshot.push_name.clone())
            .build();
        info!(
            "📡 Sending presence stanza: <presence type=\"{}\" name=\"{}\"/>",
            presence_type,
            node.attrs.get("name").unwrap_or(&"".to_string())
        );
        self.send_node(node).await.map_err(|e| e.into())
    }
}
