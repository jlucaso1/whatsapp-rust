use crate::client::Client;
use log::{debug, info, warn};
use wacore_binary::builder::NodeBuilder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceStatus {
    Available,
    Unavailable,
}

impl PresenceStatus {
    fn as_str(&self) -> &'static str {
        match self {
            PresenceStatus::Available => "available",
            PresenceStatus::Unavailable => "unavailable",
        }
    }
}

impl std::fmt::Display for PresenceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<crate::types::presence::Presence> for PresenceStatus {
    fn from(p: crate::types::presence::Presence) -> Self {
        match p {
            crate::types::presence::Presence::Available => PresenceStatus::Available,
            crate::types::presence::Presence::Unavailable => PresenceStatus::Unavailable,
        }
    }
}

pub struct Presence<'a> {
    client: &'a Client,
}

impl<'a> Presence<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

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

    pub async fn set_available(&self) -> Result<(), anyhow::Error> {
        self.set(PresenceStatus::Available).await
    }

    pub async fn set_unavailable(&self) -> Result<(), anyhow::Error> {
        self.set(PresenceStatus::Unavailable).await
    }
}

impl Client {
    #[allow(clippy::wrong_self_convention)]
    pub fn presence(&self) -> Presence<'_> {
        Presence::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presence_status_display() {
        assert_eq!(PresenceStatus::Available.to_string(), "available");
        assert_eq!(PresenceStatus::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn test_presence_status_as_str() {
        assert_eq!(PresenceStatus::Available.as_str(), "available");
        assert_eq!(PresenceStatus::Unavailable.as_str(), "unavailable");
    }
}
