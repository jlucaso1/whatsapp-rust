//! Chat state (typing indicators) feature.

use crate::client::Client;
use log::debug;
use wacore::StringEnum;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

/// Chat state type for typing indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum ChatStateType {
    #[str = "composing"]
    Composing,
    #[str = "recording"]
    Recording,
    #[str = "paused"]
    Paused,
}

/// Feature handle for chat state operations.
pub struct Chatstate<'a> {
    client: &'a Client,
}

impl<'a> Chatstate<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Send a chat state update to a recipient.
    pub async fn send(
        &self,
        to: &Jid,
        state: ChatStateType,
    ) -> Result<(), crate::client::ClientError> {
        debug!(target: "Chatstate", "Sending {} to {}", state, to);

        let node = self.build_chatstate_node(to, state);
        self.client.send_node(node).await
    }

    pub async fn send_composing(&self, to: &Jid) -> Result<(), crate::client::ClientError> {
        self.send(to, ChatStateType::Composing).await
    }

    pub async fn send_recording(&self, to: &Jid) -> Result<(), crate::client::ClientError> {
        self.send(to, ChatStateType::Recording).await
    }

    pub async fn send_paused(&self, to: &Jid) -> Result<(), crate::client::ClientError> {
        self.send(to, ChatStateType::Paused).await
    }

    fn build_chatstate_node(&self, to: &Jid, state: ChatStateType) -> wacore_binary::node::Node {
        let child = match state {
            ChatStateType::Composing => NodeBuilder::new("composing").build(),
            ChatStateType::Recording => {
                NodeBuilder::new("composing").attr("media", "audio").build()
            }
            ChatStateType::Paused => NodeBuilder::new("paused").build(),
        };

        NodeBuilder::new("chatstate")
            .attr("to", to.to_string())
            .children([child])
            .build()
    }
}

impl Client {
    /// Access chat state operations.
    pub fn chatstate(&self) -> Chatstate<'_> {
        Chatstate::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_state_type_string_enum() {
        assert_eq!(ChatStateType::Composing.as_str(), "composing");
        assert_eq!(ChatStateType::Recording.to_string(), "recording");
        assert_eq!(
            ChatStateType::try_from("paused").unwrap(),
            ChatStateType::Paused
        );
    }
}
