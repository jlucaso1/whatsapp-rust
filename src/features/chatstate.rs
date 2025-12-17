use crate::client::Client;
use log::debug;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatStateType {
    Composing,

    Recording,

    Paused,
}

impl ChatStateType {
    fn as_str(&self) -> &'static str {
        match self {
            ChatStateType::Composing => "composing",
            ChatStateType::Recording => "recording",
            ChatStateType::Paused => "paused",
        }
    }
}

impl std::fmt::Display for ChatStateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub struct Chatstate<'a> {
    client: &'a Client,
}

impl<'a> Chatstate<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

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
    pub fn chatstate(&self) -> Chatstate<'_> {
        Chatstate::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_state_type_display() {
        assert_eq!(ChatStateType::Composing.to_string(), "composing");
        assert_eq!(ChatStateType::Recording.to_string(), "recording");
        assert_eq!(ChatStateType::Paused.to_string(), "paused");
    }

    #[test]
    fn test_chat_state_type_as_str() {
        assert_eq!(ChatStateType::Composing.as_str(), "composing");
        assert_eq!(ChatStateType::Recording.as_str(), "recording");
        assert_eq!(ChatStateType::Paused.as_str(), "paused");
    }
}
