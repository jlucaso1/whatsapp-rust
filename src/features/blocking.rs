use crate::client::Client;
use crate::jid_utils::server_jid;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use anyhow::Result;
use log::debug;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::NodeContent;

#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub jid: Jid,
    pub timestamp: Option<u64>,
}

pub struct Blocking<'a> {
    client: &'a Client,
}

impl<'a> Blocking<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn block(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Blocking contact: {}", jid);
        self.update_blocklist(jid, "block").await
    }

    pub async fn unblock(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Unblocking contact: {}", jid);
        self.update_blocklist(jid, "unblock").await
    }

    pub async fn get_blocklist(&self) -> Result<Vec<BlocklistEntry>> {
        debug!(target: "Blocking", "Fetching blocklist...");

        let iq = InfoQuery {
            namespace: "blocklist",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: None,
            timeout: None,
        };

        let response = self.client.send_iq(iq).await?;
        self.parse_blocklist_response(&response)
    }

    async fn update_blocklist(&self, jid: &Jid, action: &str) -> Result<(), IqError> {
        let item_node = NodeBuilder::new("item")
            .attr("action", action)
            .attr("jid", jid.to_string())
            .build();

        let iq = InfoQuery {
            namespace: "blocklist",
            query_type: InfoQueryType::Set,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![item_node])),
            timeout: None,
        };

        self.client.send_iq(iq).await?;
        debug!(target: "Blocking", "Successfully {}ed contact: {}", action, jid);
        Ok(())
    }

    fn parse_blocklist_response(
        &self,
        node: &wacore_binary::node::Node,
    ) -> Result<Vec<BlocklistEntry>> {
        let mut entries = Vec::new();

        let items = if let Some(list) = node.get_optional_child("list") {
            list.get_children_by_tag("item")
        } else {
            node.get_children_by_tag("item")
        };

        for item in items {
            if let Some(jid_str) = item.attrs().optional_string("jid")
                && let Ok(jid) = jid_str.parse::<Jid>()
            {
                let timestamp = item.attrs().optional_u64("t");
                entries.push(BlocklistEntry { jid, timestamp });
            }
        }

        debug!(target: "Blocking", "Parsed {} blocked contacts", entries.len());
        Ok(entries)
    }

    pub async fn is_blocked(&self, jid: &Jid) -> Result<bool> {
        let blocklist = self.get_blocklist().await?;
        Ok(blocklist.iter().any(|e| e.jid.user == jid.user))
    }
}

impl Client {
    pub fn blocking(&self) -> Blocking<'_> {
        Blocking::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocklist_entry() {
        let jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let entry = BlocklistEntry {
            jid: jid.clone(),
            timestamp: Some(1234567890),
        };

        assert_eq!(entry.jid.user, "1234567890");
        assert_eq!(entry.timestamp, Some(1234567890));
    }
}
