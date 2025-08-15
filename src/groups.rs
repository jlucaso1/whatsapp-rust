use crate::client::Client;
use wacore::client::context::GroupInfo;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

impl Client {
    pub async fn query_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        if let Some(cached) = self.group_cache.get(jid) {
            return Ok(cached.value().clone());
        }

        if self.test_mode.load(std::sync::atomic::Ordering::Relaxed) {
            let info = GroupInfo {
                participants: vec!["559984726662@s.whatsapp.net".parse()?],
                addressing_mode: crate::types::message::AddressingMode::Pn,
            };
            self.group_cache.insert(jid.clone(), info.clone());
            return Ok(info);
        }

        use wacore_binary::node::NodeContent;
        let query_node = NodeBuilder::new("query")
            .attr("request", "interactive")
            .build();
        let iq = crate::request::InfoQuery {
            namespace: "w:g2",
            query_type: crate::request::InfoQueryType::Get,
            to: jid.clone(),
            content: Some(NodeContent::Nodes(vec![query_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let group_node = resp_node
            .get_optional_child("group")
            .ok_or_else(|| anyhow::anyhow!("<group> not found in group info response"))?;

        let mut participants = Vec::new();
        let addressing_mode_str = group_node
            .attrs()
            .optional_string("addressing_mode")
            .unwrap_or("pn");
        let addressing_mode = match addressing_mode_str {
            "lid" => crate::types::message::AddressingMode::Lid,
            _ => crate::types::message::AddressingMode::Pn,
        };

        for participant_node in group_node.get_children_by_tag("participant") {
            participants.push(participant_node.attrs().jid("jid"));
        }

        let info = GroupInfo {
            participants,
            addressing_mode,
        };
        self.group_cache.insert(jid.clone(), info.clone());

        Ok(info)
    }
}
