use crate::client::Client;
use wacore::client::context::GroupInfo;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

impl Client {
    pub async fn query_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        if let Some(cached) = self.group_cache.get(jid) {
            return Ok(cached.value().clone());
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
        let mut lid_to_pn_map = std::collections::HashMap::new();

        let addressing_mode_str = group_node
            .attrs()
            .optional_string("addressing_mode")
            .unwrap_or("pn");
        let addressing_mode = match addressing_mode_str {
            "lid" => crate::types::message::AddressingMode::Lid,
            _ => crate::types::message::AddressingMode::Pn,
        };

        for participant_node in group_node.get_children_by_tag("participant") {
            let participant_jid = participant_node.attrs().jid("jid");
            participants.push(participant_jid.clone());

            // If this is a LID group, extract the phone_number mapping
            if addressing_mode == crate::types::message::AddressingMode::Lid
                && let Some(phone_number) = participant_node.attrs().optional_jid("phone_number")
            {
                // Store mapping: LID user -> phone number JID (for device queries)
                lid_to_pn_map.insert(participant_jid.user.clone(), phone_number);
            }
        }

        let mut info = GroupInfo::new(participants, addressing_mode);
        if !lid_to_pn_map.is_empty() {
            info.set_lid_to_pn_map(lid_to_pn_map);
        }
        self.group_cache.insert(jid.clone(), info.clone());

        Ok(info)
    }
}
