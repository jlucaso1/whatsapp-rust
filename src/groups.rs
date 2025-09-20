use crate::client::Client;
use wacore::client::context::GroupInfo;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::jid::JidExt as _;

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

        // Opportunistically persist PN<->LID mappings from participant attributes
        let mut pairs: Vec<(Jid, Jid)> = Vec::new();
        for participant_node in group_node.get_children_by_tag("participant") {
            let mut attrs = participant_node.attrs();
            let jid = attrs.jid("jid");
            let lid = attrs.optional_jid("lid");
            let pn = attrs.optional_jid("phone_number");
            if jid.server() == wacore_binary::jid::DEFAULT_USER_SERVER {
                if let Some(l) = lid.clone() {
                    pairs.push((l, jid.clone()));
                }
                if let Some(p) = pn.clone() {
                    // jid already PN; if both present and consistent, ignore
                    let _ = p;
                }
            } else if jid.server() == wacore_binary::jid::HIDDEN_USER_SERVER {
                if let Some(p) = pn.clone() {
                    pairs.push((jid.clone(), p));
                }
                if let Some(l) = lid.clone() {
                    // jid already LID; if both present and consistent, ignore
                    let _ = l;
                }
            }
        }
        for (lid, pn) in pairs {
            self.store_lid_pn_mapping(lid, pn).await;
        }

        Ok(info)
    }
}
