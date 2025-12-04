use crate::client::Client;
use std::collections::HashMap;
use wacore::client::context::GroupInfo;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

#[derive(Debug, Clone)]
pub struct GroupMetadata {
    pub id: Jid,
    pub subject: String,
    pub participants: Vec<GroupParticipant>,
    pub addressing_mode: crate::types::message::AddressingMode,
}

#[derive(Debug, Clone)]
pub struct GroupParticipant {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
    pub is_admin: bool,
}

impl Client {
    pub async fn query_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        if let Some(cached) = self.get_group_cache().await.get(jid).await {
            return Ok(cached);
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

            if addressing_mode == crate::types::message::AddressingMode::Lid
                && let Some(phone_number) = participant_node.attrs().optional_jid("phone_number")
            {
                lid_to_pn_map.insert(participant_jid.user.clone(), phone_number);
            }
        }

        let mut info = GroupInfo::new(participants, addressing_mode);
        if !lid_to_pn_map.is_empty() {
            info.set_lid_to_pn_map(lid_to_pn_map);
        }
        self.get_group_cache()
            .await
            .insert(jid.clone(), info.clone())
            .await;

        Ok(info)
    }

    pub async fn get_participating_groups(
        &self,
    ) -> Result<HashMap<String, GroupMetadata>, anyhow::Error> {
        use wacore_binary::node::NodeContent;

        let participants_node = NodeBuilder::new("participants").build();
        let description_node = NodeBuilder::new("description").build();
        let participating_node = NodeBuilder::new("participating")
            .children([participants_node, description_node])
            .build();

        let iq = crate::request::InfoQuery {
            namespace: "w:g2",
            query_type: crate::request::InfoQueryType::Get,
            to: "@g.us".parse().unwrap(),
            content: Some(NodeContent::Nodes(vec![participating_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let mut result = HashMap::new();

        if let Some(groups_node) = resp_node.get_optional_child("groups") {
            for group_node in groups_node.get_children_by_tag("group") {
                let group_id_str = group_node.attrs().string("id");
                let group_jid: Jid = if group_id_str.contains('@') {
                    group_id_str.parse().unwrap_or_else(|_| Jid {
                        user: group_id_str.clone(),
                        server: "g.us".to_string(),
                        agent: 0,
                        device: 0,
                        integrator: 0,
                    })
                } else {
                    Jid {
                        user: group_id_str.clone(),
                        server: "g.us".to_string(),
                        agent: 0,
                        device: 0,
                        integrator: 0,
                    }
                };

                let subject = group_node
                    .attrs()
                    .optional_string("subject")
                    .unwrap_or_default()
                    .to_string();

                let addressing_mode_str = group_node
                    .attrs()
                    .optional_string("addressing_mode")
                    .unwrap_or("pn");
                let addressing_mode = match addressing_mode_str {
                    "lid" => crate::types::message::AddressingMode::Lid,
                    _ => crate::types::message::AddressingMode::Pn,
                };

                let mut participants = Vec::new();
                for participant_node in group_node.get_children_by_tag("participant") {
                    let jid = participant_node.attrs().jid("jid");
                    let phone_number = participant_node.attrs().optional_jid("phone_number");
                    let admin_type = participant_node.attrs().optional_string("type");
                    let is_admin = admin_type == Some("admin") || admin_type == Some("superadmin");

                    participants.push(GroupParticipant {
                        jid,
                        phone_number,
                        is_admin,
                    });
                }

                let metadata = GroupMetadata {
                    id: group_jid.clone(),
                    subject,
                    participants,
                    addressing_mode,
                };

                result.insert(group_jid.to_string(), metadata);
            }
        }

        Ok(result)
    }

    pub async fn query_group_metadata(&self, jid: &Jid) -> Result<GroupMetadata, anyhow::Error> {
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

        let subject = group_node
            .attrs()
            .optional_string("subject")
            .unwrap_or_default()
            .to_string();

        let addressing_mode_str = group_node
            .attrs()
            .optional_string("addressing_mode")
            .unwrap_or("pn");
        let addressing_mode = match addressing_mode_str {
            "lid" => crate::types::message::AddressingMode::Lid,
            _ => crate::types::message::AddressingMode::Pn,
        };

        let mut participants = Vec::new();
        for participant_node in group_node.get_children_by_tag("participant") {
            let participant_jid = participant_node.attrs().jid("jid");
            let phone_number = participant_node.attrs().optional_jid("phone_number");
            let admin_type = participant_node.attrs().optional_string("type");
            let is_admin = admin_type == Some("admin") || admin_type == Some("superadmin");

            participants.push(GroupParticipant {
                jid: participant_jid,
                phone_number,
                is_admin,
            });
        }

        Ok(GroupMetadata {
            id: jid.clone(),
            subject,
            participants,
            addressing_mode,
        })
    }
}
