use anyhow::{Result, anyhow};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// A LID mapping learned from usync response
#[derive(Debug, Clone)]
pub struct UsyncLidMapping {
    /// The phone number user part (e.g., "559980000001")
    pub phone_number: String,
    /// The LID user part (e.g., "100000012345678")
    pub lid: String,
}

pub fn build_get_user_devices_query(jids: &[Jid], sid: &str) -> Node {
    let user_nodes = jids
        .iter()
        .map(|jid| {
            NodeBuilder::new("user")
                .attr("jid", jid.to_non_ad().to_string())
                .build()
        })
        .collect::<Vec<_>>();

    let query_node = NodeBuilder::new("query")
        .children([NodeBuilder::new("devices").attr("version", "2").build()])
        .build();

    let list_node = NodeBuilder::new("list").children(user_nodes).build();

    NodeBuilder::new("usync")
        .attrs([
            ("context", "message"),
            ("index", "0"),
            ("last", "true"),
            ("mode", "query"),
            ("sid", sid),
        ])
        .children([query_node, list_node])
        .build()
}

pub fn parse_get_user_devices_response(resp_node: &Node) -> Result<Vec<Jid>> {
    let list_node = resp_node
        .get_optional_child_by_tag(&["usync", "list"])
        .ok_or_else(|| anyhow!("<usync> or <list> not found in usync response"))?;

    let mut all_devices = Vec::new();

    for user_node in list_node.get_children_by_tag("user") {
        let user_jid = user_node.attrs().jid("jid");
        let device_list_node = user_node
            .get_optional_child_by_tag(&["devices", "device-list"])
            .ok_or_else(|| anyhow!("<device-list> not found for user {user_jid}"))?;

        for device_node in device_list_node.get_children_by_tag("device") {
            let device_id_str = device_node.attrs().string("id");
            let device_id: u16 = device_id_str.parse()?;

            let mut device_jid = user_jid.clone();
            device_jid.device = device_id;
            all_devices.push(device_jid);
        }
    }

    Ok(all_devices)
}

/// Parse LID mappings from a usync response.
/// Returns a list of phone -> LID mappings learned from the response.
pub fn parse_lid_mappings_from_response(resp_node: &Node) -> Vec<UsyncLidMapping> {
    let mut mappings = Vec::new();

    let list_node = match resp_node.get_optional_child_by_tag(&["usync", "list"]) {
        Some(node) => node,
        None => return mappings,
    };

    for user_node in list_node.get_children_by_tag("user") {
        let user_jid_str = user_node.attrs().string("jid");
        let user_jid: Jid = match user_jid_str.parse() {
            Ok(j) => j,
            Err(_) => continue,
        };

        // Only extract mappings for phone number JIDs (not LID JIDs)
        if user_jid.server != wacore_binary::jid::DEFAULT_USER_SERVER {
            continue;
        }

        // Look for <lid val="...@lid"> node inside the user node
        if let Some(lid_node) = user_node.get_optional_child("lid") {
            let lid_val = lid_node.attrs().string("val");
            if !lid_val.is_empty() {
                // Parse the LID JID to extract just the user part
                if let Ok(lid_jid) = lid_val.parse::<Jid>()
                    && lid_jid.server == wacore_binary::jid::HIDDEN_USER_SERVER
                {
                    mappings.push(UsyncLidMapping {
                        phone_number: user_jid.user.clone(),
                        lid: lid_jid.user.clone(),
                    });
                }
            }
        }
    }

    mappings
}
