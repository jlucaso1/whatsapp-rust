use crate::binary::builder::NodeBuilder;
use crate::binary::node::Node;
use crate::types::jid::Jid;
use anyhow::{Result, anyhow};

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
