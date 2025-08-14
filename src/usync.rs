use crate::binary::builder::NodeBuilder;
use crate::binary::node::NodeContent;
use crate::client::Client;
use log::debug;
use std::sync::atomic::Ordering;

impl Client {
    pub async fn get_user_devices(
        &self,
        jids: &[crate::types::jid::Jid],
    ) -> Result<Vec<crate::types::jid::Jid>, anyhow::Error> {
        if self.test_mode.load(Ordering::Relaxed) {
            debug!("get_user_devices: Using test mode, returning mock devices for {jids:?}");
            return Ok(jids.to_vec());
        }

        debug!("get_user_devices: Using normal mode for {jids:?}");
        let mut user_nodes = Vec::new();
        for jid in jids {
            user_nodes.push(
                NodeBuilder::new("user")
                    .attr("jid", jid.to_non_ad().to_string())
                    .build(),
            );
        }

        let query_node = NodeBuilder::new("query")
            .children([NodeBuilder::new("devices").attr("version", "2").build()])
            .build();
        let list_node = NodeBuilder::new("list").children(user_nodes).build();
        let sid = self.generate_request_id();
        let usync_node = NodeBuilder::new("usync")
            .attrs([
                ("context", "message"),
                ("index", "0"),
                ("last", "true"),
                ("mode", "query"),
                ("sid", sid.as_str()),
            ])
            .children([query_node, list_node])
            .build();

        let iq = crate::request::InfoQuery {
            namespace: "usync",
            query_type: crate::request::InfoQueryType::Get,
            to: crate::types::jid::SERVER_JID.parse().unwrap(),
            content: Some(NodeContent::Nodes(vec![usync_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let list_node = resp_node
            .get_optional_child_by_tag(&["usync", "list"])
            .ok_or_else(|| anyhow::anyhow!("<usync> or <list> not found in usync response"))?;

        let mut all_devices = Vec::new();
        for user_node in list_node.get_children_by_tag("user") {
            let user_jid = user_node.attrs().jid("jid");
            let device_list_node = user_node
                .get_optional_child_by_tag(&["devices", "device-list"])
                .ok_or_else(|| anyhow::anyhow!("<device-list> not found for user {user_jid}"))?;

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
}
