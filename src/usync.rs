use crate::client::Client;
use log::debug;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::NodeContent;

impl Client {
    pub(crate) async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        debug!("get_user_devices: Using normal mode for {jids:?}");

        let sid = self.generate_request_id();
        let usync_node = wacore::usync::build_get_user_devices_query(jids, sid.as_str());

        let iq = crate::request::InfoQuery {
            namespace: "usync",
            query_type: crate::request::InfoQueryType::Get,
            to: SERVER_JID.parse().unwrap(),
            content: Some(NodeContent::Nodes(vec![usync_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let devices = wacore::usync::parse_get_user_devices_response(&resp_node)?;

        Ok(devices)
    }
}
