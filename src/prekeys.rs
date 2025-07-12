use crate::binary::node::NodeContent;
use crate::client::Client;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::types::jid::{Jid, SERVER_JID};
use log;

// Re-export core utilities  
pub use whatsapp_core::prekeys::PreKeyUtils;

impl Client {
    /// Fetches pre-key bundles for a list of JIDs.
    pub async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
    ) -> Result<std::collections::HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        let content = PreKeyUtils::build_fetch_prekeys_request(jids);

        let resp_node = self
            .send_iq(crate::request::InfoQuery {
                namespace: "encrypt",
                query_type: crate::request::InfoQueryType::Get,
                to: SERVER_JID.parse().unwrap(),
                content: Some(NodeContent::Nodes(vec![content])),
                id: None,
                target: None,
                timeout: None,
            })
            .await?;

        let bundles = PreKeyUtils::parse_prekeys_response(&resp_node)?;
        
        // Add logging for any failed bundles (driver responsibility)
        for (jid, _) in &bundles {
            log::debug!("Successfully parsed pre-key bundle for {}", jid);
        }
        
        Ok(bundles)
    }
}
