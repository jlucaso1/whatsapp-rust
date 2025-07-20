use crate::binary::node::NodeContent;
use crate::client::Client;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::types::jid::{Jid, SERVER_JID};
use log;

// Re-export core utilities
pub use wacore::prekeys::PreKeyUtils;

impl Client {
    /// Fetches pre-key bundles for a list of JIDs.
    pub async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
    ) -> Result<std::collections::HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        // In test mode, return mock prekey bundles
        if self.test_mode.load(std::sync::atomic::Ordering::Relaxed) {
            use wacore::signal::ecc::keys::DjbEcPublicKey;
            use wacore::signal::identity::IdentityKey;
            use crate::signal::state::prekey_bundle::PreKeyBundle;
            
            let mut bundles = std::collections::HashMap::new();
            for jid in jids {
                // Create a dummy prekey bundle for testing
                let dummy_key_data = [0u8; 32];
                let dummy_public_key = DjbEcPublicKey::new(dummy_key_data);
                let dummy_identity_key = IdentityKey::new(dummy_public_key.clone());
                let dummy_signature = [0u8; 64];
                
                let bundle = PreKeyBundle {
                    registration_id: 12345,
                    device_id: jid.device as u32,
                    pre_key_id: Some(1),
                    pre_key_public: Some(dummy_public_key.clone()),
                    signed_pre_key_id: 1,
                    signed_pre_key_public: dummy_public_key,
                    signed_pre_key_signature: dummy_signature,
                    identity_key: dummy_identity_key,
                };
                bundles.insert(jid.clone(), bundle);
            }
            return Ok(bundles);
        }

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
        for jid in bundles.keys() {
            log::debug!("Successfully parsed pre-key bundle for {jid}");
        }

        Ok(bundles)
    }
}
