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
            use crate::signal::state::prekey_bundle::PreKeyBundle;
            use wacore::signal::identity::IdentityKey;
            use wacore::signal::ecc::keys::DjbEcPublicKey;
            
            let mut bundles = std::collections::HashMap::new();
            for jid in jids {
                // For simplicity in tests, create a dummy bundle that should pass basic validation
                // Use the device's actual identity key if available
                let device_snapshot = self.persistence_manager.get_device_snapshot().await;
                
                let identity_public_key = DjbEcPublicKey::new(device_snapshot.core.identity_key.public_key);
                let identity_key = IdentityKey::new(identity_public_key.clone());
                let signed_pre_key_public = DjbEcPublicKey::new(device_snapshot.core.signed_pre_key.key_pair.public_key);
                
                let bundle = PreKeyBundle {
                    registration_id: device_snapshot.core.registration_id,
                    device_id: jid.device as u32,
                    pre_key_id: Some(1),
                    pre_key_public: Some(identity_public_key),  // Use identity key for simplicity
                    signed_pre_key_id: device_snapshot.core.signed_pre_key.key_id,
                    signed_pre_key_public,
                    signed_pre_key_signature: device_snapshot.core.signed_pre_key.signature.unwrap_or([0u8; 64]),
                    identity_key,
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
