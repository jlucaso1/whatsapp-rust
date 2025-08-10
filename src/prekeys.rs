use crate::binary::node::NodeContent;
use crate::client::Client;
use crate::types::jid::{Jid, SERVER_JID};
use libsignal_protocol::PreKeyBundle;
use log;

pub use wacore::prekeys::PreKeyUtils;

impl Client {
    pub async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
    ) -> Result<std::collections::HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        if self.test_mode.load(std::sync::atomic::Ordering::Relaxed) {
            use libsignal_protocol::{
                DeviceId, IdentityKey, PreKeyBundle, PreKeyId, PublicKey, SignedPreKeyId,
            };

            let mut bundles = std::collections::HashMap::new();
            for jid in jids {
                let device_snapshot = self.persistence_manager.get_device_snapshot().await;

                let identity_public_key = PublicKey::from_djb_public_key_bytes(
                    device_snapshot
                        .core
                        .identity_key
                        .public_key
                        .public_key_bytes(),
                )?;
                let identity_key = IdentityKey::new(identity_public_key);

                let signed_pre_key_public = PublicKey::from_djb_public_key_bytes(
                    device_snapshot
                        .core
                        .signed_pre_key
                        .public_key
                        .public_key_bytes(),
                )?;
                let signed_pre_key_id: SignedPreKeyId =
                    device_snapshot.core.signed_pre_key_id.into();
                let signed_pre_key_signature =
                    device_snapshot.core.signed_pre_key_signature.to_vec();

                let pre_key_id: PreKeyId = 1u32.into();
                let pre_key_public = identity_public_key;
                let pre_key_tuple = Some((pre_key_id, pre_key_public));

                let bundle = PreKeyBundle::new(
                    device_snapshot.core.registration_id,
                    DeviceId::from(jid.device as u32),
                    pre_key_tuple,
                    signed_pre_key_id,
                    signed_pre_key_public,
                    signed_pre_key_signature,
                    identity_key,
                )?;
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

        for jid in bundles.keys() {
            log::debug!("Successfully parsed pre-key bundle for {jid}");
        }

        Ok(bundles)
    }
}
