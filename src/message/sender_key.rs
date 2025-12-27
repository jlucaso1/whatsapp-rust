//! Sender key distribution message processing.
//!
//! This module handles the processing of SenderKeyDistributionMessage (SKDM)
//! which are used to establish sender keys for group messaging in the
//! Signal Protocol.

use crate::client::Client;
use prost::Message as ProtoMessage;
use std::sync::Arc;
use wacore::libsignal::protocol::SenderKeyDistributionMessage;
use wacore::libsignal::protocol::{
    PublicKey as SignalPublicKey, SENDERKEY_MESSAGE_CURRENT_VERSION,
    process_sender_key_distribution_message,
};
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::types::jid::JidExt;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

impl Client {
    /// Handles an incoming SenderKeyDistributionMessage (SKDM).
    ///
    /// This processes the SKDM to establish a sender key for decrypting
    /// future group messages from the sender. Supports both the standard
    /// Signal Protocol format and the Go/Protobuf format used by some clients.
    pub(crate) async fn handle_sender_key_distribution_message(
        self: &Arc<Self>,
        group_jid: &Jid,
        sender_jid: &Jid,
        axolotl_bytes: &[u8],
    ) {
        let skdm = match SenderKeyDistributionMessage::try_from(axolotl_bytes) {
            Ok(msg) => msg,
            Err(e1) => match wa::SenderKeyDistributionMessage::decode(axolotl_bytes) {
                Ok(go_msg) => {
                    let (Some(signing_key), Some(id), Some(iteration), Some(chain_key)) = (
                        go_msg.signing_key.as_ref(),
                        go_msg.id,
                        go_msg.iteration,
                        go_msg.chain_key.as_ref(),
                    ) else {
                        log::warn!(
                            "Go SKDM from {} missing required fields (signing_key={}, id={}, iteration={}, chain_key={})",
                            sender_jid,
                            go_msg.signing_key.is_some(),
                            go_msg.id.is_some(),
                            go_msg.iteration.is_some(),
                            go_msg.chain_key.is_some()
                        );
                        return;
                    };
                    match SignalPublicKey::from_djb_public_key_bytes(signing_key) {
                        Ok(pub_key) => {
                            match SenderKeyDistributionMessage::new(
                                SENDERKEY_MESSAGE_CURRENT_VERSION,
                                id,
                                iteration,
                                chain_key.clone(),
                                pub_key,
                            ) {
                                Ok(skdm) => skdm,
                                Err(e) => {
                                    log::error!(
                                        "Failed to construct SKDM from Go format from {}: {:?} (original parse error: {:?})",
                                        sender_jid,
                                        e,
                                        e1
                                    );
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Failed to parse public key from Go SKDM for {}: {:?} (original parse error: {:?})",
                                sender_jid,
                                e,
                                e1
                            );
                            return;
                        }
                    }
                }
                Err(e2) => {
                    log::error!(
                        "Failed to parse SenderKeyDistributionMessage (standard and Go fallback) from {}: primary: {:?}, fallback: {:?}",
                        sender_jid,
                        e1,
                        e2
                    );
                    return;
                }
            },
        };

        let device_arc = self.persistence_manager.get_device_arc().await;
        let mut device_guard = device_arc.write().await;

        let sender_address = sender_jid.to_protocol_address();

        let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());

        if let Err(e) =
            process_sender_key_distribution_message(&sender_key_name, &skdm, &mut *device_guard)
                .await
        {
            log::error!(
                "Failed to process SenderKeyDistributionMessage from {}: {:?}",
                sender_jid,
                e
            );
        } else {
            log::info!(
                "Successfully processed sender key distribution for group {} from {}",
                group_jid,
                sender_jid
            );
        }
    }
}
