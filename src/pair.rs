use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use crate::crypto::xed25519;
use crate::types::events::{Event, PairError, PairSuccess, Qr};
use crate::types::jid::{Jid, SERVER_JID};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use prost::Message;
use sha2::Sha256;
use std::sync::Arc;
use whatsapp_proto::whatsapp as wa;
use whatsapp_proto::whatsapp::AdvEncryptionType;

use std::sync::atomic::Ordering;

// Prefixes from whatsmeow/pair.go, crucial for signature verification
const ADV_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 0];
const ADV_PREFIX_DEVICE_SIGNATURE_GENERATE: &[u8] = &[6, 1];
const ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 5];
const ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION: &[u8] = &[6, 6];

// Aliases for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Handles incoming IQ stanzas related to the pairing process.
pub async fn handle_iq(client: &Arc<Client>, node: &Node) -> bool {
    if node.attrs.get("from").cloned().unwrap_or_default() != SERVER_JID {
        return false;
    }

    if let Some(children) = node.children() {
        for child in children {
            let handled = match child.tag.as_str() {
                "pair-device" => {
                    // 1. Acknowledge the request immediately, like the Go implementation.
                    acknowledge_request(client, node).await;

                    // 2. Extract QR code refs and generate full QR data strings (async)
                    let mut codes = Vec::new();
                    for grandchild in child.get_children_by_tag("ref") {
                        if let Some(NodeContent::Bytes(bytes)) = &grandchild.content {
                            if let Ok(r) = String::from_utf8(bytes.clone()) {
                                let store_guard = client.store.read().await;
                                codes.push(make_qr_data(&store_guard, r));
                            }
                        }
                    }

                    debug!(target: "Client/Pair", "Dispatching QR event with {} codes", codes.len());
                    client.dispatch_event(Event::Qr(Qr { codes })).await;
                    true
                }
                "pair-success" => {
                    handle_pair_success(client, node, child).await;
                    true
                }
                _ => false,
            };
            if handled {
                return true;
            }
        }
    }

    false
}

/// Acknowledges an incoming IQ request by sending a result stanza.
async fn acknowledge_request(client: &Client, request_node: &Node) {
    if let (Some(to), Some(id)) = (request_node.attrs.get("from"), request_node.attrs.get("id")) {
        let ack = Node {
            tag: "iq".into(),
            attrs: [
                ("to".into(), to.clone()),
                ("id".into(), id.clone()),
                ("type".into(), "result".into()),
            ]
            .iter()
            .cloned()
            .collect(),
            content: None,
        };
        if let Err(e) = client.send_node(ack).await {
            warn!("Failed to send acknowledgement for request ID {id}: {e:?}");
        }
    }
}

/// Sends a standardized pair-error IQ response.
async fn send_pair_error(client: &Client, req_id: &str, code: u16, text: &str) {
    let error_node = Node {
        tag: "error".into(),
        attrs: [
            ("code".into(), code.to_string()),
            ("text".into(), text.to_string()),
        ]
        .into(),
        content: None,
    };
    let iq_error = Node {
        tag: "iq".into(),
        attrs: [
            ("to".into(), SERVER_JID.to_string()),
            ("type".into(), "error".into()),
            ("id".into(), req_id.to_string()),
        ]
        .into(),
        content: Some(NodeContent::Nodes(vec![error_node])),
    };
    if let Err(e) = client.send_node(iq_error).await {
        error!("Failed to send pair error node: {e:?}");
    }
}

/// Handles the <pair-success> stanza, finalizing the pairing process.
async fn handle_pair_success(client: &Arc<Client>, request_node: &Node, success_node: &Node) {
    let req_id = match request_node.attrs.get("id") {
        Some(id) => id.to_string(),
        None => {
            error!("Received pair-success without request ID");
            return;
        }
    };

    // Extract all data from the success node.
    let device_identity_bytes = match success_node
        .get_optional_child_by_tag(&["device-identity"])
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(b)) => b.clone(),
        _ => {
            send_pair_error(client, &req_id, 500, "internal-error").await;
            error!("pair-success is missing device-identity");
            return;
        }
    };

    let business_name = success_node
        .get_optional_child_by_tag(&["biz"])
        .map(|n| n.attrs().optional_string("name").unwrap_or("").to_string())
        .unwrap_or_default();

    let platform = success_node
        .get_optional_child_by_tag(&["platform"])
        .map(|n| n.attrs().optional_string("name").unwrap_or("").to_string())
        .unwrap_or_default();

    // For jid and lid, parse them together to handle errors correctly
    let (jid, lid) = if let Some(device_node) = success_node.get_optional_child_by_tag(&["device"])
    {
        let mut parser = device_node.attrs();
        let parsed_jid = parser.optional_jid("jid").unwrap_or_default();
        let parsed_lid = parser.optional_jid("lid").unwrap_or_default();

        if let Err(e) = parser.finish() {
            warn!(target: "Client/Pair", "Error parsing device node attributes: {e:?}");
            (Jid::default(), Jid::default()) // Return defaults on parsing error
        } else {
            (parsed_jid, parsed_lid)
        }
    } else {
        (Jid::default(), Jid::default())
    };

    // Perform the crypto operations directly and respond only once.
    let result = do_pair_crypto(&client.store, &device_identity_bytes).await;

    match result {
        Ok((self_signed_identity_bytes, key_index)) => {
            let signed_identity = match wa::AdvSignedDeviceIdentity::decode(
                self_signed_identity_bytes.as_slice(),
            ) {
                Ok(identity) => Some(identity),
                Err(e) => {
                    error!("FATAL: Failed to re-decode self-signed identity for storage, pairing cannot complete: {e}");
                    client
                        .dispatch_event(Event::PairError(PairError {
                            id: jid.clone(),
                            lid: lid.clone(),
                            business_name: business_name.clone(),
                            platform: platform.clone(),
                            error: format!(
                                "internal error: failed to decode identity for storage: {e}"
                            ),
                        }))
                        .await;
                    return;
                }
            };

            // Update the in-memory store immediately
            let mut store_guard = client.store.write().await;
            store_guard.id = Some(jid.clone());
            store_guard.account = signed_identity;

            // Only set push_name if we actually got one.
            if !business_name.is_empty() {
                info!("✅ Setting push_name during pairing: '{}'", &business_name);
                store_guard.push_name = business_name.clone();
            } else {
                info!(
                    "⚠️ business_name not found in pair-success, push_name remains unset for now."
                );
            }
            drop(store_guard);

            let response_content = Node {
                tag: "pair-device-sign".into(),
                attrs: [].into(),
                content: Some(NodeContent::Nodes(vec![Node {
                    tag: "device-identity".into(),
                    attrs: [("key-index".into(), key_index.to_string())].into(),
                    content: Some(NodeContent::Bytes(self_signed_identity_bytes)),
                }])),
            };
            let response_node = Node {
                tag: "iq".into(),
                attrs: [
                    ("to".into(), SERVER_JID.to_string()),
                    ("id".into(), req_id.clone()),
                    ("type".into(), "result".into()),
                ]
                .into(),
                content: Some(NodeContent::Nodes(vec![response_content])),
            };

            if let Err(e) = client.send_node(response_node).await {
                error!("Failed to send pair-device-sign: {e}");
                // Optionally: state cleanup here.
                return;
            }

            // Tell the client that the upcoming disconnect is expected and part of the flow.
            client.expected_disconnect.store(true, Ordering::Relaxed);

            info!("Successfully paired {jid}");

            let success_event = PairSuccess {
                id: jid,
                lid,
                business_name,
                platform,
            };
            client
                .dispatch_event(Event::PairSuccess(success_event))
                .await;
        }
        Err(e) => {
            error!("Pairing crypto failed: {e}");
            send_pair_error(client, &req_id, e.code, e.text).await;
            // Optionally dispatch a PairError event
            let pair_error_event = crate::types::events::PairError {
                id: jid,
                lid,
                business_name,
                platform,
                error: e.to_string(),
            };
            client
                .dispatch_event(Event::PairError(pair_error_event))
                .await;
        }
    }
}

struct PairCryptoError {
    code: u16,
    text: &'static str,
    source: anyhow::Error,
}

impl std::fmt::Display for PairCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pairing crypto failed with code {}: {} (source: {})",
            self.code, self.text, self.source
        )
    }
}

async fn do_pair_crypto(
    store: &tokio::sync::RwLock<crate::store::Device>,
    device_identity_bytes: &[u8],
) -> Result<(Vec<u8>, u32), PairCryptoError> {
    let store_guard = store.read().await;
    // 1. Unmarshal HMAC container and verify HMAC
    let hmac_container =
        wa::AdvSignedDeviceIdentityHmac::decode(device_identity_bytes).map_err(|e| {
            PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            }
        })?;

    // Determine if this is a hosted account
    let is_hosted_account = hmac_container.account_type.is_some()
        && hmac_container.account_type() == AdvEncryptionType::Hosted;

    let mut mac = HmacSha256::new_from_slice(&store_guard.adv_secret_key).unwrap();
    // Get details and hmac as slices, handling potential None values
    let details_bytes = hmac_container
        .details
        .as_deref()
        .ok_or_else(|| PairCryptoError {
            code: 500,
            text: "internal-error",
            source: anyhow::anyhow!("HMAC container missing details"),
        })?;
    let hmac_bytes = hmac_container
        .hmac
        .as_deref()
        .ok_or_else(|| PairCryptoError {
            code: 500,
            text: "internal-error",
            source: anyhow::anyhow!("HMAC container missing hmac"),
        })?;

    if is_hosted_account {
        mac.update(ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE);
    }
    mac.update(details_bytes);
    if mac.verify_slice(hmac_bytes).is_err() {
        return Err(PairCryptoError {
            code: 401,
            text: "hmac-mismatch",
            source: anyhow::anyhow!("HMAC mismatch"),
        });
    }

    // 2. Unmarshal inner container and verify account signature
    let mut signed_identity =
        wa::AdvSignedDeviceIdentity::decode(details_bytes).map_err(|e| PairCryptoError {
            code: 500,
            text: "internal-error",
            source: e.into(),
        })?;

    let account_sig_key_bytes = signed_identity.account_signature_key();
    let account_sig_bytes = signed_identity.account_signature();
    let inner_details_bytes = signed_identity.details().to_vec();

    let account_sig_prefix = if is_hosted_account {
        ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE
    } else {
        ADV_PREFIX_ACCOUNT_SIGNATURE
    };

    let msg_to_verify = concat_bytes(&[
        account_sig_prefix,
        &inner_details_bytes,
        &store_guard.identity_key.public_key,
    ]);

    let Ok(signature) = ed25519_dalek::Signature::from_slice(account_sig_bytes) else {
        return Err(PairCryptoError {
            code: 500,
            text: "internal-error",
            source: anyhow::anyhow!("Invalid account signature format"),
        });
    };

    if !xed25519::verify(
        account_sig_key_bytes.try_into().unwrap(),
        &msg_to_verify,
        &signature.to_bytes(),
    ) {
        return Err(PairCryptoError {
            code: 401,
            text: "signature-mismatch",
            source: anyhow::anyhow!("XEd25519 account signature mismatch"),
        });
    }

    // 3. Generate our device signature
    let device_sig_prefix = if is_hosted_account {
        ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION
    } else {
        ADV_PREFIX_DEVICE_SIGNATURE_GENERATE
    };

    let msg_to_sign = concat_bytes(&[
        device_sig_prefix,
        &inner_details_bytes,
        &store_guard.identity_key.public_key,
        account_sig_key_bytes,
    ]);
    let device_signature = store_guard.identity_key.sign_message(&msg_to_sign).to_vec();
    signed_identity.device_signature = Some(device_signature);

    // 4. Unmarshal final details to get key_index
    let identity_details =
        wa::AdvDeviceIdentity::decode(&*inner_details_bytes).map_err(|e| PairCryptoError {
            code: 500,
            text: "internal-error",
            source: e.into(),
        })?;
    let key_index = identity_details.key_index();

    // 5. Marshal the modified signed_identity to send back
    let self_signed_identity_bytes = signed_identity.encode_to_vec();

    Ok((self_signed_identity_bytes, key_index))
}

/// Constructs the full QR code string from the ref and the client's keys.
pub fn make_qr_data(store: &crate::store::Device, ref_str: String) -> String {
    let noise_b64 = B64.encode(store.noise_key.public_key);
    let identity_b64 = B64.encode(store.identity_key.public_key);
    let adv_b64 = B64.encode(store.adv_secret_key);

    [ref_str, noise_b64, identity_b64, adv_b64].join(",")
}

/// Helper to concatenate multiple byte slices into a single Vec.
fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    slices.iter().flat_map(|s| s.iter().cloned()).collect()
}

/// Simulates a phone scanning a QR code and pairing with a new device.
/// This is the logic that the "master" client will use in tests.
pub async fn pair_with_qr_code(
    client: &Arc<Client>, // The "master" client
    qr_code: &str,
) -> Result<(), anyhow::Error> {
    info!(target: "Client/PairTest", "Master client attempting to pair with QR code.");

    // 1. Parse the QR Code string
    let parts: Vec<&str> = qr_code.split(',').collect();
    if parts.len() != 4 {
        return Err(anyhow::anyhow!("Invalid QR code format"));
    }
    let pairing_ref = parts[0].to_string();
    let dut_noise_pub_b64 = parts[1];
    let dut_identity_pub_b64 = parts[2];
    // The ADV secret is not used by the phone side.

    let dut_noise_pub_bytes = B64.decode(dut_noise_pub_b64)?;
    let dut_identity_pub_bytes = B64.decode(dut_identity_pub_b64)?;

    let dut_noise_pub: [u8; 32] = dut_noise_pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid noise public key length"))?;
    let dut_identity_pub: [u8; 32] = dut_identity_pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid identity public key length"))?;

    // 2. The master client (phone) generates its own ephemeral key
    let master_ephemeral = crate::crypto::key_pair::KeyPair::new();

    // 3. Perform the cryptographic exchange to create the shared secrets
    let store_guard = client.store.read().await;
    let adv_key = &store_guard.adv_secret_key;
    let identity_key = &store_guard.identity_key;

    let mut mac = HmacSha256::new_from_slice(adv_key).unwrap();
    mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
    mac.update(&dut_identity_pub);
    mac.update(&master_ephemeral.public_key);
    let account_signature = mac.finalize().into_bytes();

    let secret = x25519_dalek::StaticSecret::from(master_ephemeral.private_key);
    let shared_secret = x25519_dalek::x25519(secret.to_bytes(), dut_noise_pub);

    let mut final_message = Vec::new();
    final_message.extend_from_slice(&account_signature);
    final_message.extend_from_slice(&master_ephemeral.public_key);
    final_message.extend_from_slice(&identity_key.public_key);

    // 4. Encrypt the final message
    let encryption_key = crate::crypto::hkdf::sha256(&shared_secret, None, b"WA-Ads-Key", 32)?;
    let encrypted = crate::crypto::gcm::encrypt(
        &encryption_key,
        &[0; 12],
        &final_message,
        pairing_ref.as_bytes(),
    )?;

    // 5. Send the final pairing IQ stanza to the server
    let master_jid = store_guard.id.clone().unwrap();
    drop(store_guard);

    let response_content = Node {
        tag: "pair-device-sign".into(),
        attrs: [("jid".into(), master_jid.to_string())].into(),
        content: Some(NodeContent::Bytes(encrypted)),
    };
    let iq = Node {
        tag: "iq".into(),
        attrs: [
            ("to".into(), SERVER_JID.to_string()),
            ("type".into(), "set".into()),
            ("id".into(), client.generate_request_id()),
            ("xmlns".into(), "md".into()),
        ]
        .into(),
        content: Some(NodeContent::Nodes(vec![response_content])),
    };

    client.send_node(iq).await?;

    info!(target: "Client/PairTest", "Master client sent pairing confirmation.");
    Ok(())
}
