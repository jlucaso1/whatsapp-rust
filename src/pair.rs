use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use crate::crypto::xed25519::xed25519::verify;
use crate::proto::whatsapp as wa;
use crate::types::events::{Event, PairSuccess, Qr};
use crate::types::jid::{Jid, SERVER_JID};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use log::{debug, error, info, warn};
use prost::Message;
use sha2::Sha256;

// Prefixes from whatsmeow/pair.go, crucial for signature verification
const ADV_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 0];
const ADV_PREFIX_DEVICE_SIGNATURE_GENERATE: &[u8] = &[6, 1];

// Aliases for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Handles incoming IQ stanzas related to the pairing process.
pub async fn handle_iq(client: &mut Client, node: &Node) -> bool {
    if node.attrs.get("from").cloned().unwrap_or_default() != SERVER_JID {
        return false;
    }

    if let Some(children) = node.children() {
        for child in children {
            let handled = match child.tag.as_str() {
                "pair-device" => {
                    // 1. Acknowledge the request immediately, like the Go implementation.
                    acknowledge_request(client, node).await;

                    // 2. Extract QR code refs and generate full QR data strings
                    let codes: Vec<String> = child
                        .get_children_by_tag("ref")
                        .iter()
                        .filter_map(|grandchild| match &grandchild.content {
                            Some(NodeContent::Bytes(bytes)) => {
                                String::from_utf8(bytes.clone()).ok()
                            }
                            _ => None,
                        })
                        .map(|r| make_qr_data(&client.store, r))
                        .collect();

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
            warn!(
                "Failed to send acknowledgement for request ID {}: {:?}",
                id, e
            );
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
        error!("Failed to send pair error node: {:?}", e);
    }
}

/// Handles the <pair-success> stanza, finalizing the pairing process.
async fn handle_pair_success(client: &mut Client, request_node: &Node, success_node: &Node) {
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
            warn!(target: "Client/Pair", "Error parsing device node attributes: {:?}", e);
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
                error!("Failed to send pair-device-sign: {}", e);
                // Optionally: state cleanup here.
                return;
            }

            info!("Successfully paired {}", jid);
            client.store.id = Some(jid.clone());
            // Optionally: persist lid, business_name, platform, etc.

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
            error!("Pairing crypto failed: {}", e);
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
    store: &crate::store::Device,
    device_identity_bytes: &[u8],
) -> Result<(Vec<u8>, u32), PairCryptoError> {
    // 1. Unmarshal HMAC container and verify HMAC
    let hmac_container =
        wa::AdvSignedDeviceIdentityHmac::decode(device_identity_bytes).map_err(|e| {
            PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            }
        })?;

    let mut mac = HmacSha256::new_from_slice(&store.adv_secret_key).unwrap();
    // In the future, we might need to handle is_hosted_account and use a different prefix
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

    mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
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
    let msg_to_verify = concat_bytes(&[
        ADV_PREFIX_ACCOUNT_SIGNATURE,
        &inner_details_bytes,
        &store.identity_key.public_key,
    ]);

    let Ok(signature) = ed25519_dalek::Signature::from_slice(account_sig_bytes) else {
        return Err(PairCryptoError {
            code: 500,
            text: "internal-error",
            source: anyhow::anyhow!("Invalid account signature format"),
        });
    };

    if !verify(
        account_sig_key_bytes.try_into().unwrap(),
        &msg_to_verify,
        &signature,
    ) {
        return Err(PairCryptoError {
            code: 401,
            text: "signature-mismatch",
            source: anyhow::anyhow!("XEd25519 account signature mismatch"),
        });
    }

    // 3. Generate our device signature
    let msg_to_sign = concat_bytes(&[
        ADV_PREFIX_DEVICE_SIGNATURE_GENERATE,
        &inner_details_bytes,
        &store.identity_key.public_key,
        account_sig_key_bytes,
    ]);
    let device_signature = store
        .identity_key
        .sign_message(&msg_to_sign)
        .to_vec();
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
fn make_qr_data(store: &crate::store::Device, ref_str: String) -> String {
    let noise_b64 = B64.encode(&store.noise_key.public_key);
    let identity_b64 = B64.encode(&store.identity_key.public_key);
    let adv_b64 = B64.encode(&store.adv_secret_key);

    [ref_str, noise_b64, identity_b64, adv_b64].join(",")
}

/// Helper to concatenate multiple byte slices into a single Vec.
fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    slices.iter().flat_map(|s| s.iter().cloned()).collect()
}
