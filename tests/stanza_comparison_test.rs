#[cfg(test)]
mod tests {
    use base64::Engine;
    use log::info;
    use prost::Message;
    use rand::TryRngCore;
    use serde::Deserialize;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use wacore::libsignal::protocol::{
        CiphertextMessage, KeyPair, PreKeySignalMessage, PrivateKey, PublicKey, UsePQRatchet,
        message_decrypt,
    };
    use wacore::libsignal::protocol::{
        PublicKey as SignalPublicKey, SENDERKEY_MESSAGE_CURRENT_VERSION,
    };
    use wacore::libsignal::protocol::{
        SenderKeyDistributionMessage, process_sender_key_distribution_message,
    };
    use wacore::proto_helpers::MessageExt;
    use wacore::signal::store::PreKeyStore as WacorePreKeyStore;
    use wacore::types::jid::JidExt as _;
    use wacore_binary::Node;
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::jid::Jid;
    use wacore_binary::node::NodeContent;
    use waproto::whatsapp as wa;
    use whatsapp_rust::store::sqlite_store::SqliteStore;
    use whatsapp_rust::store::{Device, signal_adapter::SignalProtocolStoreAdapter};

    // --- Data Structures for Deserializing Captured JSON ---

    #[derive(Deserialize, Debug, Clone)]
    struct TestCase {
        path: PathBuf,
        group_id: Jid,
        sender_id: Jid,
        recipient_lid: Jid,
        recipient_pn: Jid,
        #[allow(dead_code)]
        message_id: String,
    }

    #[derive(Deserialize, Debug)]
    struct GoMetadata {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "messageId")]
        message_id: String,
        #[serde(rename = "senderId")]
        sender_id: String,
    }

    #[derive(Deserialize, Debug)]
    struct TestMeta {
        #[serde(rename = "recipientLid")]
        recipient_lid: String,
        #[serde(rename = "recipientPn")]
        recipient_pn: String,
    }

    #[derive(Deserialize, Debug)]
    struct CapturedState {
        registration_id: u32,
        identity_key_pub_b64: String,
        identity_key_priv_b64: String,
        signed_pre_key: CapturedSignedPreKey,
        #[serde(default)]
        pre_keys: Vec<CapturedPreKey>,
    }

    #[derive(Deserialize, Debug)]
    struct CapturedSignedPreKey {
        id: u32,
        public_key_b64: String,
        private_key_b64: String,
        signature_b64: String,
    }

    #[derive(Deserialize, Debug)]
    struct CapturedPreKey {
        id: u32,
        public_key_b64: String,
        private_key_b64: String,
    }

    #[derive(Deserialize, Debug, PartialEq, Clone)]
    #[serde(untagged)]
    enum SerializableContent {
        Nodes(Vec<SerializableNode>),
        Bytes(String),
        String(String),
    }

    #[derive(Deserialize, Debug, PartialEq, Clone)]
    struct SerializableNode {
        tag: String,
        attrs: Option<HashMap<String, String>>,
        content: Option<SerializableContent>,
    }

    // --- Test Case Discovery Function ---

    fn find_test_cases() -> Vec<TestCase> {
        let mut cases = Vec::new();
        let base_dir = Path::new("tests/captured_stanza_group");
        if !base_dir.exists() {
            println!(
                "Skipping group decryption tests: directory '{:?}' not found",
                base_dir
            );
            return cases;
        }

        for entry in fs::read_dir(base_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                let metadata_path = path.join("metadata.json");
                let meta_path = path.join("meta.json");

                if metadata_path.exists() && meta_path.exists() {
                    let metadata_str = fs::read_to_string(&metadata_path).unwrap();
                    let metadata: GoMetadata = serde_json::from_str(&metadata_str).unwrap();

                    let meta_str = fs::read_to_string(&meta_path).unwrap();
                    let meta: TestMeta = serde_json::from_str(&meta_str).unwrap();

                    cases.push(TestCase {
                        path,
                        group_id: metadata.group_id.parse().unwrap(),
                        sender_id: metadata.sender_id.parse().unwrap(),
                        recipient_lid: meta.recipient_lid.parse().unwrap(),
                        recipient_pn: meta.recipient_pn.parse().unwrap(),
                        message_id: metadata.message_id,
                    });
                }
            }
        }
        cases
    }

    // --- Main Test Function (Now uses a for loop) ---

    #[tokio::test]
    async fn test_all_group_message_decryption_captures() {
        let _ = env_logger::builder().is_test(true).try_init();
        let test_cases = find_test_cases();

        assert!(
            !test_cases.is_empty(),
            "No test cases found in 'tests/captured_stanza_group'. Please run the Go capture script."
        );

        for case in test_cases {
            info!("--- Running test case from: {:?} ---", case.path);

            // 1. --- LOAD ALL CAPTURED ASSETS ---
            let plaintext = fs::read_to_string(case.path.join("plaintext.txt")).unwrap();
            let captured_stanza: Node = serializable_to_node(
                serde_json::from_str::<SerializableNode>(
                    &fs::read_to_string(case.path.join("stanza.json")).unwrap(),
                )
                .unwrap(),
            );
            let recipient_state_data: CapturedState = serde_json::from_str(
                &fs::read_to_string(case.path.join("recipient_state.json")).unwrap(),
            )
            .unwrap();

            // 2. --- SETUP RECIPIENT'S CRYPTOGRAPHIC STATE ---
            let recipient_device = setup_device_from_state(recipient_state_data).await;
            let device_arc = Arc::new(RwLock::new(recipient_device));
            let mut recipient_adapter = SignalProtocolStoreAdapter::new(device_arc.clone());

            let sender_signal_address = case.sender_id.to_protocol_address();
            // Do NOT pre-create a fresh session; allow PreKeySignalMessage to establish it.

            // 3. --- DECRYPT PKMSG AND PROCESS SKDM ---
            let participants = captured_stanza
                .get_optional_child("participants")
                .expect("participants node missing");
            let to_children = participants
                .children()
                .expect("participants has no children");

            // Strategy: Prefer pkmsg entry targeting our device (LID device), else any pkmsg for our PN user, else bare msg.
            let mut candidate_pkmsg_exact = None;
            let mut candidate_pkmsg_same_user = None;
            let mut candidate_msg = None;
            for n in to_children.iter() {
                if let Some(jid_str) = n.attrs.get("jid")
                    && let Ok(participant_jid) = jid_str.parse::<Jid>()
                    && participant_jid.user == case.recipient_pn.user
                {
                    let enc_child = n.get_optional_child("enc");
                    if let Some(enc_child) = enc_child {
                        let etype = enc_child.attrs.get("type").cloned().unwrap_or_default();
                        if etype == "pkmsg" {
                            if participant_jid.device == case.recipient_lid.device {
                                candidate_pkmsg_exact = Some(n);
                            } else if candidate_pkmsg_same_user.is_none() {
                                candidate_pkmsg_same_user = Some(n);
                            }
                        } else if etype == "msg" && candidate_msg.is_none() {
                            candidate_msg = Some(n);
                        }
                    }
                }
            }
            let recipient_to_node = candidate_pkmsg_exact
                .or(candidate_pkmsg_same_user)
                .or(candidate_msg)
                .unwrap_or_else(|| {
                    panic!(
                        "No suitable <to> node found for recipient user {} (wanted device {})",
                        case.recipient_pn.user, case.recipient_lid.device
                    )
                });

            let enc_node = recipient_to_node.get_optional_child("enc").unwrap();
            let pkmsg_ciphertext = match &enc_node.content {
                Some(NodeContent::Bytes(b)) => b,
                _ => panic!("<enc type=pkmsg> has no byte content"),
            };

            let enc_type = enc_node.attrs.get("type").cloned().unwrap_or_default();
            eprintln!(
                "[DEBUG] Recipient session enc type={} length={}",
                enc_type,
                pkmsg_ciphertext.len()
            );
            let dm_cipher = if enc_type == "pkmsg" {
                CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(pkmsg_ciphertext.as_slice())
                        .expect("Failed to parse PreKeySignalMessage"),
                )
            } else if enc_type == "msg" {
                CiphertextMessage::SignalMessage(
                    wacore::libsignal::protocol::SignalMessage::try_from(
                        pkmsg_ciphertext.as_slice(),
                    )
                    .expect("Failed to parse SignalMessage"),
                )
            } else {
                panic!(
                    "Unexpected enc type for session establishment: {}",
                    enc_type
                );
            };
            let decrypted_skdm_payload = message_decrypt(
                &dm_cipher,
                &sender_signal_address,
                &mut recipient_adapter.session_store,
                &mut recipient_adapter.identity_store,
                &mut recipient_adapter.pre_key_store,
                &recipient_adapter.signed_pre_key_store,
                &mut rand::rngs::OsRng.unwrap_err(),
                UsePQRatchet::No,
            )
            .await
            .expect("DECRYPTION OF PKMSG FAILED!");

            eprintln!(
                "[DEBUG] Decrypted SKDM wrapper payload len={} hex={}",
                decrypted_skdm_payload.len(),
                hex::encode(&decrypted_skdm_payload)
            );
            // Remove padding (PKCS#7 style) if present
            let skdm_wrapper_bytes = {
                if decrypted_skdm_payload.is_empty() {
                    decrypted_skdm_payload.clone()
                } else {
                    let pad_len = *decrypted_skdm_payload.last().unwrap() as usize;
                    if pad_len > 0 && pad_len <= decrypted_skdm_payload.len() {
                        let (data, padding) =
                            decrypted_skdm_payload.split_at(decrypted_skdm_payload.len() - pad_len);
                        if padding.iter().all(|b| *b as usize == pad_len) {
                            data.to_vec()
                        } else {
                            decrypted_skdm_payload.clone()
                        }
                    } else {
                        decrypted_skdm_payload.clone()
                    }
                }
            };
            eprintln!(
                "[DEBUG] Unpadded SKDM wrapper payload len={} hex={}",
                skdm_wrapper_bytes.len(),
                hex::encode(&skdm_wrapper_bytes)
            );

            let skdm_wrapper = wa::Message::decode(skdm_wrapper_bytes.as_slice()).unwrap();
            let skdm = skdm_wrapper.sender_key_distribution_message.unwrap();
            let axolotl_bytes = skdm
                .axolotl_sender_key_distribution_message
                .as_ref()
                .expect("Missing axolotl_sender_key_distribution_message bytes");

            eprintln!(
                "[DEBUG] Raw axolotl SKDM bytes len={} hex={}",
                axolotl_bytes.len(),
                hex::encode(axolotl_bytes)
            );

            // Attempt normal parsing first, fallback to manual decode on failure
            let skdm_proto = match SenderKeyDistributionMessage::try_from(axolotl_bytes.as_slice())
            {
                Ok(m) => m,
                Err(err_primary) => {
                    eprintln!(
                        "[DEBUG] Primary SKDM parse failed: {:?}; attempting Go protobuf fallback",
                        err_primary
                    );

                    let go_msg: wa::SenderKeyDistributionMessage =
                        match wa::SenderKeyDistributionMessage::decode(axolotl_bytes.as_slice()) {
                            Ok(m) => m,
                            Err(e) => {
                                panic!(
                                    "Failed to prost-decode Go SKDM protobuf after primary parse error: {:?}",
                                    e
                                );
                            }
                        };
                    let signing_key_public =
                        SignalPublicKey::from_djb_public_key_bytes(&go_msg.signing_key.unwrap())
                            .expect("Failed to parse public signing key from Go SKDM");
                    SenderKeyDistributionMessage::new(
                        SENDERKEY_MESSAGE_CURRENT_VERSION,
                        go_msg.id.unwrap(),
                        go_msg.iteration.unwrap(),
                        go_msg.chain_key.unwrap(),
                        signing_key_public,
                    )
                    .expect("Failed constructing SenderKeyDistributionMessage from Go format")
                }
            };

            let group_sender_address = wacore::libsignal::protocol::ProtocolAddress::new(
                format!("{}\n{}", case.group_id, sender_signal_address),
                0.into(),
            );

            process_sender_key_distribution_message(
                &group_sender_address,
                &skdm_proto,
                &mut recipient_adapter.sender_key_store,
            )
            .await
            .expect("Failed to process SKDM on recipient");

            // 4. --- DECRYPT SKMSG AND VERIFY ---
            let skmsg_node = captured_stanza.get_optional_child("enc").unwrap();
            let skmsg_ciphertext = match &skmsg_node.content {
                Some(NodeContent::Bytes(b)) => b,
                _ => panic!("skmsg node has no byte content"),
            };

            let decrypted_message_payload = wacore::libsignal::protocol::group_decrypt(
                skmsg_ciphertext,
                &mut recipient_adapter.sender_key_store,
                &group_sender_address,
            )
            .await
            .expect("DECRYPTION OF SKMSG FAILED!");
            // Unpad group message
            let group_plain = {
                if decrypted_message_payload.is_empty() {
                    decrypted_message_payload.clone()
                } else {
                    let pad_len = *decrypted_message_payload.last().unwrap() as usize;
                    if pad_len > 0 && pad_len <= decrypted_message_payload.len() {
                        let (data, padding) = decrypted_message_payload
                            .split_at(decrypted_message_payload.len() - pad_len);
                        if padding.iter().all(|b| *b as usize == pad_len) {
                            data.to_vec()
                        } else {
                            decrypted_message_payload.clone()
                        }
                    } else {
                        decrypted_message_payload.clone()
                    }
                }
            };
            eprintln!(
                "[DEBUG] Decrypted group message len={} unpadded_len={} hex={}",
                decrypted_message_payload.len(),
                group_plain.len(),
                hex::encode(&group_plain)
            );
            let final_message = wa::Message::decode(group_plain.as_slice()).unwrap();
            assert_eq!(
                final_message.text_content().unwrap(),
                plaintext.trim(),
                "Decrypted plaintext did not match for case {:?}",
                case.path
            );

            info!("✅ Test passed for {:?}!", case.path.file_name().unwrap());
        }
    }

    // --- Helper Functions ---

    async fn setup_device_from_state(state: CapturedState) -> Device {
        let mut device = Device::new(Arc::new(SqliteStore::new(":memory:").await.unwrap()));

        let identity_pub = PublicKey::from_djb_public_key_bytes(
            &base64::prelude::BASE64_STANDARD
                .decode(&state.identity_key_pub_b64)
                .unwrap(),
        )
        .unwrap();
        let identity_priv = PrivateKey::deserialize(
            &base64::prelude::BASE64_STANDARD
                .decode(&state.identity_key_priv_b64)
                .unwrap(),
        )
        .unwrap();
        device.core.identity_key = KeyPair::new(identity_pub, identity_priv);

        let signed_pre_key_pub = PublicKey::from_djb_public_key_bytes(
            &base64::prelude::BASE64_STANDARD
                .decode(&state.signed_pre_key.public_key_b64)
                .unwrap(),
        )
        .unwrap();
        let signed_pre_key_priv = PrivateKey::deserialize(
            &base64::prelude::BASE64_STANDARD
                .decode(&state.signed_pre_key.private_key_b64)
                .unwrap(),
        )
        .unwrap();
        device.core.signed_pre_key = KeyPair::new(signed_pre_key_pub, signed_pre_key_priv);
        device.core.signed_pre_key_id = state.signed_pre_key.id;
        let sig_bytes = base64::prelude::BASE64_STANDARD
            .decode(&state.signed_pre_key.signature_b64)
            .unwrap();
        device.core.signed_pre_key_signature = sig_bytes.try_into().unwrap_or([0u8; 64]);
        device.core.registration_id = state.registration_id;

        for pre_key_data in state.pre_keys {
            let pre_key_pub = PublicKey::from_djb_public_key_bytes(
                &base64::prelude::BASE64_STANDARD
                    .decode(&pre_key_data.public_key_b64)
                    .unwrap(),
            )
            .unwrap();
            let pre_key_priv = PrivateKey::deserialize(
                &base64::prelude::BASE64_STANDARD
                    .decode(&pre_key_data.private_key_b64)
                    .unwrap(),
            )
            .unwrap();
            let key_pair = KeyPair::new(pre_key_pub, pre_key_priv);

            let record =
                wacore::signal::state::record::new_pre_key_record(pre_key_data.id, &key_pair);
            // Now we can just .await the async method
            device
                .store_prekey(pre_key_data.id, record, false)
                .await
                .unwrap();
        }

        device
    }

    fn serializable_to_node(s_node: SerializableNode) -> Node {
        let content = match s_node.content {
            Some(SerializableContent::Nodes(nodes)) => Some(NodeContent::Nodes(
                nodes.into_iter().map(serializable_to_node).collect(),
            )),
            Some(SerializableContent::Bytes(b64_string)) => Some(NodeContent::Bytes(
                base64::prelude::BASE64_STANDARD.decode(b64_string).unwrap(),
            )),
            Some(SerializableContent::String(s)) => Some(NodeContent::Bytes(s.into_bytes())),
            None => None,
        };
        NodeBuilder::new(s_node.tag)
            .attrs(s_node.attrs.unwrap_or_default())
            .apply_content(content)
            .build()
    }
}
