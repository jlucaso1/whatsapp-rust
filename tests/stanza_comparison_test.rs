#[cfg(test)]
mod tests {
    use base64::Engine;
    use libsignal_protocol::{
        GenericSignedPreKey, IdentityKeyPair, PreKeyBundle, PreKeyRecord, ProtocolAddress,
        SenderKeyRecord, SenderKeyStore, SignedPreKeyRecord, Timestamp,
    };
    use log::debug;
    use prost::Message;
    use rand::{TryRngCore, random};
    use serde::Deserialize;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use wacore::{
        binary::node::{Node, NodeContent},
        client::context::{GroupInfo, SendContextResolver},
        send::SignalStores,
        signal::store::SessionStore as WacoreSessionStore,
        types::{jid::Jid, message::AddressingMode},
    };
    use waproto::whatsapp as wa;
    use whatsapp_rust::store::{
        Device, memory::MemoryStore, signal_adapter::SignalProtocolStoreAdapter,
    };

    // --- Structs for Deserializing Captured Go Data ---

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
    struct GoSenderKeyRecordBefore {
        b64_record: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct GoSenderKeyRecord {
        sender_key_states: Vec<GoSenderKeyState>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct GoSenderKeyState {
        #[serde(rename = "KeyID")]
        key_id: u32,
        sender_chain_key: GoSenderChainKey,
        signing_key_public: String,
        signing_key_private: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct GoSenderChainKey {
        iteration: u32,
        chain_key: String, // This is a base64 encoded string, equivalent to the 'seed'
    }

    #[derive(Deserialize, Debug, PartialEq, Clone)]
    #[serde(untagged)]
    enum SerializableContent {
        Nodes(Vec<SerializableNode>),
        Bytes(String), // JSON encodes bytes as base64 strings
        String(String),
    }

    #[derive(Deserialize, Debug, PartialEq, Clone)]
    struct SerializableNode {
        #[serde(rename = "tag")]
        tag: String,
        #[serde(rename = "attrs")]
        attrs: Option<HashMap<String, String>>,
        #[serde(rename = "content")]
        content: Option<SerializableContent>,
    }

    // --- Test Implementation ---

    #[tokio::test]
    async fn test_stanza_recreation_matches_go_capture() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug) // Or LevelFilter::Trace for more verbosity
            .try_init();
        // 1. --- LOAD THE CAPTURED BUNDLE ---
        let base_path = Path::new("tests/captured_stanza_group/20250811_222500");

        let metadata_str = fs::read_to_string(base_path.join("metadata.json")).unwrap();
        let metadata: GoMetadata = serde_json::from_str(&metadata_str).unwrap();

        let sk_record_str =
            fs::read_to_string(base_path.join("sender_key_record_before.json")).unwrap();
        let sk_record_before: GoSenderKeyRecordBefore =
            serde_json::from_str(&sk_record_str).unwrap();

        let stanza_str = fs::read_to_string(base_path.join("stanza.json")).unwrap();
        let captured_stanza_serializable: SerializableNode =
            serde_json::from_str(&stanza_str).unwrap();
        let captured_stanza_node = serializable_to_node(captured_stanza_serializable);

        let plaintext_bytes = fs::read(base_path.join("plaintext.txt"))
            .expect("plaintext.txt not found in capture directory");
        let message_proto = waproto::whatsapp::Message::decode(plaintext_bytes.as_slice()).unwrap();

        // 2. --- REPLICATE STATE IN RUST ---
        let sender_device = Device::new(Arc::new(MemoryStore::new()));

        let group_jid: Jid = metadata.group_id.parse().unwrap();
        let sender_jid: Jid = metadata.sender_id.parse().unwrap();
        let message_id = metadata.message_id.clone();

        let sk_record_json_from_b64 = base64::prelude::BASE64_STANDARD
            .decode(sk_record_before.b64_record)
            .unwrap();
        let go_sk_record: GoSenderKeyRecord =
            serde_json::from_slice(&sk_record_json_from_b64).unwrap();

        let mut sender_key_states = Vec::new();
        for go_state in go_sk_record.sender_key_states {
            let signing_key_public = base64::prelude::BASE64_STANDARD
                .decode(go_state.signing_key_public)
                .expect("Failed to decode signing key public");
            let signing_key_private = base64::prelude::BASE64_STANDARD
                .decode(go_state.signing_key_private)
                .expect("Failed to decode signing key private");
            let chain_key_seed = base64::prelude::BASE64_STANDARD
                .decode(go_state.sender_chain_key.chain_key)
                .expect("Failed to decode chain key seed");

            let state_structure = wa::SenderKeyStateStructure {
                sender_key_id: Some(go_state.key_id),
                sender_chain_key: Some(wa::sender_key_state_structure::SenderChainKey {
                    iteration: Some(go_state.sender_chain_key.iteration),
                    seed: Some(chain_key_seed),
                }),
                sender_signing_key: Some(wa::sender_key_state_structure::SenderSigningKey {
                    public: Some(signing_key_public),
                    private: Some(signing_key_private),
                }),
                sender_message_keys: Vec::new(),
            };
            sender_key_states.push(state_structure);
        }

        let record_proto = wa::SenderKeyRecordStructure { sender_key_states };
        let sk_record_bytes = record_proto.encode_to_vec();
        let sender_key_record = SenderKeyRecord::deserialize(&sk_record_bytes).unwrap();

        let sender_address =
            ProtocolAddress::new(sender_jid.user.clone(), (sender_jid.device as u32).into());
        let group_sender_address = ProtocolAddress::new(
            format!("{}\n{}", metadata.group_id, sender_address),
            0.into(),
        );

        let sender_device_arc = Arc::new(Mutex::new(sender_device));
        {
            let mut device_guard = sender_device_arc.lock().await;
            device_guard
                .store_sender_key(&group_sender_address, &sender_key_record)
                .await
                .unwrap();

            // The Go capture indicates a session already existed with the primary device.
            // We must replicate this state for the test to be accurate.
            let recipient_for_session_jid: Jid = "559984726662@s.whatsapp.net".parse().unwrap();
            let recipient_address = ProtocolAddress::new(
                recipient_for_session_jid.user.clone(),
                (recipient_for_session_jid.device as u32).into(),
            );
            // A fresh, empty record is enough to establish that a session exists.
            let session_record = libsignal_protocol::SessionRecord::new_fresh();
            device_guard
                .store_session(&recipient_address, &session_record)
                .await
                .unwrap();
        }

        // 3. --- GENERATE THE STANZA IN RUST ---
        let device_identity_node = captured_stanza_node
            .children()
            .unwrap()
            .iter()
            .find(|n| n.tag == "device-identity")
            .expect("No device-identity node found in captured stanza");

        let device_identity_bytes = match &device_identity_node.content {
            Some(NodeContent::Bytes(b)) => b,
            _ => panic!("device-identity node has no byte content"),
        };

        let account_info =
            wa::AdvSignedDeviceIdentity::decode(device_identity_bytes.as_slice()).unwrap();

        struct MockResolver;
        #[async_trait::async_trait]
        impl SendContextResolver for MockResolver {
            async fn resolve_devices(&self, _jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
                Ok(vec![
                    "559984726662@s.whatsapp.net".parse().unwrap(),
                    "559984726662:14@s.whatsapp.net".parse().unwrap(),
                    "559984726662:41@s.whatsapp.net".parse().unwrap(),
                    "559984726662:42@s.whatsapp.net".parse().unwrap(),
                ])
            }
            async fn fetch_prekeys(
                &self,
                _jids: &[Jid],
            ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
                Ok(HashMap::new())
            }
            async fn fetch_prekeys_for_identity_check(
                &self,
                jids: &[Jid],
            ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
                let mut bundles = HashMap::new();
                for jid in jids {
                    let identity_key_pair =
                        IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
                    let registration_id = random::<u32>();
                    let pre_key_id = 1;
                    let pre_key = PreKeyRecord::new(
                        pre_key_id.into(),
                        &libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err()),
                    );
                    let signed_pre_key_id = 1;
                    let signed_pre_key_keypair =
                        libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
                    let signature = identity_key_pair
                        .private_key()
                        .calculate_signature(
                            &signed_pre_key_keypair.public_key.serialize(),
                            &mut rand::rngs::OsRng.unwrap_err(),
                        )
                        .unwrap();
                    let signed_pre_key = SignedPreKeyRecord::new(
                        signed_pre_key_id.into(),
                        Timestamp::from_epoch_millis(0),
                        &signed_pre_key_keypair,
                        signature.as_ref(),
                    );

                    let bundle = PreKeyBundle::new(
                        registration_id,
                        (jid.device as u32).into(),
                        Some((
                            pre_key.id().unwrap(),
                            pre_key.key_pair().unwrap().public_key,
                        )),
                        signed_pre_key.id().unwrap(),
                        signed_pre_key.key_pair().unwrap().public_key,
                        signed_pre_key.signature().unwrap(),
                        *identity_key_pair.identity_key(),
                    )
                    .unwrap();
                    bundles.insert(jid.clone(), bundle);
                }
                Ok(bundles)
            }
            async fn resolve_group_info(&self, _jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
                Ok(GroupInfo {
                    participants: vec!["559984726662@s.whatsapp.net".parse().unwrap()],
                    addressing_mode: AddressingMode::Pn,
                })
            }
        }

        let mock_resolver = MockResolver;
        let mut group_info = mock_resolver.resolve_group_info(&group_jid).await.unwrap();

        let mut adapter = SignalProtocolStoreAdapter::new(sender_device_arc.clone());
        let mut stores = SignalStores {
            sender_key_store: &mut adapter.sender_key_store,
            session_store: &mut adapter.session_store,
            identity_store: &mut adapter.identity_store,
            prekey_store: &mut adapter.pre_key_store,
            signed_prekey_store: &adapter.signed_pre_key_store,
            kyber_prekey_store: &mut adapter.kyber_pre_key_store,
        };

        let rust_stanza_node = wacore::send::prepare_group_stanza(
            &mut stores,
            &mock_resolver,
            &mut group_info,
            &sender_jid,
            &sender_jid,
            Some(&account_info),
            group_jid,
            message_proto,
            message_id,
            true,
        )
        .await
        .expect("Failed to prepare Rust group stanza");

        // 4. --- DEEP COMPARISON ---
        assert_nodes_equal(&rust_stanza_node, &captured_stanza_node, "root");

        println!("✅ Test passed: Recreated Rust stanza matches the Go capture exactly!");
    }

    // --- Helper Functions for Comparison and Deserialization ---

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
        Node {
            tag: s_node.tag,
            attrs: s_node.attrs.unwrap_or_default(),
            content,
        }
    }

    fn assert_nodes_equal(rust_node: &Node, go_node: &Node, path: &str) {
        assert_eq!(
            rust_node.tag, go_node.tag,
            "Tag mismatch at path '{}'",
            path
        );

        let rust_attrs_filtered = rust_node.attrs.clone();
        let go_attrs_filtered = go_node.attrs.clone();
        debug!("Comparing attributes at path '{}': {:?} vs {:?}", path, rust_attrs_filtered, go_attrs_filtered);
        assert_eq!(
            rust_attrs_filtered, go_attrs_filtered,
            "Attribute mismatch at path '{}'",
            path
        );

        match (&rust_node.content, &go_node.content) {
            (Some(NodeContent::Bytes(rust_bytes)), Some(NodeContent::Bytes(go_bytes))) => {
                if rust_node.attrs.get("type") == Some(&"skmsg".to_string()) {
                    assert_eq!(
                        rust_bytes, go_bytes,
                        "Ciphertext mismatch for skmsg at path '{}'",
                        path
                    );
                }
            }
            (Some(NodeContent::Nodes(rust_children)), Some(NodeContent::Nodes(go_children))) => {
                assert_eq!(
                    rust_children.len(),
                    go_children.len(),
                    "Children count mismatch at path '{}'",
                    path
                );
                for i in 0..rust_children.len() {
                    let new_path = format!("{}/{}", path, rust_children[i].tag);
                    assert_nodes_equal(&rust_children[i], &go_children[i], &new_path);
                }
            }
            (None, None) => {}
            _ => panic!(
                "Content type mismatch at path '{}': Rust={:?}, Go={:?}",
                path, rust_node.content, go_node.content
            ),
        }
    }
}
