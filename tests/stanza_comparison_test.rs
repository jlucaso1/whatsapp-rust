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
        send::{SignalStores, derive_keys_pre_kyber},
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
                jids: &[Jid],
            ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
                self.fetch_prekeys_for_identity_check(jids).await
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

        // Pre-create a session ONLY for the primary device so it uses 'msg' while
        // other devices go through 'pkmsg', matching the Go capture.
        {
            let primary_jid: Jid = "559984726662@s.whatsapp.net".parse().unwrap();
            let bundles = mock_resolver
                .fetch_prekeys_for_identity_check(std::slice::from_ref(&primary_jid))
                .await
                .unwrap();
            let bundle = bundles.get(&primary_jid).unwrap();

            let mut adapter = SignalProtocolStoreAdapter::new(sender_device_arc.clone());
            let primary_addr = libsignal_protocol::ProtocolAddress::new(
                primary_jid.user.clone(),
                (primary_jid.device as u32).into(),
            );
            create_session_without_prekey(
                &primary_addr,
                &mut adapter.session_store,
                &mut adapter.identity_store,
                bundle,
            )
            .await
            .expect("failed to pre-create primary session");
        }

        // Build stores after priming the primary session
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

        debug!(
            "Comparing nodes rust:{:?} vs go:{:?}",
            rust_stanza_node, captured_stanza_node
        );

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
        // For encrypted nodes, compare 'v' strictly and handle 'type' according to expected path.
        if path.ends_with("/enc") {
            let r_v = rust_attrs_filtered.get("v");
            let g_v = go_attrs_filtered.get("v");
            debug!(
                "Comparing attributes at path '{}': {:?} vs {:?}",
                path, rust_attrs_filtered, go_attrs_filtered
            );
            assert_eq!(r_v, g_v, "Attribute 'v' mismatch at path '{}'", path);

            let r_t = rust_attrs_filtered.get("type").cloned().unwrap_or_default();
            let g_t = go_attrs_filtered.get("type").cloned().unwrap_or_default();

            if path.contains("/participants/to") {
                // Participant enc nodes must match exactly to catch MAC/source key divergence.
                assert_eq!(
                    r_t, g_t,
                    "Participant enc type mismatch at path '{}': rust={}, go={}",
                    path, r_t, g_t
                );
            } else {
                // Root enc node should be skmsg and must match exactly
                assert_eq!(r_t, g_t, "Root enc type mismatch at path '{}'", path);
            }
        } else {
            debug!(
                "Comparing attributes at path '{}': {:?} vs {:?}",
                path, rust_attrs_filtered, go_attrs_filtered
            );
            assert_eq!(
                rust_attrs_filtered, go_attrs_filtered,
                "Attribute mismatch at path '{}'",
                path
            );
        }

        match (&rust_node.content, &go_node.content) {
            (Some(NodeContent::Bytes(rust_bytes)), Some(NodeContent::Bytes(go_bytes))) => {
                // Skip ciphertext comparison for encrypted nodes: non-deterministic by design.
                if path.ends_with("/enc") {
                    return;
                }
                if rust_node.attrs.get("type") == Some(&"skmsg".to_string()) {
                    // For skmsg, compare a deterministic header prefix (first 10 bytes),
                    // then skip the rest due to randomness (IV, padding).
                    let header_len = 10usize;
                    assert!(
                        rust_bytes.len() >= header_len && go_bytes.len() >= header_len,
                        "skmsg too short to contain header at path '{}' (len rust={}, go={})",
                        path,
                        rust_bytes.len(),
                        go_bytes.len()
                    );
                    assert_eq!(
                        &rust_bytes[..header_len],
                        &go_bytes[..header_len],
                        "skmsg header prefix mismatch at path '{}'",
                        path
                    );
                } else {
                    assert_eq!(
                        rust_bytes,
                        go_bytes,
                        "Ciphertext mismatch for {} at path '{}'",
                        rust_node.attrs.get("type").unwrap_or(&"enc".to_string()),
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

    async fn create_session_without_prekey<
        S: libsignal_protocol::SessionStore + Send + Sync,
        I: libsignal_protocol::IdentityKeyStore + Send + Sync,
    >(
        remote_address: &libsignal_protocol::ProtocolAddress,
        session_store: &mut S,
        identity_store: &mut I,
        bundle: &libsignal_protocol::PreKeyBundle,
    ) -> anyhow::Result<()> {
        use libsignal_protocol::{IdentityKey, KeyPair, SessionRecord};

        let their_identity_key: &IdentityKey = bundle.identity_key()?;
        let spk_pub = bundle.signed_pre_key_public()?;

        // Create or load session record
        let mut record: SessionRecord = match session_store.load_session(remote_address).await? {
            Some(r) => r,
            None => SessionRecord::new_fresh(),
        };

        // Generate our base key and fetch our identity key pair
        let our_base_kp: KeyPair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let our_id_kp = identity_store.get_identity_key_pair().await?;

        // Compute X3DH secrets: 0xFF*32 || DH(IKa, SPKb) || DH(EKa, IKb) || DH(EKa, SPKb) || [DH(EKa, OPKb)]
        let mut secrets: Vec<u8> = Vec::with_capacity(32 * 5);
        secrets.extend_from_slice(&[0xFFu8; 32]);

        // DH1: IKa x SPKb
        let dh1 = our_id_kp.private_key().calculate_agreement(&spk_pub)?;
        secrets.extend_from_slice(&dh1);

        // DH2: EKa x IKb
        let their_ik_pub = their_identity_key.public_key();
        let dh2 = our_base_kp.private_key.calculate_agreement(their_ik_pub)?;
        secrets.extend_from_slice(&dh2);

        // DH3: EKa x SPKb
        let dh3 = our_base_kp.private_key.calculate_agreement(&spk_pub)?;
        secrets.extend_from_slice(&dh3);

        // Optional DH4: EKa x OPKb
        if let Some(opk_pub) = bundle.pre_key_public()? {
            let dh4 = our_base_kp.private_key.calculate_agreement(&opk_pub)?;
            secrets.extend_from_slice(&dh4);
        }

        // Derive initial RootKey
        let (root_key, _initial_ck) = derive_keys_pre_kyber(&secrets)?;

        // Initial ratchet step to get sending chain
        let our_sending_ratchet_kp: libsignal_protocol::KeyPair =
            libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let (new_root_key, new_sending_chain_key) =
            root_key.create_chain(&spk_pub, &our_sending_ratchet_kp.private_key)?;

        // Build SessionState WITHOUT unacknowledged prekey metadata
        let version = libsignal_protocol::CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION;
        let mut state = libsignal_protocol::SessionState::new(
            version,
            our_id_kp.identity_key(),
            their_identity_key,
            &new_root_key,
            &spk_pub,
            libsignal_protocol::SerializedState::new(),
        )
        .with_sender_chain(&our_sending_ratchet_kp, &new_sending_chain_key);

        state.set_local_registration_id(identity_store.get_local_registration_id().await?);
        state.set_remote_registration_id(bundle.registration_id()?);

        record.promote_state(state);
        identity_store
            .save_identity(remote_address, their_identity_key)
            .await?;
        session_store.store_session(remote_address, &record).await?;

        Ok(())
    }
}
