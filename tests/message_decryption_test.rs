use log::info;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::time::timeout;
use wacore::binary::node::{Node, NodeContent};
use wacore::proto_helpers::MessageExt;
use wacore::signal::address::SignalAddress;
use wacore::signal::ecc::key_pair::EcKeyPair;
use wacore::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};
use wacore::signal::identity::IdentityKey;
use wacore::signal::root_key::RootKey;
use wacore::signal::state::session_record::SessionRecord;
use wacore::signal::state::session_state::SessionState;
use wacore::signal::store::{PreKeyStore, SenderKeyStore, SessionStore};
use waproto::whatsapp::session_structure::chain::ChainKey;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::commands::DeviceCommand;

use base64::Engine as _;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

mod test_utils {
    use super::*;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, de};

    use wacore::signal::state::sender_key_record::SenderKeyRecord;

    mod base64_serde {}

    #[derive(Debug)]
    pub(crate) struct JsonBuffer(pub Vec<u8>);

    impl<'de> Deserialize<'de> for JsonBuffer {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde_json::Value;
            let value = Value::deserialize(deserializer)?;
            // Try Buffer object
            if let Some(obj) = value.as_object() {
                if obj.get("type").and_then(|v| v.as_str()) == Some("Buffer") {
                    if let Some(data) = obj.get("data") {
                        // Accept either array of numbers or base64 string
                        if let Some(arr) = data.as_array() {
                            let bytes: Vec<u8> = arr
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();
                            return Ok(JsonBuffer(bytes));
                        }
                        if let Some(s) = data.as_str() {
                            let decoded = base64::prelude::BASE64_STANDARD
                                .decode(s)
                                .map_err(de::Error::custom)?;
                            return Ok(JsonBuffer(decoded));
                        }
                    }
                }
            }
            // Try as base64 string
            if let Some(s) = value.as_str() {
                let decoded = base64::prelude::BASE64_STANDARD
                    .decode(s)
                    .map_err(de::Error::custom)?;
                return Ok(JsonBuffer(decoded));
            }
            Err(de::Error::custom("Invalid Buffer or base64 string"))
        }
    }

    fn from_buffer<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde_json::Value;
        let value = Value::deserialize(deserializer)?;
        // Try Buffer object
        if let Some(obj) = value.as_object() {
            if obj.get("type").and_then(|v| v.as_str()) == Some("Buffer") {
                if let Some(data) = obj.get("data") {
                    // Accept either array of numbers or base64 string
                    if let Some(arr) = data.as_array() {
                        let bytes: Vec<u8> = arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        return bytes
                            .try_into()
                            .map_err(|v: Vec<u8>| de::Error::invalid_length(v.len(), &"32 bytes"));
                    }
                    if let Some(s) = data.as_str() {
                        let decoded = base64::prelude::BASE64_STANDARD
                            .decode(s)
                            .map_err(de::Error::custom)?;
                        return decoded
                            .try_into()
                            .map_err(|v: Vec<u8>| de::Error::invalid_length(v.len(), &"32 bytes"));
                    }
                }
            }
        }
        // Try as base64 string
        if let Some(s) = value.as_str() {
            let decoded = base64::prelude::BASE64_STANDARD
                .decode(s)
                .map_err(de::Error::custom)?;
            return decoded
                .try_into()
                .map_err(|v: Vec<u8>| de::Error::invalid_length(v.len(), &"32 bytes"));
        }
        Err(de::Error::custom("Invalid Buffer or base64 string"))
    }

    // endregion: --- Baileys Struct Definitions for JSON Parsing ---

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct BaileysKeyPair {
        #[serde(deserialize_with = "from_buffer")]
        pub private: [u8; 32],
        #[serde(deserialize_with = "from_buffer")]
        pub public: [u8; 32],
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct BaileysSignedPreKey {
        pub key_pair: BaileysKeyPair,
        pub signature: JsonBuffer,
        pub key_id: u32,
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct Me {
        pub id: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct BaileysCreds {
        pub signed_identity_key: BaileysKeyPair,
        pub signed_pre_key: BaileysSignedPreKey,
        pub registration_id: u32,
        pub me: Me,
    }

    #[derive(Deserialize, Debug)]
    #[serde(untagged)]
    enum JsonStanzaContent {
        Nodes(Vec<JsonStanza>),
        Buffer(JsonBuffer),
    }

    #[derive(Deserialize, Debug)]
    pub(crate) struct JsonStanza {
        pub tag: String,
        pub attrs: HashMap<String, String>,
        content: Option<JsonStanzaContent>,
    }

    impl JsonStanza {
        pub(crate) fn into_node(self) -> Node {
            let content = match self.content {
                Some(JsonStanzaContent::Nodes(nodes)) => Some(NodeContent::Nodes(
                    nodes.into_iter().map(|n| n.into_node()).collect(),
                )),
                Some(JsonStanzaContent::Buffer(JsonBuffer(data))) => Some(NodeContent::Bytes(data)),
                None => None,
            };
            Node {
                tag: self.tag,
                attrs: self.attrs,
                content,
            }
        }
    }

    // region: --- Baileys to WACore Struct Converters ---

    #[derive(Deserialize, Debug)]
    struct BaileysSessionContainer {
        #[serde(rename = "_sessions")]
        sessions: HashMap<String, BaileysSession>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct BaileysSession {
        current_ratchet: BaileysRatchet,
        index_info: BaileysIndexInfo,
        #[serde(rename = "_chains")]
        chains: HashMap<String, BaileysChain>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct BaileysRatchet {
        ephemeral_key_pair: BaileysChainKeyPair,
        previous_counter: u32,
        root_key: JsonBuffer,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct BaileysIndexInfo {
        remote_identity_key: JsonBuffer,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct BaileysChainKeyPair {
        pub_key: JsonBuffer,
        priv_key: JsonBuffer,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct BaileysChain {
        chain_key: BaileysChainKey,
        chain_type: u32,
    }

    #[derive(Deserialize, Debug)]
    struct BaileysChainKey {
        counter: i32,
        key: JsonBuffer,
    }

    pub(crate) fn convert_session(baileys_session_json: &str) -> SessionRecord {
        let container: BaileysSessionContainer =
            serde_json::from_str(baileys_session_json).unwrap();
        let baileys_session = container.sessions.values().next().unwrap();

        let mut session_state = SessionState::new();
        session_state.set_session_version(3);
        let remote_identity_bytes = &baileys_session.index_info.remote_identity_key.0;
        // Strip the type prefix byte (first byte) and use the remaining 32 bytes
        let key_bytes: [u8; 32] = remote_identity_bytes[1..]
            .try_into()
            .expect("remote_identity_key should be 33 bytes with type prefix");
        let key = DjbEcPublicKey::new(key_bytes);
        session_state.set_remote_identity_key(IdentityKey::new(key));
        session_state.set_root_key(RootKey::new(
            baileys_session
                .current_ratchet
                .root_key
                .0
                .clone()
                .try_into()
                .unwrap(),
        ));
        session_state.set_previous_counter(baileys_session.current_ratchet.previous_counter);

        for (_key, chain) in &baileys_session.chains {
            if chain.chain_type == 1 {
                // Sender chain
                session_state.set_sender_chain(
                    EcKeyPair::new(
                        DjbEcPublicKey::new(
                            baileys_session.current_ratchet.ephemeral_key_pair.pub_key.0[1..]
                                .try_into()
                                .unwrap(),
                        ),
                        DjbEcPrivateKey::new(
                            baileys_session
                                .current_ratchet
                                .ephemeral_key_pair
                                .priv_key
                                .0
                                .clone()
                                .try_into()
                                .unwrap(),
                        ),
                    ),
                    ChainKey {
                        key: Some(chain.chain_key.key.0.clone()),
                        index: Some(chain.chain_key.counter as u32),
                    },
                );
            } else {
                // Receiver chain
                let key_bytes = base64::prelude::BASE64_STANDARD.decode(_key).unwrap();
                // Baileys receiver chain keys have a type prefix, strip first byte
                let ratchet_key = DjbEcPublicKey::new(key_bytes[1..].try_into().unwrap());
                session_state.add_receiver_chain(
                    Arc::new(ratchet_key),
                    ChainKey {
                        key: Some(chain.chain_key.key.0.clone()),
                        index: Some(chain.chain_key.counter as u32),
                    },
                );
            }
        }

        let mut record = SessionRecord::new();
        *record.session_state_mut() = session_state;
        record
    }

    // Baileys SenderKey state structures
    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct BaileysSenderKeyState {
        sender_key_id: u32,
        sender_chain_key: BaileysSenderChainKey,
        sender_signing_key: BaileysSenderSigningKey,
    }

    #[derive(Deserialize, Debug)]
    struct BaileysSenderChainKey {
        iteration: u32,
        seed: JsonBuffer,
    }

    #[derive(Deserialize, Debug)]
    struct BaileysSenderSigningKey {
        public: JsonBuffer,
    }

    pub(crate) fn convert_sender_key(baileys_sender_key_json: &str) -> SenderKeyRecord {
        let states: Vec<BaileysSenderKeyState> =
            serde_json::from_str(baileys_sender_key_json).unwrap();

        let mut record = SenderKeyRecord::new();
        for state in states {
            record.add_sender_key_state(
                state.sender_key_id,
                state.sender_chain_key.iteration,
                &state.sender_chain_key.seed.0,
                &state.sender_signing_key.public.0,
            );
        }
        record
    }
}

/// Helper function to set up a test client with pre-loaded state from a capture directory.
async fn setup_test_client(
    capture_dir: &str,
    is_group: bool,
) -> (Arc<Client>, Node, tempfile::TempDir) {
    let dir = Path::new("tests")
        .join("captured_prekeys")
        .join(capture_dir);

    let read_json_file = |file: &str| -> String {
        let path = dir.join(file);
        println!("DEBUG: Attempting to read file: {path:?}");
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                println!("DEBUG: Successfully read file: {path:?}");
                content
            }
            Err(e) => {
                println!("DEBUG: Failed to read file: {path:?} with error: {e:?}");
                panic!("Failed to read {path:?}: {e:?}");
            }
        }
    };

    // 1. Load and parse all necessary files
    let creds_json = read_json_file("creds.json");
    println!("DEBUG: creds.json raw content:\n{creds_json}");
    match serde_json::from_str::<serde_json::Value>(&creds_json) {
        Ok(val) => println!("DEBUG: creds.json parsed as Value:\n{val:#?}"),
        Err(e) => println!("DEBUG: Failed to parse creds.json as Value: {e:?}"),
    }
    let creds: test_utils::BaileysCreds = serde_json::from_str(&creds_json).unwrap();
    let stanza_json = read_json_file("stanza.json");
    let stanza: test_utils::JsonStanza = serde_json::from_str(&stanza_json).unwrap();
    let prekeys_json = read_json_file("pre-keys.json");
    let prekeys: HashMap<u32, Option<test_utils::BaileysKeyPair>> =
        serde_json::from_str(&prekeys_json).unwrap();

    let (session_json, sender_key_json): (Option<String>, Option<String>) = if is_group {
        let sender_key_path = dir.join("sender-key-before.json");
        println!("DEBUG: Checking for sender-key-before.json at {sender_key_path:?}");
        let sender_key = read_json_file("sender-key-before.json");
        println!("DEBUG: Loaded sender-key-before.json content:\n{sender_key}");
        (None, Some(sender_key))
    } else {
        let session_path = dir.join("session-before.json");
        println!("DEBUG: Checking for session-before.json at {session_path:?}");
        let session = read_json_file("session-before.json");
        println!("DEBUG: Loaded session-before.json content:\n{session}");
        (Some(session), None)
    };

    // 2. Setup store and device
    println!("DEBUG: Setting up PersistenceManager...");
    let tempdir = tempfile::tempdir().unwrap();
    let pm = Arc::new(PersistenceManager::new(tempdir.path()).await.unwrap());

    // Modify the device state within the single PersistenceManager
    pm.modify_device(|device| {
        // Populate device from creds
        device.identity_key = wacore::crypto::key_pair::KeyPair {
            public_key: creds.signed_identity_key.public,
            private_key: creds.signed_identity_key.private,
        };
        device.signed_pre_key = wacore::crypto::key_pair::PreKey {
            key_pair: wacore::crypto::key_pair::KeyPair {
                public_key: creds.signed_pre_key.key_pair.public,
                private_key: creds.signed_pre_key.key_pair.private,
            },
            key_id: creds.signed_pre_key.key_id,
            signature: Some(creds.signed_pre_key.signature.0.try_into().unwrap()),
        };
        device.registration_id = creds.registration_id;
    })
    .await;

    let client = Arc::new(Client::new(pm.clone()).await);

    client
        .persistence_manager
        .process_command(DeviceCommand::SetId(Some(creds.me.id.parse().unwrap())))
        .await;

    let device_store = client.persistence_manager.get_device_arc().await;
    let device_store_locked = device_store.lock().await;

    println!(
        "DEBUG: Prekey IDs found in test data: {:?}",
        prekeys.keys().collect::<Vec<_>>()
    );
    for (id, keypair) in prekeys {
        if let Some(kp) = keypair {
            println!("DEBUG: Attempting to store prekey id {id} in device store");
            let record = waproto::whatsapp::PreKeyRecordStructure {
                id: Some(id),
                public_key: Some(kp.public.to_vec()),
                private_key: Some(kp.private.to_vec()),
            };
            match device_store_locked.store_prekey(id, record).await {
                Ok(_) => println!("DEBUG: Successfully stored prekey id {id}"),
                Err(e) => println!("ERROR: Failed to store prekey id {id}: {e:?}"),
            }
        }
    }

    if let Some(json) = session_json {
        println!("DEBUG: Populating session from JSON...");
        let sender_jid_str = stanza
            .attrs
            .get("participant")
            .or_else(|| stanza.attrs.get("from"))
            .unwrap();
        let sender_jid: whatsapp_rust::types::jid::Jid = sender_jid_str.parse().unwrap();
        let sender_addr = SignalAddress::new(sender_jid.user, sender_jid.device as u32);
        let session_record = test_utils::convert_session(&json);
        device_store_locked
            .store_session(&sender_addr, &session_record)
            .await
            .unwrap();
    }

    if let Some(json_b64) = sender_key_json {
        println!("DEBUG: Populating sender key from JSON...");
        // The sender-key-before.json is a Buffer object containing base64-encoded JSON array
        let buffer_obj: serde_json::Value = serde_json::from_str(&json_b64).unwrap();
        let base64_data = buffer_obj
            .get("data")
            .and_then(|v| v.as_str())
            .expect("Missing base64 data in sender-key-before.json");
        let decoded_bytes = base64::prelude::BASE64_STANDARD
            .decode(base64_data)
            .expect("Failed to decode base64 sender key");
        let json_array_str =
            String::from_utf8(decoded_bytes).expect("Sender key bytes not valid UTF-8");
        let sender_key_record = test_utils::convert_sender_key(&json_array_str);

        let group_jid = stanza.attrs.get("from").unwrap();
        let sender_jid_str = stanza.attrs.get("participant").unwrap();
        let sender_jid: whatsapp_rust::types::jid::Jid = sender_jid_str.parse().unwrap();

        let sender_key_name = wacore::signal::sender_key_name::SenderKeyName::new(
            group_jid.to_string(),
            sender_jid.user,
        );
        device_store_locked
            .store_sender_key(&sender_key_name, sender_key_record)
            .await
            .unwrap();
    }

    (client, stanza.into_node(), tempdir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_decrypt_skmsg() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (client, stanza_node, _tempdir) = setup_test_client("3AE25114554577124F87", true).await;

    let mut message_rx = client.subscribe_to_messages();

    info!("Dispatching group message for decryption...");
    client.handle_encrypted_message(stanza_node).await;

    let received_event = timeout(std::time::Duration::from_secs(5), message_rx.recv())
        .await
        .expect("Test timed out waiting for decrypted message event")
        .expect("Message channel was closed unexpectedly");

    let (decrypted_msg, _info) = &*received_event;

    let conversation_text = decrypted_msg.text_content().unwrap_or("");
    info!("Decrypted group message content: \"{conversation_text}\"");

    assert_eq!(conversation_text, "Oi");
    println!("✅ Decrypted group message (skmsg) successfully.");
}
