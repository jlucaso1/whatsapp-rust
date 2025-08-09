use log::info;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::time::timeout;
use wacore::binary::node::{Node, NodeContent};
use wacore::proto_helpers::MessageExt;

use libsignal_protocol::{ProtocolAddress, SenderKeyRecord, SenderKeyStore, SessionRecord};

use wacore::signal::store::{PreKeyStore, SessionStore};

use base64::Engine as _;
use prost::Message;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

mod test_utils {
    use super::*;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, de};
    use waproto::whatsapp::{
        SenderKeyRecordStructure, SenderKeyStateStructure,
        sender_key_state_structure::{SenderChainKey, SenderSigningKey},
    };

    #[derive(Debug)]
    pub(crate) struct JsonBuffer(pub Vec<u8>);

    impl<'de> Deserialize<'de> for JsonBuffer {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde_json::Value;
            let value = Value::deserialize(deserializer)?;
            if let Some(obj) = value.as_object()
                && obj.get("type").and_then(|v| v.as_str()) == Some("Buffer")
                && let Some(data) = obj.get("data")
            {
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

        if let Some(obj) = value.as_object()
            && obj.get("type").and_then(|v| v.as_str()) == Some("Buffer")
            && let Some(data) = obj.get("data")
        {
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

    pub(crate) fn convert_session(_baileys_session_json: &str) -> SessionRecord {
        panic!(
            "`convert_session` is outdated and not compatible with the current signal protocol implementation."
        );
    }

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

        let sender_key_states = states
            .into_iter()
            .map(|state| SenderKeyStateStructure {
                sender_key_id: Some(state.sender_key_id),
                sender_chain_key: Some(SenderChainKey {
                    iteration: Some(state.sender_chain_key.iteration),
                    seed: Some(state.sender_chain_key.seed.0),
                }),
                sender_signing_key: Some(SenderSigningKey {
                    public: Some(state.sender_signing_key.public.0),
                    private: vec![].into(),
                }),
                sender_message_keys: vec![],
            })
            .collect();

        let record_proto = SenderKeyRecordStructure { sender_key_states };

        let mut record_bytes = Vec::new();
        record_proto
            .encode(&mut record_bytes)
            .expect("Failed to encode SenderKeyRecordStructure protobuf");

        SenderKeyRecord::deserialize(&record_bytes)
            .expect("Failed to deserialize constructed SenderKeyRecord")
    }
}

async fn setup_test_client(capture_dir: &str, is_group: bool) -> (Arc<Client>, Node) {
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

    let creds_json = read_json_file("creds.json");
    let creds: test_utils::BaileysCreds = serde_json::from_str(&creds_json).unwrap();
    let stanza_json = read_json_file("stanza.json");
    let stanza: test_utils::JsonStanza = serde_json::from_str(&stanza_json).unwrap();
    let prekeys_json = read_json_file("pre-keys.json");
    let prekeys: HashMap<u32, Option<test_utils::BaileysKeyPair>> =
        serde_json::from_str(&prekeys_json).unwrap();

    let (session_json, sender_key_json): (Option<String>, Option<String>) = if is_group {
        let sender_key = read_json_file("sender-key-before.json");
        (None, Some(sender_key))
    } else {
        let session = read_json_file("session-before.json");
        (Some(session), None)
    };

    let pm = Arc::new(PersistenceManager::new_in_memory().await.unwrap());

    pm.modify_device(|device| {
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
    let mut device_store_locked = device_store.lock().await;

    for (id, keypair) in prekeys {
        if let Some(kp) = keypair {
            let record = waproto::whatsapp::PreKeyRecordStructure {
                id: Some(id),
                public_key: Some(kp.public.to_vec()),
                private_key: Some(kp.private.to_vec()),
            };
            if let Err(e) = device_store_locked.store_prekey(id, record).await {
                println!("ERROR: Failed to store prekey id {id}: {e:?}");
            }
        }
    }

    if let Some(json) = session_json {
        let sender_jid_str = stanza
            .attrs
            .get("participant")
            .or_else(|| stanza.attrs.get("from"))
            .unwrap();
        let sender_jid: whatsapp_rust::types::jid::Jid = sender_jid_str.parse().unwrap();
        let sender_addr = ProtocolAddress::new(sender_jid.user, (sender_jid.device as u32).into());
        let session_record = test_utils::convert_session(&json);
        device_store_locked
            .store_session(&sender_addr, &session_record)
            .await
            .unwrap();
    }

    if let Some(json_b64) = sender_key_json {
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

        let group_jid_str = stanza.attrs.get("from").unwrap();
        let sender_jid_str = stanza.attrs.get("participant").unwrap();
        let sender_jid: whatsapp_rust::types::jid::Jid = sender_jid_str.parse().unwrap();

        let sender_address =
            ProtocolAddress::new(sender_jid.user.clone(), (sender_jid.device as u32).into());
        let group_sender_name = format!("{}\n{}", group_jid_str, sender_address);
        let group_sender_address = ProtocolAddress::new(group_sender_name, 0.into());

        device_store_locked
            .store_sender_key(&group_sender_address, &sender_key_record)
            .await
            .unwrap();
    }

    (client, stanza.into_node())
}

#[tokio::test]
async fn test_decrypt_skmsg() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (client, stanza_node) = setup_test_client("3AE25114554577124F87", true).await;

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
