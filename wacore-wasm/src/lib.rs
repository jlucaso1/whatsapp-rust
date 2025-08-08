use async_trait::async_trait;
use js_sys::Uint8Array;
use prost::Message;
use wacore::signal::{
    address::SignalAddress,
    groups::message::SenderKeyMessage,
    groups::{builder::GroupSessionBuilder, cipher::GroupCipher},
    identity::{IdentityKey, IdentityKeyPair},
    protocol::{Ciphertext, PreKeySignalMessage, SignalMessage},
    sender_key_name::SenderKeyName,
    state::sender_key_record::SenderKeyRecord,
    state::{prekey_bundle::PreKeyBundle, session_record::SessionRecord},
    store::{IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStore, SignedPreKeyStore},
    util::keyhelper,
    SessionBuilder, SessionCipher,
};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};
use wasm_bindgen::prelude::*;

// Initialize panic hook for better debugging
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

// JavaScript store bridge that implements the Rust store traits
#[wasm_bindgen]
#[derive(Clone)]
extern "C" {
    #[wasm_bindgen(typescript_type = "SignalKeyStore")]
    pub type JsSignalKeyStore;

    // We'll define JS methods here but for now, use stub implementations
}

// Rust wrapper that bridges JavaScript store to Rust store traits
#[derive(Clone)]
pub struct JsStoreWrapper {
    // For stub implementation, we just store a JsValue
    #[allow(dead_code)]
    js_store: JsValue,
}

// SAFETY: In WASM context, there's only one thread, so these are safe
unsafe impl Send for JsStoreWrapper {}
unsafe impl Sync for JsStoreWrapper {}

impl JsStoreWrapper {
    pub fn new(js_store: JsSignalKeyStore) -> Self {
        Self {
            js_store: js_store.into(),
        }
    }
}

// Simplified stub implementations for WASM compatibility
// In a production implementation, these would properly bridge to JavaScript
#[async_trait]
impl IdentityKeyStore for JsStoreWrapper {
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, Box<dyn std::error::Error + Send + Sync>> {
        // WARNING: This is a stub implementation for testing purposes only.
        // In production, this method must load the identity key pair from a persistent store.
        // Using this stub in production will result in security vulnerabilities.
        panic!("Stub implementation: get_identity_key_pair must not be used in production.");
    }

    async fn get_local_registration_id(
        &self,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        Ok(12345) // Stub registration ID
    }

    async fn save_identity(
        &self,
        _address: &SignalAddress,
        _identity_key: &IdentityKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }

    async fn is_trusted_identity(
        &self,
        _address: &SignalAddress,
        _identity_key: &IdentityKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(true) // Always trust for now
    }
}

#[async_trait]
impl PreKeyStore for JsStoreWrapper {
    async fn load_prekey(
        &self,
        _prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None) // No prekeys available
    }

    async fn store_prekey(
        &self,
        _prekey_id: u32,
        _record: PreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }

    async fn contains_prekey(
        &self,
        _prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false) // No prekeys available
    }

    async fn remove_prekey(
        &self,
        _prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }
}

#[async_trait]
impl SignedPreKeyStore for JsStoreWrapper {
    async fn load_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None) // No signed prekeys available
    }

    async fn load_signed_prekeys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![]) // No signed prekeys available
    }

    async fn store_signed_prekey(
        &self,
        _signed_prekey_id: u32,
        _record: SignedPreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }

    async fn contains_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false) // No signed prekeys available
    }

    async fn remove_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }
}

#[async_trait]
impl SessionStore for JsStoreWrapper {
    async fn load_session(
        &self,
        _address: &SignalAddress,
    ) -> Result<SessionRecord, Box<dyn std::error::Error + Send + Sync>> {
        // Return a fresh session record. In a full implementation, you'd deserialize from bytes
        Ok(SessionRecord::new())
    }

    async fn get_sub_device_sessions(
        &self,
        _name: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![]) // No sub-devices
    }

    async fn store_session(
        &self,
        _address: &SignalAddress,
        _record: &SessionRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }

    async fn contains_session(
        &self,
        _address: &SignalAddress,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false) // No sessions stored
    }

    async fn delete_session(
        &self,
        _address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }

    async fn delete_all_sessions(
        &self,
        _name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }
}

#[async_trait]
impl SenderKeyStore for JsStoreWrapper {
    async fn store_sender_key(
        &self,
        _sender_key_name: &SenderKeyName,
        _record: SenderKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }

    async fn load_sender_key(
        &self,
        _sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        // Return a fresh sender key record
        Ok(SenderKeyRecord::new())
    }

    async fn delete_sender_key(
        &self,
        _sender_key_name: &SenderKeyName,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub implementation
    }
}

#[wasm_bindgen]
pub struct WasmSignalRepository {
    store: JsStoreWrapper,
}

#[wasm_bindgen]
impl WasmSignalRepository {
    #[wasm_bindgen(constructor)]
    pub fn new(js_store: JsSignalKeyStore) -> Self {
        console_error_panic_hook::set_once();
        Self {
            store: JsStoreWrapper::new(js_store),
        }
    }

    #[wasm_bindgen(js_name = encryptMessage)]
    pub fn encrypt_message(&self, jid: String, plaintext: js_sys::Uint8Array) -> js_sys::Promise {
        let store = self.store.clone();
        let future = async move {
            let mut plaintext_bytes = vec![0u8; plaintext.length() as usize];
            plaintext.copy_to(&mut plaintext_bytes);

            // Parse JID to create SignalAddress
            let address = SignalAddress::new(jid.clone(), 0);

            // Create SessionCipher
            let session_cipher = SessionCipher::new(store.clone(), address.clone());

            // Load session record
            let mut session_record = store
                .load_session(&address)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to load session: {e}")))?;

            // Encrypt the message
            let ciphertext_message = session_cipher
                .encrypt(&mut session_record, &plaintext_bytes)
                .await
                .map_err(|e| JsValue::from_str(&format!("Encryption failed: {e}")))?;

            // Store updated session
            store
                .store_session(&address, &session_record)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to store session: {e}")))?;

            // Create result object
            let result = js_sys::Object::new();
            let serialized = ciphertext_message.serialize();
            let ciphertext_js = Uint8Array::from(&serialized[..]);
            js_sys::Reflect::set(&result, &"ciphertext".into(), &ciphertext_js).unwrap();
            js_sys::Reflect::set(
                &result,
                &"messageType".into(),
                &JsValue::from(ciphertext_message.q_type()),
            )
            .unwrap();

            Ok(result.into())
        };

        wasm_bindgen_futures::future_to_promise(future)
    }

    #[wasm_bindgen(js_name = decryptMessage)]
    pub fn decrypt_message(
        &self,
        jid: String,
        ciphertext: js_sys::Uint8Array,
        message_type: u32,
    ) -> js_sys::Promise {
        let store = self.store.clone();
        let future = async move {
            let mut ciphertext_bytes = vec![0u8; ciphertext.length() as usize];
            ciphertext.copy_to(&mut ciphertext_bytes);

            // Parse JID to create SignalAddress
            let address = SignalAddress::new(jid.clone(), 0);

            // Create SessionCipher
            let session_cipher = SessionCipher::new(store.clone(), address.clone());

            // Determine ciphertext type and decrypt
            let ciphertext_msg = match message_type {
                2 => Ciphertext::Whisper(
                    SignalMessage::deserialize(&ciphertext_bytes)
                        .map_err(|e| JsValue::from_str(&format!("Invalid whisper message: {e}")))?,
                ),
                3 => Ciphertext::PreKey(
                    PreKeySignalMessage::deserialize(&ciphertext_bytes)
                        .map_err(|e| JsValue::from_str(&format!("Invalid prekey message: {e}")))?,
                ),
                _ => return Err(JsValue::from_str("Unknown message type")),
            };

            // Decrypt the message
            let plaintext = session_cipher
                .decrypt(ciphertext_msg)
                .await
                .map_err(|e| JsValue::from_str(&format!("Decryption failed: {e}")))?;

            // Create result object
            let result = js_sys::Object::new();
            let plaintext_js = Uint8Array::from(&plaintext[..]);
            js_sys::Reflect::set(&result, &"plaintext".into(), &plaintext_js).unwrap();

            Ok(result.into())
        };

        wasm_bindgen_futures::future_to_promise(future)
    }

    #[wasm_bindgen(js_name = encryptGroupMessage)]
    pub fn encrypt_group_message(
        &self,
        group_id: String,
        sender_key_id: String,
        plaintext: js_sys::Uint8Array,
    ) -> js_sys::Promise {
        let store = self.store.clone();
        let future = async move {
            let mut plaintext_bytes = vec![0u8; plaintext.length() as usize];
            plaintext.copy_to(&mut plaintext_bytes);

            // Create SenderKeyName - fix: use cloned strings instead of references
            let sender_key_name = SenderKeyName::new(group_id.clone(), sender_key_id.clone());

            // Create GroupSessionBuilder and GroupCipher
            let group_session_builder = GroupSessionBuilder::new(store.clone());
            let group_cipher =
                GroupCipher::new(sender_key_name, store.clone(), group_session_builder);

            // Encrypt the message
            let sender_key_message = group_cipher
                .encrypt(&plaintext_bytes)
                .await
                .map_err(|e| JsValue::from_str(&format!("Group encryption failed: {e}")))?;

            // Create result object
            let result = js_sys::Object::new();
            let serialized = sender_key_message.serialize();
            let ciphertext_js = Uint8Array::from(&serialized[..]);
            js_sys::Reflect::set(&result, &"ciphertext".into(), &ciphertext_js).unwrap();
            js_sys::Reflect::set(&result, &"messageType".into(), &JsValue::from(4)).unwrap(); // SKMSG

            Ok(result.into())
        };

        wasm_bindgen_futures::future_to_promise(future)
    }

    #[wasm_bindgen(js_name = decryptGroupMessage)]
    pub fn decrypt_group_message(
        &self,
        group_id: String,
        sender_key_id: String,
        ciphertext: js_sys::Uint8Array,
    ) -> js_sys::Promise {
        let store = self.store.clone();
        let future = async move {
            let mut ciphertext_bytes = vec![0u8; ciphertext.length() as usize];
            ciphertext.copy_to(&mut ciphertext_bytes);

            // Create SenderKeyName - fix: use cloned strings
            let sender_key_name = SenderKeyName::new(group_id.clone(), sender_key_id.clone());

            // Create GroupSessionBuilder and GroupCipher
            let group_session_builder = GroupSessionBuilder::new(store.clone());
            let group_cipher =
                GroupCipher::new(sender_key_name, store.clone(), group_session_builder);

            // Parse sender key message
            let (sender_key_message, data_to_verify) =
                SenderKeyMessage::deserialize(&ciphertext_bytes)
                    .map_err(|e| JsValue::from_str(&format!("Invalid sender key message: {e}")))?;

            // Decrypt the message
            let plaintext = group_cipher
                .decrypt(&sender_key_message, data_to_verify)
                .await
                .map_err(|e| JsValue::from_str(&format!("Group decryption failed: {e}")))?;

            // Create result object
            let result = js_sys::Object::new();
            let plaintext_js = Uint8Array::from(&plaintext[..]);
            js_sys::Reflect::set(&result, &"plaintext".into(), &plaintext_js).unwrap();

            Ok(result.into())
        };

        wasm_bindgen_futures::future_to_promise(future)
    }

    #[wasm_bindgen(js_name = injectE2ESession)]
    pub fn inject_e2e_session(&self, jid: String, _prekey_bundle: JsValue) -> js_sys::Promise {
        let store = self.store.clone();
        let future = async move {
            // Parse JID to create SignalAddress
            let address = SignalAddress::new(jid.clone(), 0);

            // Parse PreKeyBundle from JavaScript object
            // For now, create a placeholder bundle
            let bundle = PreKeyBundle {
                registration_id: 1,
                device_id: 0,
                pre_key_id: Some(1),
                pre_key_public: None, // Would be parsed from JS object
                signed_pre_key_id: 1,
                signed_pre_key_public: wacore::signal::ecc::curve::generate_key_pair().public_key,
                signed_pre_key_signature: [0u8; 64], // Would be parsed from JS object
                identity_key: keyhelper::generate_identity_key_pair().public_key().clone(),
            };

            // Create SessionBuilder and process bundle
            let session_builder = SessionBuilder::new(store.clone(), address.clone());
            let mut session_record = store
                .load_session(&address)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to load session: {e}")))?;

            session_builder
                .process_bundle(&mut session_record, &bundle)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to process bundle: {e}")))?;

            // Store updated session
            store
                .store_session(&address, &session_record)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to store session: {e}")))?;

            Ok(JsValue::UNDEFINED)
        };

        wasm_bindgen_futures::future_to_promise(future)
    }

    #[wasm_bindgen(js_name = processSenderKeyDistributionMessage)]
    pub fn process_sender_key_distribution_message(
        &self,
        sender_key_id: String,
        distribution_message: js_sys::Uint8Array,
    ) -> js_sys::Promise {
        let store = self.store.clone();
        let future = async move {
            let mut message_bytes = vec![0u8; distribution_message.length() as usize];
            distribution_message.copy_to(&mut message_bytes);

            // Parse distribution message
            let dist_msg =
                waproto::whatsapp::SenderKeyDistributionMessage::decode(&message_bytes[..])
                    .map_err(|e| {
                        JsValue::from_str(&format!("Invalid distribution message: {e}"))
                    })?;

            // Create SenderKeyName (assuming group_id is the sender_key_id for now)
            let sender_key_name = SenderKeyName::new(sender_key_id.clone(), sender_key_id.clone());

            // Create GroupSessionBuilder and process distribution message
            let group_session_builder = GroupSessionBuilder::new(store.clone());
            group_session_builder
                .process(&sender_key_name, &dist_msg)
                .await
                .map_err(|e| {
                    JsValue::from_str(&format!("Failed to process distribution message: {e}"))
                })?;

            Ok(JsValue::UNDEFINED)
        };

        wasm_bindgen_futures::future_to_promise(future)
    }
}
