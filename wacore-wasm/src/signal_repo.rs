use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use js_sys::{Promise, Uint8Array};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};

use wacore::signal::{
    address::SignalAddress,
    groups::{builder::GroupSessionBuilder, cipher::GroupCipher},
    session::{SessionBuilder, SessionCipher},
    state::prekey_bundle::PreKeyBundle,
    sender_key_name::SenderKeyName,
};

use crate::store::JsSignalStore;

#[derive(Serialize, Deserialize)]
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub r#type: u32,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
}

#[wasm_bindgen]
pub struct WasmSignalRepository {
    store: JsSignalStore,
}

#[wasm_bindgen]
impl WasmSignalRepository {
    #[wasm_bindgen(constructor)]
    pub fn new(js_store: JsValue) -> Self {
        console_error_panic_hook::set_once();
        Self {
            store: JsSignalStore::new(js_store),
        }
    }

    #[wasm_bindgen(js_name = encryptMessage)]
    pub fn encrypt_message(
        &self,
        jid: String,
        plaintext: Uint8Array,
    ) -> Promise {
        let store = self.store.clone();
        let plaintext_vec = plaintext.to_vec();
        
        future_to_promise(async move {
            let result = encrypt_message_impl(store, jid, plaintext_vec).await;
            match result {
                Ok(encrypt_result) => to_value(&encrypt_result)
                    .map_err(|e| JsError::new(&format!("Serialization failed: {}", e))),
                Err(e) => Err(JsError::new(&format!("Encryption failed: {}", e))),
            }
        })
    }

    #[wasm_bindgen(js_name = decryptMessage)]
    pub fn decrypt_message(
        &self,
        jid: String,
        ciphertext: Uint8Array,
        message_type: u32,
    ) -> Promise {
        let store = self.store.clone();
        let ciphertext_vec = ciphertext.to_vec();
        
        future_to_promise(async move {
            let result = decrypt_message_impl(store, jid, ciphertext_vec, message_type).await;
            match result {
                Ok(decrypt_result) => to_value(&decrypt_result)
                    .map_err(|e| JsError::new(&format!("Serialization failed: {}", e))),
                Err(e) => Err(JsError::new(&format!("Decryption failed: {}", e))),
            }
        })
    }

    #[wasm_bindgen(js_name = encryptGroupMessage)]
    pub fn encrypt_group_message(
        &self,
        group_id: String,
        sender_key_id: String,
        plaintext: Uint8Array,
    ) -> Promise {
        let store = self.store.clone();
        let plaintext_vec = plaintext.to_vec();
        
        future_to_promise(async move {
            let result = encrypt_group_message_impl(store, group_id, sender_key_id, plaintext_vec).await;
            match result {
                Ok(encrypt_result) => to_value(&encrypt_result)
                    .map_err(|e| JsError::new(&format!("Serialization failed: {}", e))),
                Err(e) => Err(JsError::new(&format!("Group encryption failed: {}", e))),
            }
        })
    }

    #[wasm_bindgen(js_name = decryptGroupMessage)]
    pub fn decrypt_group_message(
        &self,
        group_id: String,
        sender_key_id: String,
        ciphertext: Uint8Array,
    ) -> Promise {
        let store = self.store.clone();
        let ciphertext_vec = ciphertext.to_vec();
        
        future_to_promise(async move {
            let result = decrypt_group_message_impl(store, group_id, sender_key_id, ciphertext_vec).await;
            match result {
                Ok(decrypt_result) => to_value(&decrypt_result)
                    .map_err(|e| JsError::new(&format!("Serialization failed: {}", e))),
                Err(e) => Err(JsError::new(&format!("Group decryption failed: {}", e))),
            }
        })
    }

    #[wasm_bindgen(js_name = injectE2ESession)]
    pub fn inject_e2e_session(
        &self,
        jid: String,
        prekey_bundle_data: JsValue,
    ) -> Promise {
        let store = self.store.clone();
        
        future_to_promise(async move {
            let result = inject_e2e_session_impl(store, jid, prekey_bundle_data).await;
            match result {
                Ok(_) => Ok(JsValue::UNDEFINED),
                Err(e) => Err(JsError::new(&format!("Session injection failed: {}", e))),
            }
        })
    }

    #[wasm_bindgen(js_name = processSenderKeyDistributionMessage)]
    pub fn process_sender_key_distribution_message(
        &self,
        sender_key_id: String,
        distribution_message: Uint8Array,
    ) -> Promise {
        let store = self.store.clone();
        let message_vec = distribution_message.to_vec();
        
        future_to_promise(async move {
            let result = process_sender_key_distribution_impl(store, sender_key_id, message_vec).await;
            match result {
                Ok(_) => Ok(JsValue::UNDEFINED),
                Err(e) => Err(JsError::new(&format!("Sender key processing failed: {}", e))),
            }
        })
    }
}

// Implementation functions
async fn encrypt_message_impl(
    store: JsSignalStore,
    jid: String,
    plaintext: Vec<u8>,
) -> Result<EncryptResult, Box<dyn std::error::Error + Send + Sync>> {
    let address = SignalAddress::new(&jid, 0); // Default device ID
    let mut session_record = store.load_session(&address).await?;
    
    let cipher = SessionCipher::new(store, address);
    let ciphertext_msg = cipher.encrypt(&mut session_record, &plaintext).await?;
    
    // Store the updated session
    store.store_session(&address, &session_record).await?;
    
    Ok(EncryptResult {
        ciphertext: ciphertext_msg.serialize()?,
        r#type: ciphertext_msg.get_type(),
    })
}

async fn decrypt_message_impl(
    store: JsSignalStore,
    jid: String,
    ciphertext: Vec<u8>,
    message_type: u32,
) -> Result<DecryptResult, Box<dyn std::error::Error + Send + Sync>> {
    let address = SignalAddress::new(&jid, 0); // Default device ID
    let cipher = SessionCipher::new(store.clone(), address.clone());
    
    let plaintext = match message_type {
        1 => {
            // PreKey message
            use wacore::signal::protocol::PreKeySignalMessage;
            let prekey_msg = PreKeySignalMessage::try_from(&ciphertext[..])?;
            cipher.decrypt_prekey_message(&prekey_msg).await?
        }
        2 => {
            // Regular message
            use wacore::signal::protocol::SignalMessage;
            let signal_msg = SignalMessage::try_from(&ciphertext[..])?;
            cipher.decrypt_message(&signal_msg).await?
        }
        _ => return Err("Unsupported message type".into()),
    };
    
    Ok(DecryptResult { plaintext })
}

async fn encrypt_group_message_impl(
    store: JsSignalStore,
    group_id: String,
    sender_key_id: String,
    plaintext: Vec<u8>,
) -> Result<EncryptResult, Box<dyn std::error::Error + Send + Sync>> {
    let sender_key_name = SenderKeyName::new(&group_id, &sender_key_id);
    let session_builder = GroupSessionBuilder::new(store.clone());
    let cipher = GroupCipher::new(sender_key_name, store, session_builder);
    
    let ciphertext_msg = cipher.encrypt(&plaintext).await?;
    
    Ok(EncryptResult {
        ciphertext: ciphertext_msg.serialize()?,
        r#type: 3, // Group message type
    })
}

async fn decrypt_group_message_impl(
    store: JsSignalStore,
    group_id: String,
    sender_key_id: String,
    ciphertext: Vec<u8>,
) -> Result<DecryptResult, Box<dyn std::error::Error + Send + Sync>> {
    let sender_key_name = SenderKeyName::new(&group_id, &sender_key_id);
    let session_builder = GroupSessionBuilder::new(store.clone());
    let cipher = GroupCipher::new(sender_key_name, store, session_builder);
    
    use wacore::signal::groups::message::SenderKeyMessage;
    let sender_key_msg = SenderKeyMessage::try_from(&ciphertext[..])?;
    let plaintext = cipher.decrypt(&sender_key_msg).await?;
    
    Ok(DecryptResult { plaintext })
}

async fn inject_e2e_session_impl(
    store: JsSignalStore,
    jid: String,
    prekey_bundle_data: JsValue,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = SignalAddress::new(&jid, 0); // Default device ID
    let prekey_bundle: PreKeyBundle = from_value(prekey_bundle_data)?;
    
    let session_builder = SessionBuilder::new(store, address);
    session_builder.process_prekey_bundle(&prekey_bundle).await?;
    
    Ok(())
}

async fn process_sender_key_distribution_impl(
    store: JsSignalStore,
    sender_key_id: String,
    distribution_message: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse sender key distribution message and process it
    // This would involve parsing the distribution message format
    // and updating the sender key store accordingly
    
    // For now, we'll implement a basic placeholder
    // In a full implementation, this would parse the distribution message
    // and create/update sender key records
    
    Ok(())
}