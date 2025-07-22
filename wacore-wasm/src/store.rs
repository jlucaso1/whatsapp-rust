use async_trait::async_trait;
use js_sys::{Object, Promise, Uint8Array};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use std::error::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use wacore::signal::{
    address::SignalAddress,
    identity::{IdentityKey, IdentityKeyPair}, 
    sender_key_name::SenderKeyName,
    state::{
        session_record::SessionRecord,
        sender_key_record::SenderKeyRecord,
    },
    store::{
        IdentityKeyStore, PreKeyStore, SessionStore, 
        SignedPreKeyStore, SenderKeyStore, SignalProtocolStore, 
        StoreError
    },
};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// Bridge struct that holds JavaScript store implementation
#[wasm_bindgen]
#[derive(Clone)]
pub struct JsSignalStore {
    js_store: JsValue,
}

#[wasm_bindgen]
impl JsSignalStore {
    #[wasm_bindgen(constructor)]
    pub fn new(js_store: JsValue) -> Self {
        Self { js_store }
    }
}

// Helper function to call JS async methods
async fn call_js_async_method(
    js_object: &JsValue, 
    method_name: &str, 
    args: &[JsValue]
) -> Result<JsValue, Box<dyn Error + Send + Sync>> {
    let js_method = js_sys::Reflect::get(js_object, &JsValue::from_str(method_name))
        .map_err(|e| format!("Failed to get method {}: {:?}", method_name, e))?;
    
    let promise = js_sys::Reflect::apply(
        js_method.dyn_ref::<js_sys::Function>().ok_or("Method is not a function")?,
        js_object,
        &js_sys::Array::from_iter(args.iter().cloned())
    ).map_err(|e| format!("Failed to call method {}: {:?}", method_name, e))?;
    
    let future = JsFuture::from(Promise::from(promise));
    let result = future.await
        .map_err(|e| format!("JS method {} failed: {:?}", method_name, e))?;
    
    Ok(result)
}

// Implement IdentityKeyStore trait
#[async_trait]
impl IdentityKeyStore for JsSignalStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        let result = call_js_async_method(&self.js_store, "getIdentityKeyPair", &[]).await?;
        let key_pair: IdentityKeyPair = from_value(result)
            .map_err(|e| format!("Failed to deserialize IdentityKeyPair: {}", e))?;
        Ok(key_pair)
    }

    async fn get_local_registration_id(&self) -> Result<u32, StoreError> {
        let result = call_js_async_method(&self.js_store, "getLocalRegistrationId", &[]).await?;
        let reg_id: u32 = result.as_f64().ok_or("Expected number")? as u32;
        Ok(reg_id)
    }

    async fn save_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), StoreError> {
        let address_js = to_value(address)
            .map_err(|e| format!("Failed to serialize address: {}", e))?;
        let identity_js = to_value(identity_key)
            .map_err(|e| format!("Failed to serialize identity key: {}", e))?;
        
        call_js_async_method(&self.js_store, "saveIdentity", &[address_js, identity_js]).await?;
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        let address_js = to_value(address)
            .map_err(|e| format!("Failed to serialize address: {}", e))?;
        let identity_js = to_value(identity_key)
            .map_err(|e| format!("Failed to serialize identity key: {}", e))?;
        
        let result = call_js_async_method(&self.js_store, "isTrustedIdentity", &[address_js, identity_js]).await?;
        let is_trusted = result.as_bool().ok_or("Expected boolean")?;
        Ok(is_trusted)
    }
}

// Implement SessionStore trait
#[async_trait]
impl SessionStore for JsSignalStore {
    async fn load_session(&self, address: &SignalAddress) -> Result<SessionRecord, StoreError> {
        let address_js = to_value(address)
            .map_err(|e| format!("Failed to serialize address: {}", e))?;
        
        let result = call_js_async_method(&self.js_store, "loadSession", &[address_js]).await?;
        let session: SessionRecord = from_value(result)
            .map_err(|e| format!("Failed to deserialize SessionRecord: {}", e))?;
        Ok(session)
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        let name_js = JsValue::from_str(name);
        let result = call_js_async_method(&self.js_store, "getSubDeviceSessions", &[name_js]).await?;
        let devices: Vec<u32> = from_value(result)
            .map_err(|e| format!("Failed to deserialize device list: {}", e))?;
        Ok(devices)
    }

    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        let address_js = to_value(address)
            .map_err(|e| format!("Failed to serialize address: {}", e))?;
        let record_js = to_value(record)
            .map_err(|e| format!("Failed to serialize session record: {}", e))?;
        
        call_js_async_method(&self.js_store, "storeSession", &[address_js, record_js]).await?;
        Ok(())
    }

    async fn contains_session(&self, address: &SignalAddress) -> Result<bool, StoreError> {
        let address_js = to_value(address)
            .map_err(|e| format!("Failed to serialize address: {}", e))?;
        
        let result = call_js_async_method(&self.js_store, "containsSession", &[address_js]).await?;
        let contains = result.as_bool().ok_or("Expected boolean")?;
        Ok(contains)
    }

    async fn delete_session(&self, address: &SignalAddress) -> Result<(), StoreError> {
        let address_js = to_value(address)
            .map_err(|e| format!("Failed to serialize address: {}", e))?;
        
        call_js_async_method(&self.js_store, "deleteSession", &[address_js]).await?;
        Ok(())
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        let name_js = JsValue::from_str(name);
        call_js_async_method(&self.js_store, "deleteAllSessions", &[name_js]).await?;
        Ok(())
    }
}

// Implement PreKeyStore trait
#[async_trait]
impl PreKeyStore for JsSignalStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, StoreError> {
        let id_js = JsValue::from(prekey_id);
        let result = call_js_async_method(&self.js_store, "loadPreKey", &[id_js]).await?;
        
        if result.is_null() || result.is_undefined() {
            Ok(None)
        } else {
            let prekey: PreKeyRecordStructure = from_value(result)
                .map_err(|e| format!("Failed to deserialize PreKeyRecordStructure: {}", e))?;
            Ok(Some(prekey))
        }
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        let id_js = JsValue::from(prekey_id);
        let record_js = to_value(&record)
            .map_err(|e| format!("Failed to serialize PreKeyRecordStructure: {}", e))?;
        
        call_js_async_method(&self.js_store, "storePreKey", &[id_js, record_js]).await?;
        Ok(())
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        let id_js = JsValue::from(prekey_id);
        let result = call_js_async_method(&self.js_store, "containsPreKey", &[id_js]).await?;
        let contains = result.as_bool().ok_or("Expected boolean")?;
        Ok(contains)
    }

    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
        let id_js = JsValue::from(prekey_id);
        call_js_async_method(&self.js_store, "removePreKey", &[id_js]).await?;
        Ok(())
    }
}

// Implement SignedPreKeyStore trait
#[async_trait]
impl SignedPreKeyStore for JsSignalStore {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        let id_js = JsValue::from(signed_prekey_id);
        let result = call_js_async_method(&self.js_store, "loadSignedPreKey", &[id_js]).await?;
        
        if result.is_null() || result.is_undefined() {
            Ok(None)
        } else {
            let signed_prekey: SignedPreKeyRecordStructure = from_value(result)
                .map_err(|e| format!("Failed to deserialize SignedPreKeyRecordStructure: {}", e))?;
            Ok(Some(signed_prekey))
        }
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        let result = call_js_async_method(&self.js_store, "loadSignedPreKeys", &[]).await?;
        let signed_prekeys: Vec<SignedPreKeyRecordStructure> = from_value(result)
            .map_err(|e| format!("Failed to deserialize SignedPreKeyRecordStructure vector: {}", e))?;
        Ok(signed_prekeys)
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        let id_js = JsValue::from(signed_prekey_id);
        let record_js = to_value(&record)
            .map_err(|e| format!("Failed to serialize SignedPreKeyRecordStructure: {}", e))?;
        
        call_js_async_method(&self.js_store, "storeSignedPreKey", &[id_js, record_js]).await?;
        Ok(())
    }

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError> {
        let id_js = JsValue::from(signed_prekey_id);
        let result = call_js_async_method(&self.js_store, "containsSignedPreKey", &[id_js]).await?;
        let contains = result.as_bool().ok_or("Expected boolean")?;
        Ok(contains)
    }

    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError> {
        let id_js = JsValue::from(signed_prekey_id);
        call_js_async_method(&self.js_store, "removeSignedPreKey", &[id_js]).await?;
        Ok(())
    }
}

// Implement SenderKeyStore trait
#[async_trait]
impl SenderKeyStore for JsSignalStore {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), StoreError> {
        let name_js = to_value(sender_key_name)
            .map_err(|e| format!("Failed to serialize SenderKeyName: {}", e))?;
        let record_js = to_value(&record)
            .map_err(|e| format!("Failed to serialize SenderKeyRecord: {}", e))?;
        
        call_js_async_method(&self.js_store, "storeSenderKey", &[name_js, record_js]).await?;
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, StoreError> {
        let name_js = to_value(sender_key_name)
            .map_err(|e| format!("Failed to serialize SenderKeyName: {}", e))?;
        
        let result = call_js_async_method(&self.js_store, "loadSenderKey", &[name_js]).await?;
        let record: SenderKeyRecord = from_value(result)
            .map_err(|e| format!("Failed to deserialize SenderKeyRecord: {}", e))?;
        Ok(record)
    }

    async fn delete_sender_key(&self, sender_key_name: &SenderKeyName) -> Result<(), StoreError> {
        let name_js = to_value(sender_key_name)
            .map_err(|e| format!("Failed to serialize SenderKeyName: {}", e))?;
        
        call_js_async_method(&self.js_store, "deleteSenderKey", &[name_js]).await?;
        Ok(())
    }
}

// Implement the main SignalProtocolStore trait
impl SignalProtocolStore for JsSignalStore {}