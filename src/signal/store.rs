use crate::proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};
use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::state::sender_key_record::SenderKeyRecord;

// src/signal/store.rs
use super::address::SignalAddress;
use super::identity::{IdentityKey, IdentityKeyPair};
use super::state::session_record::SessionRecord;
use async_trait::async_trait;
use std::error::Error;

// Using a generic error for now. In a real app, this would be a custom store error enum.
type StoreError = Box<dyn Error + Send + Sync>;

// Corresponds to state/store/IdentityKeyStore.go
#[async_trait]
pub trait IdentityKeyStore: Send + Sync {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError>;
    async fn get_local_registration_id(&self) -> Result<u32, StoreError>;
    async fn save_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), StoreError>;
    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, StoreError>;
}

// Corresponds to state/store/PreKeyStore.go
#[async_trait]
pub trait PreKeyStore: Send + Sync {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, StoreError>;
    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), StoreError>;
    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError>;
    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError>;
}

// Corresponds to state/store/SignedPreKeyStore.go
#[async_trait]
pub trait SignedPreKeyStore: Send + Sync {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError>;
    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError>;
    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError>;
    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError>;
    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError>;
}

// Corresponds to state/store/SessionStore.go
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn load_session(&self, address: &SignalAddress) -> Result<SessionRecord, StoreError>;
    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError>;
    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError>;
    async fn contains_session(&self, address: &SignalAddress) -> Result<bool, StoreError>;
    async fn delete_session(&self, address: &SignalAddress) -> Result<(), StoreError>;
    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError>;
}

#[async_trait]
pub trait SenderKeyStore: Send + Sync {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), StoreError>;
    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, StoreError>;
}

// Corresponds to state/store/SignalProtocolStore.go
pub trait SignalProtocolStore:
    IdentityKeyStore + PreKeyStore + SignedPreKeyStore + SessionStore
{
}

// Blanket implementation
impl<T: IdentityKeyStore + PreKeyStore + SignedPreKeyStore + SessionStore> SignalProtocolStore
    for T
{
}
