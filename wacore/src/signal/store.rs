use async_trait::async_trait;
use libsignal_protocol::{IdentityKeyStore, ProtocolAddress, SenderKeyRecord, SessionRecord};
use std::error::Error;
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

use crate::types::jid::Jid;

type StoreError = Box<dyn Error + Send + Sync>;

#[async_trait(?Send)]
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

#[async_trait(?Send)]
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

#[async_trait(?Send)]
pub trait SessionStore: Send + Sync {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<SessionRecord, StoreError>;
    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError>;
    async fn store_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError>;
    async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool, StoreError>;
    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), StoreError>;
    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError>;
}

use anyhow::Result;

#[async_trait(?Send)]
pub trait GroupSenderKeyStore: Send + Sync {
    async fn store_sender_key(
        &mut self,
        group_id: &Jid,
        sender: &ProtocolAddress,
        record: &SenderKeyRecord,
    ) -> Result<()>;

    async fn load_sender_key(
        &self,
        group_id: &Jid,
        sender: &ProtocolAddress,
    ) -> Result<Option<SenderKeyRecord>>;
}

pub trait SignalProtocolStore:
    IdentityKeyStore + PreKeyStore + SignedPreKeyStore + SessionStore
{
}

impl<T: IdentityKeyStore + PreKeyStore + SignedPreKeyStore + SessionStore> SignalProtocolStore
    for T
{
}
