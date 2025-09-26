use crate::libsignal::protocol::{
    CiphertextMessageType, Direction, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, SenderKeyStore as LibsignalSenderKeyStore, SignalProtocolError,
};
use crate::libsignal::store::{PreKeyStore, SignedPreKeyStore};
use crate::store::traits::{
    AppStateKeyStore, AppStateStore, Backend, IdentityStore, SenderKeyStoreHelper, SessionStore,
};
use async_trait::async_trait;
use prost::Message;
use std::sync::Arc;
use wacore_binary::jid::{Jid, JidExt as _};
use waproto::whatsapp as wa;

#[derive(Clone, Message)]
pub struct DeviceSnapshot {
    #[prost(string, optional, tag = "1")]
    pub pn: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub lid: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub phone_id: Option<String>,
    #[prost(message, optional, tag = "4")]
    pub account: Option<wa::AdvSignedDeviceIdentity>,
    #[prost(uint32, optional, tag = "5")]
    pub registration_id: Option<u32>,
    #[prost(message, optional, tag = "6")]
    pub identity: Option<wa::IdentityKeyPairStructure>,
    #[prost(string, optional, tag = "7")]
    pub push_name: Option<String>,
    #[prost(message, optional, tag = "8")]
    pub app_version: Option<wa::client_payload::user_agent::AppVersion>,
    #[prost(int64, optional, tag = "9")]
    pub app_version_last_fetched_ms: Option<i64>,
}

pub struct Device {
    pub backend: Box<dyn Backend>,
    pub snapshot: DeviceSnapshot,
}

impl Device {
    pub fn new(backend: Box<dyn Backend>) -> Self {
        Self {
            backend,
            snapshot: DeviceSnapshot::default(),
        }
    }

    pub fn with_snapshot(backend: Box<dyn Backend>, snapshot: DeviceSnapshot) -> Self {
        Self { backend, snapshot }
    }

    pub fn set_jid(&mut self, jid: &Jid) {
        if jid.is_lid() {
            self.snapshot.lid = Some(jid.to_string());
        } else {
            self.snapshot.pn = Some(jid.to_string());
        }
    }

    pub fn set_identity(&mut self, identity: wa::IdentityKeyPairStructure) {
        self.snapshot.identity = Some(identity);
    }
    pub fn set_registration_id(&mut self, registration_id: u32) {
        self.snapshot.registration_id = Some(registration_id);
    }
}

#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(
        &self,
    ) -> std::result::Result<IdentityKeyPair, SignalProtocolError> {
        let key_pair_struct = self
            .snapshot
            .identity
            .as_ref()
            .ok_or(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::Whisper,
                "Missing identity key from device snapshot",
            ))?;
        let key_pair_bytes = key_pair_struct
            .private_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::Whisper,
                "Missing private key from identity key pair structure",
            ))?;
        IdentityKeyPair::from_bytes(key_pair_bytes)
    }

    async fn get_local_registration_id(&self) -> std::result::Result<u32, SignalProtocolError> {
        self.snapshot
            .registration_id
            .ok_or(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::Whisper,
                "Missing registration ID from device snapshot",
            ))
    }

    async fn save_identity(
        &mut self,
        address: &crate::libsignal::protocol::ProtocolAddress,
        identity_key: &IdentityKey,
    ) -> std::result::Result<IdentityChange, SignalProtocolError> {
        let existing_identity = self.get_identity(address).await?;

        self.backend
            .put_identity(&address.to_string(), *identity_key.public_key().as_ref())
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("save_identity".to_string(), e.to_string())
            })?;

        match existing_identity {
            None => Ok(IdentityChange::NewOrUnchanged),
            Some(existing) if &existing == identity_key => Ok(IdentityChange::NewOrUnchanged),
            Some(_) => Ok(IdentityChange::ReplacedExisting),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &crate::libsignal::protocol::ProtocolAddress,
        identity_key: &IdentityKey,
        direction: Direction,
    ) -> std::result::Result<bool, SignalProtocolError> {
        self.backend
            .is_trusted_identity(&address.to_string(), identity_key.public_key().as_ref(), direction)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("is_trusted_identity".to_string(), e.to_string())
            })
    }

    async fn get_identity(
        &self,
        address: &crate::libsignal::protocol::ProtocolAddress,
    ) -> std::result::Result<Option<IdentityKey>, SignalProtocolError> {
        match self
            .backend
            .load_identity(&address.to_string())
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("get_identity".to_string(), e.to_string())
            })? {
            Some(bytes) => Ok(Some(IdentityKey::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl PreKeyStore for Device {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<
        Option<wa::PreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.backend.load_prekey(prekey_id).await
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: wa::PreKeyRecordStructure,
        uploaded: bool,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.store_prekey(prekey_id, record, uploaded).await
    }

    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.contains_prekey(prekey_id).await
    }

    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.remove_prekey(prekey_id).await
    }
}

#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<
        Option<wa::SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.backend.load_signed_prekey(signed_prekey_id).await
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<
        Vec<wa::SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.backend.load_signed_prekeys().await
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: wa::SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.contains_signed_prekey(signed_prekey_id).await
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.remove_signed_prekey(signed_prekey_id).await
    }
}

#[async_trait]
impl LibsignalSenderKeyStore for Device {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &crate::libsignal::store::sender_key_name::SenderKeyName,
        record: &crate::libsignal::protocol::SenderKeyRecord,
    ) -> std::result::Result<(), crate::libsignal::protocol::SignalProtocolError> {
        self.backend
            .put_sender_key(&sender_key_name.to_string(), &record.serialize()?)
            .await
            .map_err(|e| {
                crate::libsignal::protocol::SignalProtocolError::InvalidState(
                    "put_sender_key".to_string(),
                    e.to_string(),
                )
            })
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &crate::libsignal::store::sender_key_name::SenderKeyName,
    ) -> std::result::Result<
        Option<crate::libsignal::protocol::SenderKeyRecord>,
        crate::libsignal::protocol::SignalProtocolError,
    > {
        match self
            .backend
            .get_sender_key(&sender_key_name.to_string())
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("get_sender_key".to_string(), e.to_string())
            })? {
            Some(bytes) => Ok(Some(
                crate::libsignal::protocol::SenderKeyRecord::deserialize(&bytes)?,
            )),
            None => Ok(None),
        }
    }
}

pub struct AppState {
    backend: Arc<dyn AppStateStore>,
}

impl AppState {
    pub fn new(backend: Arc<dyn AppStateStore>) -> Self {
        Self { backend }
    }
}

pub struct AppStateKeys {
    backend: Arc<dyn AppStateKeyStore>,
}

impl AppStateKeys {
    pub fn new(backend: Arc<dyn AppStateKeyStore>) -> Self {
        Self { backend }
    }
}