use crate::store::Device;
use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord,
    PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, SessionRecord, SessionStore,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use waproto::whatsapp as wa;

use wacore::signal::store::{
    PreKeyStore as WacorePreKeyStore, SignedPreKeyStore as WacoreSignedPreKeyStore,
};

#[derive(Clone)]
struct SharedDevice {
    device: Arc<Mutex<Device>>,
}

#[derive(Clone)]
pub struct SessionAdapter(SharedDevice);
#[derive(Clone)]
pub struct IdentityAdapter(SharedDevice);
#[derive(Clone)]
pub struct PreKeyAdapter(SharedDevice);
#[derive(Clone)]
pub struct SignedPreKeyAdapter(SharedDevice);
#[derive(Clone)]
#[allow(dead_code)]
pub struct KyberPreKeyAdapter(SharedDevice);

#[derive(Clone)]
pub struct SignalProtocolStoreAdapter {
    pub session_store: SessionAdapter,
    pub identity_store: IdentityAdapter,
    pub pre_key_store: PreKeyAdapter,
    pub signed_pre_key_store: SignedPreKeyAdapter,
    pub kyber_pre_key_store: KyberPreKeyAdapter,
}

impl SignalProtocolStoreAdapter {
    pub fn new(device: Arc<Mutex<Device>>) -> Self {
        let shared = SharedDevice { device };
        Self {
            session_store: SessionAdapter(shared.clone()),
            identity_store: IdentityAdapter(shared.clone()),
            pre_key_store: PreKeyAdapter(shared.clone()),
            signed_pre_key_store: SignedPreKeyAdapter(shared.clone()),
            kyber_pre_key_store: KyberPreKeyAdapter(shared),
        }
    }
}

#[async_trait(?Send)]
impl SessionStore for SessionAdapter {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let device = self.0.device.lock().await;
        let wacore_address = ProtocolAddress::new(address.name().to_string(), address.device_id());
        match device
            .backend
            .get_session(&wacore_address.to_string())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
        {
            Some(data) => Ok(Some(SessionRecord::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let device = self.0.device.lock().await;
        let wacore_address = ProtocolAddress::new(address.name().to_string(), address.device_id());
        let record_bytes = record.serialize()?;
        device
            .backend
            .put_session(&wacore_address.to_string(), &record_bytes)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for IdentityAdapter {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let device = self.0.device.lock().await;
        IdentityKeyStore::get_identity_key_pair(&*device)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("get_identity_key_pair", e.to_string()))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let device = self.0.device.lock().await;
        IdentityKeyStore::get_local_registration_id(&*device)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("get_local_registration_id", e.to_string())
            })
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing_identity = self.get_identity(address).await?;

        let mut device = self.0.device.lock().await;
        IdentityKeyStore::save_identity(&mut*device, address, identity)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("save_identity", e.to_string()))?;

        match existing_identity {
            None => Ok(IdentityChange::NewOrUnchanged),
            Some(existing) if &existing == identity => Ok(IdentityChange::NewOrUnchanged),
            Some(_) => Ok(IdentityChange::ReplacedExisting),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let device = self.0.device.lock().await;
        IdentityKeyStore::is_trusted_identity(&*device, address, identity, direction)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("is_trusted_identity", e.to_string()))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let device = self.0.device.lock().await;
        IdentityKeyStore::get_identity(&*device, address)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("get_identity", e.to_string()))
    }
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeyAdapter {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let device = self.0.device.lock().await;
        WacorePreKeyStore::load_prekey(&*device, prekey_id.into())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
            .ok_or(SignalProtocolError::InvalidPreKeyId)
            .and_then(prekey_structure_to_record)
    }
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let device = self.0.device.lock().await;
        let structure = prekey_record_to_structure(record)?;
        WacorePreKeyStore::store_prekey(&*device, prekey_id.into(), structure)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let device = self.0.device.lock().await;
        WacorePreKeyStore::remove_prekey(&*device, prekey_id.into())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeyAdapter {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let device = self.0.device.lock().await;
        WacoreSignedPreKeyStore::load_signed_prekey(&*device, signed_prekey_id.into())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
            .and_then(signed_prekey_structure_to_record)
    }
    async fn save_signed_pre_key(
        &mut self,
        _id: SignedPreKeyId,
        _record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeyAdapter {
    async fn get_kyber_pre_key(
        &self,
        _id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        Err(SignalProtocolError::InvalidState(
            "get_kyber_pre_key",
            "Unimplemented".into(),
        ))
    }
    async fn save_kyber_pre_key(
        &mut self,
        _id: KyberPreKeyId,
        _record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Err(SignalProtocolError::InvalidState(
            "save_kyber_pre_key",
            "Unimplemented".into(),
        ))
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        _id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        Err(SignalProtocolError::InvalidState(
            "mark_kyber_pre_key_used",
            "Unimplemented".into(),
        ))
    }
}

fn prekey_structure_to_record(
    structure: wa::PreKeyRecordStructure,
) -> Result<PreKeyRecord, SignalProtocolError> {
    let id = structure.id.unwrap_or(0).into();
    let public_key = PublicKey::from_djb_public_key_bytes(
        structure
            .public_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .as_slice(),
    )?;
    let private_key = PrivateKey::deserialize(
        structure
            .private_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
    )?;
    Ok(PreKeyRecord::new(
        id,
        &KeyPair::new(public_key, private_key),
    ))
}

fn prekey_record_to_structure(
    record: &PreKeyRecord,
) -> Result<wa::PreKeyRecordStructure, SignalProtocolError> {
    Ok(wa::PreKeyRecordStructure {
        id: Some(record.id()?.into()),
        public_key: Some(record.key_pair()?.public_key.public_key_bytes()[1..].to_vec()),
        private_key: Some(record.key_pair()?.private_key.serialize()),
    })
}

fn signed_prekey_structure_to_record(
    structure: wa::SignedPreKeyRecordStructure,
) -> Result<SignedPreKeyRecord, SignalProtocolError> {
    let id = structure.id.unwrap_or(0).into();
    let public_key = PublicKey::from_djb_public_key_bytes(
        structure
            .public_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .as_slice(),
    )?;
    let private_key = PrivateKey::deserialize(
        structure
            .private_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
    )?;
    let key_pair = KeyPair::new(public_key, private_key);
    let signature = structure
        .signature
        .as_ref()
        .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
    let timestamp = Timestamp::from_epoch_millis(structure.timestamp.unwrap_or(0));
    Ok(SignedPreKeyRecord::new(id, timestamp, &key_pair, signature))
}
