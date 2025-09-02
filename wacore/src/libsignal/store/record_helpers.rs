use crate::libsignal::protocol::{
    KeyPair, PreKeyRecord, PrivateKey, PublicKey, SignalProtocolError, SignedPreKeyRecord,
    Timestamp,
};
use chrono::Utc;
use waproto::whatsapp as wa;

pub fn new_pre_key_record(id: u32, key_pair: &KeyPair) -> wa::PreKeyRecordStructure {
    wa::PreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize()),
    }
}

pub fn new_signed_pre_key_record(
    id: u32,
    key_pair: &KeyPair,
    signature: [u8; 64],
    timestamp: chrono::DateTime<Utc>,
) -> wa::SignedPreKeyRecordStructure {
    wa::SignedPreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize()),
        signature: Some(signature.to_vec()),
        timestamp: Some(timestamp.timestamp().try_into().unwrap()),
    }
}

pub fn prekey_structure_to_record(
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

pub fn prekey_record_to_structure(
    record: &PreKeyRecord,
) -> Result<wa::PreKeyRecordStructure, SignalProtocolError> {
    Ok(wa::PreKeyRecordStructure {
        id: Some(record.id()?.into()),
        public_key: Some(record.key_pair()?.public_key.public_key_bytes()[1..].to_vec()),
        private_key: Some(record.key_pair()?.private_key.serialize()),
    })
}

pub fn signed_prekey_structure_to_record(
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
    Ok(
        <SignedPreKeyRecord as crate::libsignal::protocol::GenericSignedPreKey>::new(
            id, timestamp, &key_pair, signature,
        ),
    )
}
