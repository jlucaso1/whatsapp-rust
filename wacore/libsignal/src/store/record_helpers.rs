use crate::protocol::{
    KeyPair, PreKeyRecord, PrivateKey, PublicKey, SignalProtocolError, SignedPreKeyRecord,
    Timestamp,
};
use chrono::Utc;
use waproto::whatsapp as wa;

pub fn new_pre_key_record(id: u32, key_pair: &KeyPair) -> wa::PreKeyRecordStructure {
    wa::PreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize().to_vec()),
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
        private_key: Some(key_pair.private_key.serialize().to_vec()),
        signature: Some(signature.to_vec()),
        timestamp: Some(
            timestamp
                .timestamp()
                .try_into()
                .expect("Timestamp conversion failed"),
        ),
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
        public_key: Some(record.key_pair()?.public_key.serialize().to_vec()),
        private_key: Some(record.key_pair()?.private_key.serialize().to_vec()),
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
        <SignedPreKeyRecord as crate::protocol::GenericSignedPreKey>::new(
            id, timestamp, &key_pair, signature,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::KeyPair;
    use crate::protocol::PreKeyRecord;

    #[test]
    fn test_prekey_serialization_length() -> Result<(), Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate(&mut rand::rng());
        let record = PreKeyRecord::new(1.into(), &key_pair);
        let structure = prekey_record_to_structure(&record)?;

        // WhatsApp Web expects 33 bytes for the public key (prefix 0x05 + 32 byte key)
        let pub_key = structure.public_key.clone().unwrap();
        assert_eq!(pub_key.len(), 33);
        assert_eq!(pub_key[0], 0x05);

        Ok(())
    }
}
