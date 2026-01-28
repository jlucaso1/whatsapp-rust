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
        public_key: Some(record.key_pair()?.public_key.public_key_bytes().to_vec()),
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
    use crate::protocol::{GenericSignedPreKey, KeyPair, PreKeyRecord};
    use rand::RngCore;

    #[test]
    fn test_prekey_serialization_length() -> Result<(), Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate(&mut rand::rng());
        let record = PreKeyRecord::new(1.into(), &key_pair);
        let structure = prekey_record_to_structure(&record)?;

        // DJB format is 32 bytes (no prefix byte)
        let pub_key = structure.public_key.clone().unwrap();
        assert_eq!(pub_key.len(), 32);

        Ok(())
    }

    #[test]
    fn test_prekey_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate(&mut rand::rng());
        let original_record = PreKeyRecord::new(42.into(), &key_pair);

        // Serialize to structure
        let structure = prekey_record_to_structure(&original_record)?;

        // Deserialize back to record
        let restored_record = prekey_structure_to_record(structure)?;

        // Verify round-trip integrity
        assert_eq!(original_record.id()?, restored_record.id()?);

        let original_keypair = original_record.key_pair()?;
        let restored_keypair = restored_record.key_pair()?;

        // Compare public keys (DJB format)
        assert_eq!(
            original_keypair.public_key.public_key_bytes(),
            restored_keypair.public_key.public_key_bytes()
        );

        // Compare private keys
        assert_eq!(
            original_keypair.private_key.serialize(),
            restored_keypair.private_key.serialize()
        );

        Ok(())
    }

    #[test]
    fn test_signed_prekey_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let key_pair = KeyPair::generate(&mut rand::rng());
        let mut signature = [0u8; 64];
        rand::rng().fill_bytes(&mut signature);
        let timestamp = chrono::Utc::now();
        let id = 123u32;

        // Create structure using new_signed_pre_key_record
        let structure = new_signed_pre_key_record(id, &key_pair, signature, timestamp);

        // Deserialize back to record
        let restored_record = signed_prekey_structure_to_record(structure)?;

        // Verify round-trip integrity
        assert_eq!(restored_record.id()?, id.into());

        let restored_keypair = restored_record.key_pair()?;

        // Compare public keys (DJB format)
        assert_eq!(
            key_pair.public_key.public_key_bytes(),
            restored_keypair.public_key.public_key_bytes()
        );

        // Compare private keys
        assert_eq!(
            key_pair.private_key.serialize(),
            restored_keypair.private_key.serialize()
        );

        // Compare signature
        assert_eq!(signature.to_vec(), restored_record.signature()?);

        Ok(())
    }
}
