use super::key_pair::EcKeyPair;
use super::keys::{DJB_TYPE, DjbEcPrivateKey, DjbEcPublicKey, EcPrivateKey, EcPublicKey};
use crate::crypto::xed25519;
use rand::rngs::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret, x25519};

#[derive(Debug, Error)]
pub enum CurveError {
    #[error("bad key type: {0}")]
    BadKeyType(u8),
}

// Corresponds to GenerateKeyPair()
pub fn generate_key_pair() -> EcKeyPair {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    EcKeyPair::new(
        DjbEcPublicKey::new(*public.as_bytes()),
        DjbEcPrivateKey::new(private.to_bytes()),
    )
}

// Corresponds to DecodePoint()
pub fn decode_point(bytes: &[u8]) -> Result<DjbEcPublicKey, CurveError> {
    if bytes.is_empty() {
        return Err(CurveError::BadKeyType(0));
    }
    let key_type = bytes[0];
    if key_type != DJB_TYPE {
        return Err(CurveError::BadKeyType(key_type));
    }
    let key_bytes: [u8; 32] = bytes[1..]
        .try_into()
        .map_err(|_| CurveError::BadKeyType(key_type))?;
    Ok(DjbEcPublicKey::new(key_bytes))
}

// Corresponds to CalculateSignature()
pub fn calculate_signature(signing_key: DjbEcPrivateKey, message: &[u8]) -> [u8; 64] {
    xed25519::sign(&signing_key.serialize(), message)
}

// Corresponds to VerifySignature()
pub fn verify_signature(signing_key: DjbEcPublicKey, message: &[u8], signature: &[u8; 64]) -> bool {
    xed25519::verify(&signing_key.public_key(), message, signature)
}

// Corresponds to kdf.CalculateSharedSecret()
pub fn calculate_shared_secret(our_private_key: [u8; 32], their_public_key: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(our_private_key);
    x25519(secret.to_bytes(), their_public_key)
}
