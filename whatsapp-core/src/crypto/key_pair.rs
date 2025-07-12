use crate::crypto::xed25519;
use ed25519_dalek::Signature;
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum KeyPairError {}

/// The DJB type constant from `go.mau.fi/libsignal/ecc.DjbType`
const DJB_TYPE: u8 = 5;

/// An X25519 key pair for cryptographic operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl KeyPair {
    /// Generates a new random X25519 key pair.
    pub fn new() -> Self {
        let mut p_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut p_bytes).expect("RNG failure");
        let private = StaticSecret::from(p_bytes);
        let public = PublicKey::from(&private);
        Self {
            public_key: *public.as_bytes(),
            private_key: private.to_bytes(),
        }
    }

    /// Creates a key pair from an existing 32-byte private key.
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let private = StaticSecret::from(private_key);
        let public = PublicKey::from(&private);
        Self {
            public_key: *public.as_bytes(),
            private_key: private.to_bytes(),
        }
    }

    /// Signs the public key of another KeyPair using this KeyPair's private key.
    /// The message to be signed is constructed by prepending the DJB type byte (0x05)
    /// to the public key, matching the Signal protocol's requirements.
    pub fn sign(&self, key_to_sign: &KeyPair) -> Signature {
        let mut message = [0u8; 33];
        message[0] = DJB_TYPE;
        message[1..].copy_from_slice(&key_to_sign.public_key);

        self.sign_message(&message)
    }

    /// Signs an arbitrary byte slice using this KeyPair's private key via the XEd25519 scheme.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let signature_bytes = xed25519::sign(&self.private_key, message);
        Signature::from_bytes(&signature_bytes)
    }

    /// Creates a new `PreKey` and signs its public key with this `KeyPair`.
    pub fn create_signed_prekey(&self, key_id: u32) -> Result<PreKey, KeyPairError> {
        let new_key = PreKey::new(key_id);
        let signature = self.sign(&new_key.key_pair);
        Ok(PreKey {
            signature: Some(signature.to_bytes()),
            ..new_key
        })
    }
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// A pre-key used in the Signal protocol handshake, with an optional signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKey {
    pub key_pair: KeyPair,
    pub key_id: u32,
    #[serde(with = "serde_bytes")]
    pub signature: Option<[u8; 64]>,
}

impl PreKey {
    /// Creates a new `PreKey` with a new `KeyPair` and the given ID.
    pub fn new(key_id: u32) -> Self {
        Self {
            key_pair: KeyPair::new(),
            key_id,
            signature: None,
        }
    }
}
