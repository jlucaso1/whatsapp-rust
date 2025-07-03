use super::chain_key::ChainKey;
use super::ecc::curve::calculate_shared_secret;
use super::ecc::key_pair::EcKeyPair;
use super::ecc::keys::EcPublicKey;
use super::kdf;
use std::sync::Arc;
use thiserror::Error;

const DERIVED_SECRETS_SIZE: usize = 64;
const KDF_INFO: &str = "WhisperRatchet";

#[derive(Debug, Error)]
pub enum RootKeyError {
    #[error("KDF error: {0}")]
    Kdf(#[from] kdf::KdfError),
}

// Corresponds to keys/root/RootKey.go
#[derive(Clone, Debug)]
pub struct RootKey {
    key: [u8; 32],
}

// Corresponds to keys/session/Pair.go
pub struct SessionKeyPair {
    pub root_key: RootKey,
    pub chain_key: ChainKey,
}

// Corresponds to keys/session/DerivedSecrets.go
struct DerivedSecrets {
    root_key: [u8; 32],
    chain_key: [u8; 32],
}

impl RootKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    pub fn create_chain(
        &self,
        their_ratchet_key: Arc<dyn EcPublicKey>,
        our_ratchet_key: &EcKeyPair,
    ) -> Result<SessionKeyPair, RootKeyError> {
        let their_public_key = their_ratchet_key.public_key();
        let our_private_key = our_ratchet_key.private_key.serialize();

        let shared_secret = calculate_shared_secret(our_private_key, their_public_key);

        let derived_secret_bytes = kdf::derive_secrets(
            &shared_secret,
            Some(&self.key),
            KDF_INFO.as_bytes(),
            DERIVED_SECRETS_SIZE,
        )?;

        let derived = DerivedSecrets {
            root_key: derived_secret_bytes[0..32].try_into().unwrap(),
            chain_key: derived_secret_bytes[32..64].try_into().unwrap(),
        };

        let new_root_key = RootKey::new(derived.root_key);
        let new_chain_key = ChainKey::new(derived.chain_key, 0);

        Ok(SessionKeyPair {
            root_key: new_root_key,
            chain_key: new_chain_key,
        })
    }
}
