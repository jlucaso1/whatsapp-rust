//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use arrayref::array_ref;

use crate::protocol::{PrivateKey, PublicKey, Result, crypto, stores::session_structure};

pub enum MessageKeyGenerator {
    Keys(MessageKeys),
    Seed((Vec<u8>, u32)),
}

impl MessageKeyGenerator {
    pub fn new_from_seed(seed: &[u8], counter: u32) -> Self {
        Self::Seed((seed.to_vec(), counter))
    }
    pub fn generate_keys(self) -> MessageKeys {
        match self {
            Self::Seed((seed, counter)) => MessageKeys::derive_keys(&seed, None, counter),
            Self::Keys(k) => k,
        }
    }
    pub fn into_pb(self) -> session_structure::chain::MessageKey {
        match self {
            Self::Keys(k) => session_structure::chain::MessageKey {
                cipher_key: k.cipher_key().to_vec(),
                mac_key: k.mac_key().to_vec(),
                iv: k.iv().to_vec(),
                index: k.counter(),
                seed: vec![],
            },
            Self::Seed((seed, counter)) => session_structure::chain::MessageKey {
                cipher_key: vec![],
                mac_key: vec![],
                iv: vec![],
                index: counter,
                seed,
            },
        }
    }
    pub fn from_pb(
        pb: session_structure::chain::MessageKey,
    ) -> std::result::Result<Self, &'static str> {
        Ok(if pb.seed.is_empty() {
            Self::Keys(MessageKeys {
                cipher_key: pb
                    .cipher_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid message cipher key")?,
                mac_key: pb
                    .mac_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid message MAC key")?,
                iv: pb
                    .iv
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid message IV")?,
                counter: pb.index,
            })
        } else {
            Self::Seed((pb.seed, pb.index))
        })
    }
}

#[derive(Clone, Copy)]
pub struct MessageKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
    counter: u32,
}

impl MessageKeys {
    pub fn derive_keys(
        input_key_material: &[u8],
        optional_salt: Option<&[u8]>,
        counter: u32,
    ) -> Self {
        let mut okm = [0; 80];
        hkdf::Hkdf::<sha2::Sha256>::new(optional_salt, input_key_material)
            .expand(b"WhisperMessageKeys", &mut okm)
            .expect("valid output length");

        MessageKeys {
            cipher_key: *array_ref![okm, 0, 32],
            mac_key: *array_ref![okm, 32, 32],
            iv: *array_ref![okm, 64, 16],
            counter,
        }
    }

    #[inline]
    pub fn cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    #[inline]
    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    #[inline]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

#[derive(Clone, Debug)]
pub struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8];

    pub fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    #[inline]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn next_chain_key(&self) -> Self {
        Self {
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    pub fn message_keys(&self) -> MessageKeyGenerator {
        MessageKeyGenerator::new_from_seed(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.index,
        )
    }

    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; 32] {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

#[derive(Clone, Debug)]
pub struct RootKey {
    key: [u8; 32],
}

impl RootKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn create_chain(
        self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &PrivateKey,
    ) -> Result<(RootKey, ChainKey)> {
        let shared_secret = our_ratchet_key.calculate_agreement(their_ratchet_key)?;
        let mut derived_secret_bytes = [0; 64];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.key), &shared_secret)
            .expand(b"WhisperRatchet", &mut derived_secret_bytes)
            .expect("valid output length");

        Ok((
            RootKey {
                key: *array_ref![derived_secret_bytes, 0, 32],
            },
            ChainKey {
                key: *array_ref![derived_secret_bytes, 32, 32],
                index: 0,
            },
        ))
    }
}

impl fmt::Display for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.key))
    }
}
