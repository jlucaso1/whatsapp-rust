//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod curve25519;
mod utils;

use std::cmp::Ordering;
use std::fmt;

use curve25519_dalek::scalar;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    Djb,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Djb => 0x05u8,
        }
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum CurveError {
    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(KeyType, usize),
}

impl std::error::Error for CurveError {}

impl TryFrom<u8> for KeyType {
    type Error = CurveError;

    fn try_from(x: u8) -> Result<Self, CurveError> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            t => Err(CurveError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    DjbPublicKey([u8; curve25519::PUBLIC_KEY_LENGTH]),
}

#[derive(Clone, Copy, Eq, derive_more::From)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        if value.is_empty() {
            return Err(CurveError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        match key_type {
            KeyType::Djb => {
                // We allow trailing data after the public key (why?)
                if value.len() < curve25519::PUBLIC_KEY_LENGTH + 1 {
                    return Err(CurveError::BadKeyLength(KeyType::Djb, value.len()));
                }
                let mut key = [0u8; curve25519::PUBLIC_KEY_LENGTH];
                key.copy_from_slice(&value[1..][..curve25519::PUBLIC_KEY_LENGTH]);
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(key),
                })
            }
        }
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => v,
        }
    }

    pub fn from_djb_public_key_bytes(bytes: &[u8]) -> Result<Self, CurveError> {
        match <[u8; curve25519::PUBLIC_KEY_LENGTH]>::try_from(bytes) {
            Err(_) => Err(CurveError::BadKeyLength(KeyType::Djb, bytes.len())),
            Ok(key) => Ok(PublicKey {
                key: PublicKeyData::DjbPublicKey(key),
            }),
        }
    }

    /// Serialize the public key to a fixed-size array (1 type byte + 32 key bytes).
    pub fn serialize(&self) -> [u8; 33] {
        let mut result = [0u8; 33];
        result[0] = self.key_type().value();
        match &self.key {
            PublicKeyData::DjbPublicKey(v) => result[1..].copy_from_slice(v),
        }
        result
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_signature_for_multipart_message(&[message], signature)
    }

    pub fn verify_signature_for_multipart_message(
        &self,
        message: &[&[u8]],
        signature: &[u8],
    ) -> bool {
        match &self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
                let Ok(signature) = signature.try_into() else {
                    return false;
                };
                curve25519::PrivateKey::verify_signature(pub_key, message, signature)
            }
        }
    }

    fn key_data(&self) -> &[u8] {
        match &self.key {
            PublicKeyData::DjbPublicKey(k) => k.as_ref(),
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
        }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }

        utils::constant_time_cmp(self.key_data(), other.key_data())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

use curve25519_dalek::edwards::CompressedEdwardsY;

/// Stores the private key bytes along with cached values for XEdDSA signing.
/// The cached Edwards public key avoids an expensive scalar multiplication on every signature.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateKeyData {
    DjbPrivateKey {
        /// The raw 32-byte private key
        key: [u8; curve25519::PRIVATE_KEY_LENGTH],
        /// Cached compressed Edwards public key (avoids scalar mult per signature)
        ed_public_key: CompressedEdwardsY,
        /// Cached sign bit from Edwards public key
        sign_bit: u8,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl From<PrivateKeyData> for PrivateKey {
    fn from(key: PrivateKeyData) -> Self {
        Self { key }
    }
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        if value.len() != curve25519::PRIVATE_KEY_LENGTH {
            Err(CurveError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut key = [0u8; curve25519::PRIVATE_KEY_LENGTH];
            key.copy_from_slice(&value[..curve25519::PRIVATE_KEY_LENGTH]);
            // Clamping is not necessary but is kept for backward compatibility
            key = scalar::clamp_integer(key);
            // Create a temporary PrivateKey to compute and cache the Ed public key
            let temp = curve25519::PrivateKey::from(key);
            let ed_public_key = temp.cached_ed_public_key();
            let sign_bit = temp.cached_sign_bit();
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey {
                    key,
                    ed_public_key,
                    sign_bit,
                },
            })
        }
    }

    pub fn serialize(&self) -> &[u8; 32] {
        match &self.key {
            PrivateKeyData::DjbPrivateKey { key, .. } => key,
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, CurveError> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey {
                key,
                ed_public_key,
                sign_bit,
            } => {
                // Reconstruct with cached values (no scalar mult)
                let private_key =
                    curve25519::PrivateKey::from_bytes_with_cache(*key, *ed_public_key, *sign_bit);
                let public_key = private_key.derive_public_key_bytes();
                Ok(PublicKey::new(PublicKeyData::DjbPublicKey(public_key)))
            }
        }
    }

    pub fn key_type(&self) -> KeyType {
        match &self.key {
            PrivateKeyData::DjbPrivateKey { .. } => KeyType::Djb,
        }
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<[u8; 64], CurveError> {
        self.calculate_signature_for_multipart_message(&[message], csprng)
    }

    pub fn calculate_signature_for_multipart_message<R: CryptoRng + Rng>(
        &self,
        message: &[&[u8]],
        csprng: &mut R,
    ) -> Result<[u8; 64], CurveError> {
        match &self.key {
            PrivateKeyData::DjbPrivateKey {
                key,
                ed_public_key,
                sign_bit,
            } => {
                // Reconstruct with cached values (no scalar mult)
                let private_key =
                    curve25519::PrivateKey::from_bytes_with_cache(*key, *ed_public_key, *sign_bit);
                Ok(private_key.calculate_signature(csprng, message))
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<[u8; 32], CurveError> {
        match (&self.key, their_key.key) {
            (
                PrivateKeyData::DjbPrivateKey {
                    key,
                    ed_public_key,
                    sign_bit,
                },
                PublicKeyData::DjbPublicKey(pub_key),
            ) => {
                // Reconstruct with cached values (no scalar mult)
                let private_key =
                    curve25519::PrivateKey::from_bytes_with_cache(*key, *ed_public_key, *sign_bit);
                Ok(private_key.calculate_agreement(&pub_key))
            }
        }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = CurveError;

    fn try_from(value: &[u8]) -> Result<Self, CurveError> {
        Self::deserialize(value)
    }
}

#[derive(Copy, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let temp = curve25519::PrivateKey::new(csprng);
        let key = temp.private_key_bytes();
        let ed_public_key = temp.cached_ed_public_key();
        let sign_bit = temp.cached_sign_bit();

        let public_key =
            PublicKey::from(PublicKeyData::DjbPublicKey(temp.derive_public_key_bytes()));
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey {
            key,
            ed_public_key,
            sign_bit,
        });

        Self {
            public_key,
            private_key,
        }
    }

    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub fn from_public_and_private(
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Self, CurveError> {
        let public_key = PublicKey::try_from(public_key)?;
        let private_key = PrivateKey::try_from(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<[u8; 64], CurveError> {
        self.private_key.calculate_signature(message, csprng)
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<[u8; 32], CurveError> {
        self.private_key.calculate_agreement(their_key)
    }
}

impl TryFrom<PrivateKey> for KeyPair {
    type Error = CurveError;

    fn try_from(value: PrivateKey) -> Result<Self, CurveError> {
        let public_key = value.public_key()?;
        Ok(Self::new(public_key, value))
    }
}
