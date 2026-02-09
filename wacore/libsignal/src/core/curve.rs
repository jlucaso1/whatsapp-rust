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
    /// Returns the byte value used in serialized key format.
    pub fn value(&self) -> u8 {
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
use curve25519_dalek::scalar::Scalar;
use std::sync::OnceLock;

/// Cached data for XEdDSA signing.
/// This avoids an expensive scalar multiplication on every signature
/// and caches the scalar representation to avoid repeated modular reduction.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct EdwardsCacheData {
    /// Cached scalar representation of the private key
    scalar: Scalar,
    ed_public_key: CompressedEdwardsY,
    sign_bit: u8,
}

/// Stores the private key bytes with lazy-initialized cached values for XEdDSA signing.
/// The Edwards public key is computed on first signature, not at key creation.
/// This keeps key generation fast while subsequent signatures benefit from caching.
#[derive(Debug, Clone)]
enum PrivateKeyData {
    DjbPrivateKey {
        /// The raw 32-byte private key
        key: [u8; curve25519::PRIVATE_KEY_LENGTH],
        /// Lazily-initialized Edwards cache (computed on first signature)
        edwards_cache: OnceLock<EdwardsCacheData>,
    },
}

impl PartialEq for PrivateKeyData {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                PrivateKeyData::DjbPrivateKey { key: k1, .. },
                PrivateKeyData::DjbPrivateKey { key: k2, .. },
            ) => k1.ct_eq(k2).into(),
        }
    }
}

impl Eq for PrivateKeyData {}

#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl From<PrivateKeyData> for PrivateKey {
    fn from(key: PrivateKeyData) -> Self {
        Self { key }
    }
}

impl PrivateKey {
    /// Lazily computes and caches the signing data (scalar + Edwards public key).
    #[inline]
    fn get_edwards_cache(&self) -> &EdwardsCacheData {
        match &self.key {
            PrivateKeyData::DjbPrivateKey { key, edwards_cache } => {
                edwards_cache.get_or_init(|| {
                    let temp = curve25519::PrivateKey::from(*key);
                    EdwardsCacheData {
                        scalar: temp.cached_scalar(),
                        ed_public_key: temp.cached_ed_public_key(),
                        sign_bit: temp.cached_sign_bit(),
                    }
                })
            }
        }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self, CurveError> {
        if value.len() != curve25519::PRIVATE_KEY_LENGTH {
            Err(CurveError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut key = [0u8; curve25519::PRIVATE_KEY_LENGTH];
            key.copy_from_slice(&value[..curve25519::PRIVATE_KEY_LENGTH]);
            // Clamping is not necessary but is kept for backward compatibility
            key = scalar::clamp_integer(key);
            // Edwards cache will be computed lazily on first signature
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey {
                    key,
                    edwards_cache: OnceLock::new(),
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
            PrivateKeyData::DjbPrivateKey { key, .. } => {
                // For public key derivation, we need the X25519 public key, not Edwards
                // Use from_bytes_without_cache since we don't need the Edwards cache
                let private_key = curve25519::PrivateKey::from_bytes_without_cache(*key);
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
            PrivateKeyData::DjbPrivateKey { key, .. } => {
                let cache = self.get_edwards_cache();
                let private_key = curve25519::PrivateKey::from_bytes_with_cache(
                    *key,
                    cache.scalar,
                    cache.ed_public_key,
                    cache.sign_bit,
                );
                Ok(private_key.calculate_signature(csprng, message))
            }
        }
    }

    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<[u8; 32], CurveError> {
        match (&self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey { key, .. }, PublicKeyData::DjbPublicKey(pub_key)) => {
                // Use from_bytes_without_cache since agreement doesn't need the Edwards cache
                let private_key = curve25519::PrivateKey::from_bytes_without_cache(*key);
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

#[derive(Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        // Generate key WITHOUT computing Edwards cache (lazy initialization).
        // The Edwards point computation is deferred until first signature.
        let temp = curve25519::PrivateKey::new_without_cache(csprng);
        let key = temp.private_key_bytes();

        let public_key =
            PublicKey::from(PublicKeyData::DjbPublicKey(temp.derive_public_key_bytes()));
        // Edwards cache will be computed lazily on first signature
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey {
            key,
            edwards_cache: OnceLock::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> impl rand::CryptoRng + rand::Rng {
        rand::rng()
    }

    #[test]
    fn test_signature_with_lazy_cache() {
        let mut csprng = rng();

        // Generate key with lazy cache (no Edwards computation yet)
        let keypair = KeyPair::generate(&mut csprng);
        let message = b"Test message for signature";

        // First signature should compute and cache Edwards point
        let signature1 = keypair
            .calculate_signature(message, &mut csprng)
            .expect("signature 1");

        // Verify signature is valid
        assert!(keypair.public_key.verify_signature(message, &signature1));

        // Second signature should use cached Edwards point
        let signature2 = keypair
            .calculate_signature(message, &mut csprng)
            .expect("signature 2");

        // Both signatures should verify (may differ due to random nonce)
        assert!(keypair.public_key.verify_signature(message, &signature2));
    }

    #[test]
    fn test_signature_consistency_after_serialization() {
        let mut csprng = rng();

        // Generate key and sign
        let keypair = KeyPair::generate(&mut csprng);
        let message = b"Test message";
        let signature = keypair
            .calculate_signature(message, &mut csprng)
            .expect("signature");

        // Serialize and deserialize private key
        let serialized = keypair.private_key.serialize();
        let restored_private = PrivateKey::deserialize(serialized).expect("deserialize");

        // Sign again with restored key (should have fresh lazy cache)
        let signature2 = restored_private
            .calculate_signature(message, &mut csprng)
            .expect("signature 2");

        // Both signatures should verify against original public key
        assert!(keypair.public_key.verify_signature(message, &signature));
        assert!(keypair.public_key.verify_signature(message, &signature2));
    }

    #[test]
    fn test_cloned_key_signatures() {
        let mut csprng = rng();

        let keypair = KeyPair::generate(&mut csprng);
        let message = b"Clone test message";

        // First signature initializes cache
        let sig1 = keypair
            .calculate_signature(message, &mut csprng)
            .expect("sig1");

        // Clone the keypair
        let cloned = keypair.clone();

        // Cloned key should also produce valid signatures
        let sig2 = cloned
            .calculate_signature(message, &mut csprng)
            .expect("sig2");

        // Both should verify
        assert!(keypair.public_key.verify_signature(message, &sig1));
        assert!(cloned.public_key.verify_signature(message, &sig2));
        assert!(keypair.public_key.verify_signature(message, &sig2));
    }

    #[test]
    fn test_multiple_signatures_same_key() {
        let mut csprng = rng();

        let keypair = KeyPair::generate(&mut csprng);

        // Sign many messages
        for i in 0..100 {
            let message = format!("Message number {}", i);
            let signature = keypair
                .calculate_signature(message.as_bytes(), &mut csprng)
                .expect("signature");

            // Each signature should verify
            assert!(
                keypair
                    .public_key
                    .verify_signature(message.as_bytes(), &signature),
                "Signature {} failed to verify",
                i
            );
        }
    }

    #[test]
    fn test_key_agreement_works_without_signing() {
        let mut csprng = rng();

        // Create two keypairs
        let alice = KeyPair::generate(&mut csprng);
        let bob = KeyPair::generate(&mut csprng);

        // Key agreement should work without ever signing (no Edwards cache needed)
        let alice_shared = alice
            .calculate_agreement(&bob.public_key)
            .expect("alice agreement");
        let bob_shared = bob
            .calculate_agreement(&alice.public_key)
            .expect("bob agreement");

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_public_key_derivation_without_signing() {
        let mut csprng = rng();

        let keypair = KeyPair::generate(&mut csprng);

        // Public key should be derivable without signing (no Edwards cache needed)
        let derived_public = keypair.private_key.public_key().expect("public key");

        // Should match the original public key
        assert_eq!(derived_public, keypair.public_key);
    }

    #[test]
    fn test_signature_sign_bit_preserved() {
        let mut csprng = rng();

        // Generate many keys and verify sign bit handling
        for _ in 0..20 {
            let keypair = KeyPair::generate(&mut csprng);
            let message = b"Sign bit test";

            let signature = keypair
                .calculate_signature(message, &mut csprng)
                .expect("signature");

            // Signature should be exactly 64 bytes
            assert_eq!(signature.len(), 64);

            // The sign bit is encoded in the MSB of the last byte
            // Verify the signature is valid (which tests that sign bit is correct)
            assert!(keypair.public_key.verify_signature(message, &signature));
        }
    }

    #[test]
    fn test_multipart_signature() {
        let mut csprng = rng();

        let keypair = KeyPair::generate(&mut csprng);

        // Sign a multipart message
        let part1 = b"Hello, ";
        let part2 = b"World!";

        let signature = keypair
            .private_key
            .calculate_signature_for_multipart_message(&[part1, part2], &mut csprng)
            .expect("multipart signature");

        // Verify with concatenated message
        let full_message = [&part1[..], &part2[..]].concat();
        assert!(
            keypair
                .public_key
                .verify_signature(&full_message, &signature)
        );

        // Also verify with multipart verification
        assert!(
            keypair
                .public_key
                .verify_signature_for_multipart_message(&[part1, part2], &signature)
        );
    }
}
