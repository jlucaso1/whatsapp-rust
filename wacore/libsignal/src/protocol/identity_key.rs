//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Wrappers over cryptographic primitives from [`libsignal_core::curve`] to represent a user.

#![warn(missing_docs)]

use prost::Message;
use rand::{CryptoRng, Rng};

use crate::protocol::{
    KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError, stores::IdentityKeyPairStructure,
};

// Used for domain separation between alternate-identity signatures and other key-to-key signatures.
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1: &[u8] = &[0xFF; 32];
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2: &[u8] = b"Signal_PNI_Signature";

/// A public key that represents the identity of a user.
///
/// Wrapper for [`PublicKey`].
#[derive(
    Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, derive_more::From, derive_more::Into,
)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    /// Initialize a public-facing identity from a public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Return the public key representing this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Serialize the identity key to a fixed-size array (1 type byte + 32 key bytes).
    #[inline]
    pub fn serialize(&self) -> [u8; 33] {
        self.public_key.serialize()
    }

    /// Deserialize a public identity from a byte slice.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::try_from(value)?;
        Ok(Self { public_key: pk })
    }

    /// Given a trusted identity `self`, verify that `other` represents an alternate identity for
    /// this user.
    ///
    /// `signature` must be calculated from [`IdentityKeyPair::sign_alternate_identity`].
    pub fn verify_alternate_identity(&self, other: &IdentityKey, signature: &[u8]) -> Result<bool> {
        Ok(self.public_key.verify_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            signature,
        ))
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

/// The private identity of a user.
///
/// Can be converted to and from [`KeyPair`].
#[derive(Clone)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: PrivateKey,
}

impl IdentityKeyPair {
    /// Create a key pair from a public `identity_key` and a private `private_key`.
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    /// Generate a random new identity from randomness in `csprng`.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
        }
    }

    /// Return the public identity of this user.
    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Return the public key that defines this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        self.identity_key.public_key()
    }

    /// Return the private key that defines this identity.
    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Return a byte slice which can later be deserialized with [`Self::try_from`].
    pub fn serialize(&self) -> Box<[u8]> {
        let structure = IdentityKeyPairStructure {
            public_key: Some(self.identity_key.serialize().to_vec()),
            private_key: Some(self.private_key.serialize().to_vec()),
        };

        let result = structure.encode_to_vec();
        result.into_boxed_slice()
    }

    /// Generate a signature claiming that `other` represents the same user as `self`.
    pub fn sign_alternate_identity<R: Rng + CryptoRng>(
        &self,
        other: &IdentityKey,
        rng: &mut R,
    ) -> Result<[u8; 64]> {
        Ok(self.private_key.calculate_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            rng,
        )?)
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = IdentityKeyPairStructure::decode(value)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(
                structure
                    .public_key
                    .as_ref()
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
                    .as_slice(),
            )?,
            private_key: PrivateKey::deserialize(
                structure
                    .private_key
                    .as_ref()
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?,
            )?,
        })
    }
}

impl TryFrom<PrivateKey> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(private_key: PrivateKey) -> Result<Self> {
        let identity_key = IdentityKey::new(private_key.public_key()?);
        Ok(Self::new(identity_key, private_key))
    }
}

impl From<KeyPair> for IdentityKeyPair {
    fn from(value: KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.private_key,
        }
    }
}

impl From<IdentityKeyPair> for KeyPair {
    fn from(value: IdentityKeyPair) -> Self {
        Self::new(value.identity_key.into(), value.private_key)
    }
}
