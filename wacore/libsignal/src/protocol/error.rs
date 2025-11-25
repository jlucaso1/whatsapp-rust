//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::panic::UnwindSafe;

use crate::{
    core::{
        ProtocolAddress,
        curve::{CurveError, KeyType},
    },
    protocol::CiphertextMessageType,
};
use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

#[derive(Debug, Display, Error)]
pub enum SignalProtocolError {
    /// invalid argument: {0}
    InvalidArgument(String),
    /// invalid state for call to {0} to succeed: {1}
    InvalidState(&'static str, String),

    /// protobuf encoding was invalid
    InvalidProtobufEncoding,

    /// ciphertext serialized bytes were too short <{0}>
    CiphertextMessageTooShort(usize),
    /// ciphertext version was too old <{0}>
    LegacyCiphertextVersion(u8),
    /// ciphertext version was unrecognized <{0}>
    UnrecognizedCiphertextVersion(u8),
    /// unrecognized message version <{0}>
    UnrecognizedMessageVersion(u32),

    /// fingerprint version number mismatch them {0} us {1}
    FingerprintVersionMismatch(u32, u32),
    /// fingerprint parsing error
    FingerprintParsingError,

    /// no key type identifier
    NoKeyTypeIdentifier,
    /// bad key type <{0:#04x}>
    BadKeyType(u8),
    /// bad key length <{1}> for key with type <{0}>
    BadKeyLength(KeyType, usize),

    /// invalid signature detected
    SignatureValidationFailed,

    /// untrusted identity for address {0}
    UntrustedIdentity(ProtocolAddress),

    /// invalid prekey identifier
    InvalidPreKeyId,
    /// invalid signed prekey identifier
    InvalidSignedPreKeyId,

    /// invalid MAC key length <{0}>
    InvalidMacKeyLength(usize),

    /// no sender key state: {0}
    NoSenderKeyState(String),

    /// session with {0} not found
    SessionNotFound(ProtocolAddress),
    /// invalid session: {0}
    InvalidSessionStructure(&'static str),
    /// invalid sender key session
    InvalidSenderKeySession,
    /// session for {0} has invalid registration ID {1:X}
    InvalidRegistrationId(ProtocolAddress, u32),

    /// message with old counter {0} / {1}
    DuplicatedMessage(u32, u32),
    /// invalid {0:?} message: {1}
    InvalidMessage(CiphertextMessageType, &'static str),

    /// error while invoking an ffi callback: {0}
    FfiBindingError(String),
    /// error in method call '{0}': {1}
    ApplicationCallbackError(
        &'static str,
        #[source] Box<dyn std::error::Error + Send + Sync + UnwindSafe + 'static>,
    ),

    /// invalid sealed sender message: {0}
    InvalidSealedSenderMessage(String),
    /// unknown sealed sender message version {0}
    UnknownSealedSenderVersion(u8),
    /// self send of a sealed sender message
    SealedSenderSelfSend,
}

impl SignalProtocolError {
    /// Convenience factory for [`SignalProtocolError::ApplicationCallbackError`].
    #[inline]
    pub fn for_application_callback<E: std::error::Error + Send + Sync + UnwindSafe + 'static>(
        method: &'static str,
    ) -> impl FnOnce(E) -> Self {
        move |error| Self::ApplicationCallbackError(method, Box::new(error))
    }
}

impl From<CurveError> for SignalProtocolError {
    fn from(e: CurveError) -> Self {
        match e {
            CurveError::NoKeyTypeIdentifier => Self::NoKeyTypeIdentifier,
            CurveError::BadKeyType(raw) => Self::BadKeyType(raw),
            CurveError::BadKeyLength(key_type, len) => Self::BadKeyLength(key_type, len),
        }
    }
}
