use libsignal_protocol::{PrivateKey, PublicKey};
use rand::{TryRngCore, rngs::OsRng};
use std::convert::TryInto;

pub fn sign(private_key_bytes: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let libsignal_private_key = PrivateKey::deserialize(private_key_bytes)
        .expect("wacore::crypto::xed25519::sign: Failed to create libsignal PrivateKey from bytes");

    let rng = OsRng;

    let signature_box = libsignal_private_key
        .calculate_signature(message, &mut rng.unwrap_err())
        .expect("wacore::crypto::xed25519::sign: libsignal failed to calculate signature");

    signature_box
        .as_ref()
        .try_into()
        .expect("wacore::crypto::xed25519::sign: libsignal signature was not 64 bytes long")
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    if let Ok(libsignal_public_key) = PublicKey::from_djb_public_key_bytes(public_key) {
        libsignal_public_key.verify_signature(message, signature)
    } else {
        false
    }
}
