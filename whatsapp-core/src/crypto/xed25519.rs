// SPDX-FileCopyrightText: 2023 Dominik George <nik@naturalnet.de>
// SPDX-FileCopyrightText: 2024 Tulir Asokan
//
// SPDX-License-Identifier: Apache-2.0
//
// This file is a consolidated and simplified version of the `xeddsa` crate,
// vendored for use within this project to provide XEd25519 signing and verification.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::TryRngCore;
use sha2::{Digest, Sha512};

// Internal struct to organize methods, not exposed publicly.
struct PrivateKey([u8; 32]);

impl PrivateKey {
    /// Calculates the EdDSA-compatible key pair from an X25519 private key.
    /// This is the core of XEdDSA, handling the potential negation to match the sign bit.
    fn calculate_key_pair(&self, sign: u8) -> ([u8; 32], [u8; 32]) {
        let clamped = clamp_integer(self.0);
        let scalar_private_key = Scalar::from_bytes_mod_order(clamped);
        let point_public_key = EdwardsPoint::mul_base(&scalar_private_key);

        if (point_public_key.compress().to_bytes()[31] & 0x80) >> 7 == sign {
            (clamped, point_public_key.compress().to_bytes())
        } else {
            let negated_scalar = (Scalar::ZERO - Scalar::from(1_u8)) * scalar_private_key;
            let negated_point = EdwardsPoint::mul_base(&negated_scalar);
            (
                negated_scalar.to_bytes(),
                negated_point.compress().to_bytes(),
            )
        }
    }
}

/// Signs a message using the XEd25519 algorithm.
///
/// # Arguments
/// * `private_key` - A 32-byte X25519 private key.
/// * `message` - The message to be signed.
///
/// # Returns
/// A 64-byte XEdDSA signature.
pub fn sign(private_key_bytes: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let private_key = PrivateKey(*private_key_bytes);
    let (ed25519_private, ed25519_public) = private_key.calculate_key_pair(0);

    let mut nonce = [0u8; 64];
    rand::rngs::OsRng.try_fill_bytes(&mut nonce).unwrap();

    let padding: [u8; 32] = hash_i_padding(1);
    let mut hasher = Sha512::new();
    hasher.update(padding);
    hasher.update(ed25519_private);
    hasher.update(message);
    hasher.update(nonce);
    let res: [u8; 64] = hasher.finalize().into();

    let res_scalar = Scalar::from_bytes_mod_order_wide(&res);
    let r_point = EdwardsPoint::mul_base(&res_scalar);

    let mut hasher = Sha512::new();
    hasher.update(r_point.compress().to_bytes());
    hasher.update(ed25519_public);
    hasher.update(message);
    let hash: [u8; 64] = hasher.finalize().into();

    let hash_scalar = Scalar::from_bytes_mod_order_wide(&hash);
    let private_scalar = Scalar::from_bytes_mod_order(ed25519_private);
    let s_scalar = res_scalar + hash_scalar * private_scalar;

    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&r_point.compress().to_bytes());
    signature[32..64].copy_from_slice(&s_scalar.to_bytes());

    signature
}

/// Verifies an XEd25519 signature.
///
/// # Arguments
/// * `public_key` - A 32-byte X25519 (Montgomery curve) public key.
/// * `message` - The message that was signed.
/// * `signature` - The 64-byte signature to verify.
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let sign_bit = (signature[63] & 0x80) >> 7;

    // Convert the Montgomery public key to an Edwards public key using the sign bit.
    let edwards_point = match MontgomeryPoint(*public_key).to_edwards(sign_bit) {
        Some(p) => p,
        None => return false,
    };
    let ed25519_public_key_bytes = edwards_point.compress().to_bytes();

    let verifying_key = match VerifyingKey::from_bytes(&ed25519_public_key_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // Clear the sign bit from a copy of the signature.
    let mut cleaned_signature_bytes = *signature;
    cleaned_signature_bytes[63] &= 0x7F;
    let cleaned_signature = Signature::from_bytes(&cleaned_signature_bytes);

    // Verify the message against the cleaned signature.
    verifying_key.verify(message, &cleaned_signature).is_ok()
}

/// Internal helper: Generate padding bytes for the `hash_i` function.
const fn hash_i_padding<const S: usize>(i: u128) -> [u8; S] {
    let mut padding: [u8; S] = [0xffu8; S];
    let slice = (u128::MAX - i).to_le_bytes();
    let mut idx = 0;
    while idx < slice.len() {
        padding[idx] = slice[idx];
        idx += 1
    }
    padding
}
