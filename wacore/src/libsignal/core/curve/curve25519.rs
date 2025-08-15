//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

const AGREEMENT_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;

#[derive(Clone)]
pub struct PrivateKey {
    secret: StaticSecret,
}

impl PrivateKey {
    pub fn new<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + Rng,
    {
        // This is essentially StaticSecret::random_from_rng only with clamping
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        bytes = scalar::clamp_integer(bytes);

        let secret = StaticSecret::from(bytes);
        PrivateKey { secret }
    }

    pub fn calculate_agreement(
        &self,
        their_public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> [u8; AGREEMENT_LENGTH] {
        *self
            .secret
            .diffie_hellman(&PublicKey::from(*their_public_key))
            .as_bytes()
    }

    /// Calculates an XEdDSA signature using the X25519 private key directly.
    ///
    /// Refer to <https://signal.org/docs/specifications/xeddsa/#curve25519> for more details.
    ///
    /// Note that this implementation varies slightly from that paper in that the sign bit is not
    /// fixed to 0, but rather passed back in the most significant bit of the signature which would
    /// otherwise always be 0. This is for compatibility with the implementation found in
    /// libsignal-protocol-java.
    pub fn calculate_signature<R>(
        &self,
        csprng: &mut R,
        message: &[&[u8]],
    ) -> [u8; SIGNATURE_LENGTH]
    where
        R: CryptoRng + Rng,
    {
        let mut random_bytes = [0u8; 64];
        csprng.fill_bytes(&mut random_bytes);

        let key_data = self.secret.to_bytes();
        let a = Scalar::from_bytes_mod_order(key_data);
        let ed_public_key_point = &a * ED25519_BASEPOINT_TABLE;
        let ed_public_key = ed_public_key_point.compress();
        let sign_bit = ed_public_key.as_bytes()[31] & 0b1000_0000_u8;

        let mut hash1 = Sha512::new();
        let hash_prefix = [
            0xFEu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ];
        // Explicitly pass a slice to avoid generating multiple versions of update().
        hash1.update(&hash_prefix[..]);
        hash1.update(&key_data[..]);
        for message_piece in message {
            hash1.update(message_piece);
        }
        hash1.update(&random_bytes[..]);

        let r = Scalar::from_hash(hash1);
        let cap_r = (&r * ED25519_BASEPOINT_TABLE).compress();

        let mut hash = Sha512::new();
        hash.update(cap_r.as_bytes());
        hash.update(ed_public_key.as_bytes());
        for message_piece in message {
            hash.update(message_piece);
        }

        let h = Scalar::from_hash(hash);
        let s = (h * a) + r;

        let mut result = [0u8; SIGNATURE_LENGTH];
        result[..32].copy_from_slice(cap_r.as_bytes());
        result[32..].copy_from_slice(s.as_bytes());
        result[SIGNATURE_LENGTH - 1] &= 0b0111_1111_u8;
        result[SIGNATURE_LENGTH - 1] |= sign_bit;
        result
    }

    pub fn verify_signature(
        their_public_key: &[u8; PUBLIC_KEY_LENGTH],
        message: &[&[u8]],
        signature: &[u8; SIGNATURE_LENGTH],
    ) -> bool {
        let mont_point = MontgomeryPoint(*their_public_key);
        let ed_pub_key_point =
            match mont_point.to_edwards((signature[SIGNATURE_LENGTH - 1] & 0b1000_0000_u8) >> 7) {
                Some(x) => x,
                None => return false,
            };
        let cap_a = ed_pub_key_point.compress();
        let mut cap_r = [0u8; 32];
        cap_r.copy_from_slice(&signature[..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);
        s[31] &= 0b0111_1111_u8;
        if (s[31] & 0b1110_0000_u8) != 0 {
            return false;
        }
        let minus_cap_a = -ed_pub_key_point;

        let mut hash = Sha512::new();
        // Explicitly pass a slice to avoid generating multiple versions of update().
        hash.update(&cap_r[..]);
        hash.update(cap_a.as_bytes());
        for message_piece in message {
            hash.update(message_piece);
        }
        let h = Scalar::from_hash(hash);

        let cap_r_check_point = EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &h,
            &minus_cap_a,
            &Scalar::from_bytes_mod_order(s),
        );
        let cap_r_check = cap_r_check_point.compress();

        bool::from(cap_r_check.as_bytes().ct_eq(&cap_r))
    }

    pub fn derive_public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    pub fn private_key_bytes(&self) -> [u8; PRIVATE_KEY_LENGTH] {
        self.secret.to_bytes()
    }
}

impl From<[u8; PRIVATE_KEY_LENGTH]> for PrivateKey {
    fn from(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(scalar::clamp_integer(private_key));
        PrivateKey { secret }
    }
}
