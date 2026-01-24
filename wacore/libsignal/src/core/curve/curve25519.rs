//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
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

/// Sentinel value for `sign_bit` indicating the Edwards cache was not initialized.
/// Valid sign_bit values are only 0x00 or 0x80 (the MSB of the compressed Edwards Y coordinate).
/// Using 0xFF as an invalid sentinel allows `calculate_signature` to detect and panic
/// instead of silently producing invalid signatures.
const SIGN_BIT_NOT_INITIALIZED: u8 = 0xFF;

/// XEdDSA hash prefix as per the specification.
/// This is 0xFE followed by 31 bytes of 0xFF.
/// See: https://signal.org/docs/specifications/xeddsa/#xeddsa
static XEDDSA_HASH_PREFIX: [u8; 32] = [
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

#[derive(Clone)]
pub struct PrivateKey {
    secret: StaticSecret,
    /// Cached scalar representation of the private key for signing.
    /// Avoids `from_bytes_mod_order` on every signature.
    scalar: Scalar,
    /// Cached Edwards public key (compressed form) derived from the X25519 key.
    /// Caching this avoids an expensive scalar multiplication on every signature.
    /// See: https://signal.org/docs/specifications/xeddsa/#curve25519
    ed_public_key: CompressedEdwardsY,
    /// Cached sign bit from the Edwards public key, used in signature encoding.
    sign_bit: u8,
}

impl PrivateKey {
    /// Computes the cached scalar, Edwards public key, and sign bit from a StaticSecret.
    #[inline]
    fn compute_edwards_cache(secret: &StaticSecret) -> (Scalar, CompressedEdwardsY, u8) {
        let key_data = secret.to_bytes();
        let scalar = Scalar::from_bytes_mod_order(key_data);
        let ed_public_key_point = &scalar * ED25519_BASEPOINT_TABLE;
        let ed_public_key = ed_public_key_point.compress();
        let sign_bit = ed_public_key.as_bytes()[31] & 0b1000_0000_u8;
        (scalar, ed_public_key, sign_bit)
    }

    /// Generates a new random private key with eagerly-computed Edwards cache.
    /// Use this when you plan to sign immediately after key creation.
    /// For lazy initialization, use `new_without_cache()` with a higher-level wrapper.
    #[allow(dead_code)]
    pub fn new<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + Rng,
    {
        // This is essentially StaticSecret::random_from_rng only with clamping
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        bytes = scalar::clamp_integer(bytes);

        let secret = StaticSecret::from(bytes);
        let (scalar, ed_public_key, sign_bit) = Self::compute_edwards_cache(&secret);
        PrivateKey {
            secret,
            scalar,
            ed_public_key,
            sign_bit,
        }
    }

    /// Generates a new random private key WITHOUT computing the Edwards cache.
    ///
    /// This skips the expensive scalar multiplication required for XEdDSA signing.
    /// Use this when the key will be wrapped in a higher-level type with lazy
    /// initialization (e.g., `curve::PrivateKey` with `OnceLock`).
    ///
    /// # Panics
    ///
    /// Calling `calculate_signature` on a key created with this function will panic.
    #[inline]
    pub(super) fn new_without_cache<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + Rng,
    {
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        bytes = scalar::clamp_integer(bytes);

        let secret = StaticSecret::from(bytes);
        // Sentinel values - calculate_signature will panic if called
        PrivateKey {
            secret,
            scalar: Scalar::ZERO,
            ed_public_key: CompressedEdwardsY::default(),
            sign_bit: SIGN_BIT_NOT_INITIALIZED,
        }
    }

    /// Creates a PrivateKey from raw bytes with ALL pre-computed cached values.
    /// This is the most efficient constructor - avoids scalar multiplication AND
    /// scalar modular reduction when all cached values are already available.
    #[inline]
    pub fn from_bytes_with_cache(
        private_key: [u8; PRIVATE_KEY_LENGTH],
        scalar: Scalar,
        ed_public_key: CompressedEdwardsY,
        sign_bit: u8,
    ) -> Self {
        let secret = StaticSecret::from(scalar::clamp_integer(private_key));
        PrivateKey {
            secret,
            scalar,
            ed_public_key,
            // Mask to ensure only valid sign bit values (0x00 or 0x80)
            sign_bit: sign_bit & 0b1000_0000_u8,
        }
    }

    /// Returns the cached Edwards public key.
    #[inline]
    pub fn cached_ed_public_key(&self) -> CompressedEdwardsY {
        self.ed_public_key
    }

    /// Returns the cached sign bit.
    #[inline]
    pub fn cached_sign_bit(&self) -> u8 {
        self.sign_bit
    }

    /// Returns the cached scalar representation.
    #[inline]
    pub fn cached_scalar(&self) -> Scalar {
        self.scalar
    }

    /// Creates a PrivateKey from raw bytes WITHOUT computing the Edwards cache.
    ///
    /// Use this for operations that don't need signatures (key agreement, public key
    /// derivation). Use `from_bytes_with_cache` if you need signing.
    ///
    /// # Panics
    ///
    /// Calling `calculate_signature` on a key created with this function will panic.
    #[inline]
    pub(super) fn from_bytes_without_cache(private_key: [u8; PRIVATE_KEY_LENGTH]) -> Self {
        let secret = StaticSecret::from(scalar::clamp_integer(private_key));
        // Sentinel values - calculate_signature will panic if called
        PrivateKey {
            secret,
            scalar: Scalar::ZERO,
            ed_public_key: CompressedEdwardsY::default(),
            sign_bit: SIGN_BIT_NOT_INITIALIZED,
        }
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
    ///
    /// Performance: This implementation caches the Edwards public key point to avoid
    /// the expensive scalar multiplication on every signature (roughly 2x speedup).
    ///
    /// # Panics
    ///
    /// Panics if the key was created with `new_without_cache` or `from_bytes_without_cache`.
    /// These constructors skip Edwards cache computation for performance; use
    /// `from_bytes_with_cache` or the higher-level `curve::PrivateKey` API instead.
    pub fn calculate_signature<R>(
        &self,
        csprng: &mut R,
        message: &[&[u8]],
    ) -> [u8; SIGNATURE_LENGTH]
    where
        R: CryptoRng + Rng,
    {
        assert!(
            self.sign_bit != SIGN_BIT_NOT_INITIALIZED,
            "cannot sign with a PrivateKey created via new_without_cache or from_bytes_without_cache; \
             use from_bytes_with_cache or the higher-level curve::PrivateKey API"
        );

        let mut random_bytes = [0u8; 64];
        csprng.fill_bytes(&mut random_bytes);

        let key_data = self.secret.to_bytes();

        // hash1 = SHA512(prefix || privKey || message || random)
        let mut hash1 = Sha512::new();
        hash1.update(&XEDDSA_HASH_PREFIX[..]);
        hash1.update(&key_data[..]);
        for message_piece in message {
            hash1.update(message_piece);
        }
        hash1.update(&random_bytes[..]);

        let r = Scalar::from_hash(hash1);
        let cap_r = (&r * ED25519_BASEPOINT_TABLE).compress();

        // hash = SHA512(R || edPubKey || message)
        let mut hash = Sha512::new();
        hash.update(cap_r.as_bytes());
        hash.update(self.ed_public_key.as_bytes());
        for message_piece in message {
            hash.update(message_piece);
        }

        let h = Scalar::from_hash(hash);
        let s = (h * self.scalar) + r;

        let mut result = [0u8; SIGNATURE_LENGTH];
        result[..32].copy_from_slice(cap_r.as_bytes());
        result[32..].copy_from_slice(s.as_bytes());
        result[SIGNATURE_LENGTH - 1] &= 0b0111_1111_u8;
        result[SIGNATURE_LENGTH - 1] |= self.sign_bit;
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
        let (scalar, ed_public_key, sign_bit) = Self::compute_edwards_cache(&secret);
        PrivateKey {
            secret,
            scalar,
            ed_public_key,
            sign_bit,
        }
    }
}
