//! Pair code authentication for phone number linking.
//!
//! This module implements the alternative device linking protocol used when
//! users enter an 8-character code on their phone instead of scanning a QR code.
//!
//! ## Protocol Overview
//!
//! 1. **Stage 1 (companion_hello)**: Client generates a code and sends encrypted
//!    ephemeral public key to server. Server returns a pairing ref.
//!
//! 2. **Stage 2 (companion_finish)**: When user enters code on phone, server
//!    sends notification with primary's ephemeral key. Client performs DH and
//!    sends encrypted key bundle.
//!
//! ## Cryptography
//!
//! - Code: 5 random bytes → Crockford Base32 → 8 characters
//! - Key derivation: PBKDF2-SHA256 with 131,072 iterations
//! - Ephemeral encryption: AES-256-CTR
//! - Bundle encryption: AES-256-GCM after HKDF key derivation

use crate::StringEnum;
use crate::libsignal::protocol::{KeyPair, PublicKey};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use ctr::Ctr128BE;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::SERVER_JID;
use wacore_binary::node::{Node, NodeContent};

// Type aliases
type Aes256Ctr = Ctr128BE<aes::Aes256>;

/// PBKDF2 iterations for pair code key derivation.
/// Matches WhatsApp Web's implementation (2^17 = 131,072).
const PAIR_CODE_PBKDF2_ITERATIONS: u32 = 131_072;

/// Salt size for PBKDF2 key derivation.
const PAIR_CODE_SALT_SIZE: usize = 32;

/// IV size for AES-CTR encryption.
const PAIR_CODE_IV_SIZE: usize = 16;

/// Crockford Base32 alphabet used for pair codes.
/// Excludes 0, I, O, U to prevent visual confusion.
const CROCKFORD_ALPHABET: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";

/// Validity duration for pair codes (approximately).
const PAIR_CODE_VALIDITY_SECS: u64 = 180;

/// Platform identifiers for companion devices.
/// These match the DeviceProps.PlatformType protobuf enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
#[repr(u8)]
pub enum PlatformId {
    #[str = "0"]
    Unknown = 0,
    #[string_default]
    #[str = "1"]
    Chrome = 1,
    #[str = "2"]
    Firefox = 2,
    #[str = "3"]
    InternetExplorer = 3,
    #[str = "4"]
    Opera = 4,
    #[str = "5"]
    Safari = 5,
    #[str = "6"]
    Edge = 6,
    #[str = "7"]
    Electron = 7,
    #[str = "8"]
    Uwp = 8,
    #[str = "9"]
    OtherWebClient = 9,
}

/// Options for pair code authentication.
#[derive(Debug, Clone)]
pub struct PairCodeOptions {
    /// Phone number with country code, no leading zeros or special chars (e.g., "15551234567").
    pub phone_number: String,
    /// Whether to show push notification on phone (default: true).
    pub show_push_notification: bool,
    /// Custom pairing code (8 chars from Crockford alphabet, or None for random).
    pub custom_code: Option<String>,
    /// Platform identifier for companion device.
    pub platform_id: PlatformId,
    /// Platform display name (e.g., "Chrome (Linux)").
    pub platform_display: String,
}

impl Default for PairCodeOptions {
    fn default() -> Self {
        Self {
            phone_number: String::new(),
            show_push_notification: true,
            custom_code: None,
            platform_id: PlatformId::Chrome,
            platform_display: "Chrome (Linux)".to_string(),
        }
    }
}

/// State machine for pair code authentication flow.
#[derive(Default)]
pub enum PairCodeState {
    /// Initial state - no pair code request in progress.
    #[default]
    Idle,
    /// Stage 1 complete - waiting for phone to confirm code entry.
    WaitingForPhoneConfirmation {
        /// Reference returned by server in stage 1.
        pairing_ref: Vec<u8>,
        /// Phone number JID (without @s.whatsapp.net).
        phone_jid: String,
        /// The 8-character pair code (needed to decrypt primary's ephemeral key).
        pair_code: String,
        /// Ephemeral keypair generated for this session.
        ephemeral_keypair: Box<KeyPair>,
    },
    /// Pairing completed (success or failure).
    Completed,
}

impl std::fmt::Debug for PairCodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::WaitingForPhoneConfirmation { phone_jid, .. } => f
                .debug_struct("WaitingForPhoneConfirmation")
                .field("phone_jid", phone_jid)
                .finish_non_exhaustive(),
            Self::Completed => write!(f, "Completed"),
        }
    }
}

/// Core pair code cryptographic utilities.
///
/// All operations are platform-independent and can be used in `no_std` environments.
pub struct PairCodeUtils;

impl PairCodeUtils {
    /// Generates a random 8-character pair code using Crockford Base32.
    ///
    /// The code consists of characters from `123456789ABCDEFGHJKLMNPQRSTVWXYZ`,
    /// which excludes 0, I, O, and U to prevent visual confusion.
    pub fn generate_code() -> String {
        let mut bytes = [0u8; 5];
        rand::rng().fill(&mut bytes);
        Self::encode_crockford(&bytes)
    }

    /// Validates a custom pair code.
    ///
    /// Returns `true` if the code is exactly 8 characters and all characters
    /// are from the Crockford Base32 alphabet.
    pub fn validate_code(code: &str) -> bool {
        code.len() == 8
            && code
                .bytes()
                .all(|b| CROCKFORD_ALPHABET.contains(&b.to_ascii_uppercase()))
    }

    /// Encodes 5 bytes to an 8-character Crockford Base32 string.
    ///
    /// 5 bytes = 40 bits = 8 × 5-bit groups, each mapped to the alphabet.
    fn encode_crockford(bytes: &[u8; 5]) -> String {
        // Combine 5 bytes into a 40-bit value
        let mut accumulator: u64 = 0;
        for &byte in bytes {
            accumulator = (accumulator << 8) | u64::from(byte);
        }

        // Extract 8 × 5-bit groups
        let mut result = String::with_capacity(8);
        for i in (0..8).rev() {
            let index = ((accumulator >> (i * 5)) & 0x1F) as usize;
            result.push(CROCKFORD_ALPHABET[index] as char);
        }
        result
    }

    /// Derives an encryption key from a pair code using PBKDF2-SHA256.
    ///
    /// This is a blocking operation (~100ms on modern hardware due to 131,072 iterations).
    /// Consider wrapping in `spawn_blocking` for async contexts.
    pub fn derive_key(code: &str, salt: &[u8; PAIR_CODE_SALT_SIZE]) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(code.as_bytes(), salt, PAIR_CODE_PBKDF2_ITERATIONS, &mut key);
        key
    }

    /// Encrypts the companion ephemeral public key for stage 1.
    ///
    /// Returns the wrapped ephemeral data: `salt (32) || iv (16) || ciphertext (32)` = 80 bytes.
    pub fn encrypt_ephemeral_pub(ephemeral_pub: &[u8; 32], code: &str) -> [u8; 80] {
        // Generate random salt and IV
        let mut salt = [0u8; PAIR_CODE_SALT_SIZE];
        let mut iv = [0u8; PAIR_CODE_IV_SIZE];
        rand::rng().fill(&mut salt);
        rand::rng().fill(&mut iv);

        // Derive key from code and encrypt with AES-256-CTR
        let key = Self::derive_key(code, &salt);
        let mut cipher = Aes256Ctr::new(&key.into(), &iv.into());
        let mut ciphertext = *ephemeral_pub;
        cipher.apply_keystream(&mut ciphertext);

        // Concatenate: salt (32) || iv (16) || ciphertext (32) = 80 bytes
        let mut result = [0u8; 80];
        result[..32].copy_from_slice(&salt);
        result[32..48].copy_from_slice(&iv);
        result[48..80].copy_from_slice(&ciphertext);

        result
    }

    /// Decrypts the primary device's ephemeral public key received in stage 2.
    ///
    /// The wrapped data format is: `salt (32) || iv (16) || ciphertext (32)` = 80 bytes.
    ///
    /// # Important
    ///
    /// This function extracts the salt from the wrapped data and derives a fresh
    /// encryption key using PBKDF2 with the pair code. This is necessary because
    /// the primary device encrypts with their own random salt.
    pub fn decrypt_primary_ephemeral_pub(
        wrapped: &[u8],
        pair_code: &str,
    ) -> Result<[u8; 32], PairCodeError> {
        if wrapped.len() != 80 {
            return Err(PairCodeError::InvalidWrappedData {
                expected: 80,
                got: wrapped.len(),
            });
        }

        // Extract salt, iv, and ciphertext (length validated above guarantees these succeed)
        let salt: [u8; PAIR_CODE_SALT_SIZE] = wrapped[0..32]
            .try_into()
            .expect("salt slice is exactly 32 bytes");
        let iv: [u8; PAIR_CODE_IV_SIZE] = wrapped[32..48]
            .try_into()
            .expect("iv slice is exactly 16 bytes");
        let mut plaintext: [u8; 32] = wrapped[48..80]
            .try_into()
            .expect("ciphertext slice is exactly 32 bytes");

        // Derive key using the PRIMARY's salt
        let derived_key = Self::derive_key(pair_code, &salt);

        // Decrypt with AES-256-CTR
        let mut cipher = Aes256Ctr::new((&derived_key).into(), &iv.into());
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }

    /// Builds the stage 1 (companion_hello) IQ node.
    pub fn build_companion_hello_iq(
        phone_number: &str,
        noise_static_pub: &[u8; 32],
        wrapped_ephemeral: &[u8; 80],
        platform_id: PlatformId,
        platform_display: &str,
        show_push_notification: bool,
        req_id: String,
    ) -> Node {
        let link_code_reg = NodeBuilder::new("link_code_companion_reg")
            .attrs([
                ("jid", format!("{}@s.whatsapp.net", phone_number)),
                ("stage", "companion_hello".to_string()),
                (
                    "should_show_push_notification",
                    show_push_notification.to_string(),
                ),
            ])
            .children([
                NodeBuilder::new("link_code_pairing_wrapped_companion_ephemeral_pub")
                    .bytes(wrapped_ephemeral.to_vec())
                    .build(),
                NodeBuilder::new("companion_server_auth_key_pub")
                    .bytes(noise_static_pub.to_vec())
                    .build(),
                NodeBuilder::new("companion_platform_id")
                    .bytes(platform_id.as_str().as_bytes().to_vec())
                    .build(),
                NodeBuilder::new("companion_platform_display")
                    .bytes(platform_display.as_bytes().to_vec())
                    .build(),
                // Nonce is sent as string "0" (matching whatsmeow/baileys)
                NodeBuilder::new("link_code_pairing_nonce")
                    .bytes(b"0".to_vec())
                    .build(),
            ])
            .build();

        NodeBuilder::new("iq")
            .attrs([
                ("xmlns", "md".to_string()),
                ("type", "set".to_string()),
                ("to", SERVER_JID.to_string()),
                ("id", req_id),
            ])
            .children([link_code_reg])
            .build()
    }

    /// Parses the stage 1 response to extract the pairing ref.
    pub fn parse_companion_hello_response(node: &Node) -> Option<Vec<u8>> {
        node.get_optional_child_by_tag(&["link_code_companion_reg"])
            .and_then(|n| n.get_optional_child_by_tag(&["link_code_pairing_ref"]))
            .and_then(|n| n.content.as_ref())
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b.clone()),
                _ => None,
            })
    }

    /// Builds the stage 2 (companion_finish) IQ node.
    pub fn build_companion_finish_iq(
        phone_number: &str,
        wrapped_key_bundle: Vec<u8>,
        identity_pub: &[u8; 32],
        pairing_ref: &[u8],
        req_id: String,
    ) -> Node {
        let link_code_reg = NodeBuilder::new("link_code_companion_reg")
            .attrs([
                ("jid", format!("{}@s.whatsapp.net", phone_number)),
                ("stage", "companion_finish".to_string()),
            ])
            .children([
                NodeBuilder::new("link_code_pairing_wrapped_key_bundle")
                    .bytes(wrapped_key_bundle)
                    .build(),
                NodeBuilder::new("companion_identity_public")
                    .bytes(identity_pub.to_vec())
                    .build(),
                NodeBuilder::new("link_code_pairing_ref")
                    .bytes(pairing_ref.to_vec())
                    .build(),
            ])
            .build();

        NodeBuilder::new("iq")
            .attrs([
                ("xmlns", "md".to_string()),
                ("type", "set".to_string()),
                ("to", SERVER_JID.to_string()),
                ("id", req_id),
            ])
            .children([link_code_reg])
            .build()
    }

    /// Prepares the encrypted key bundle for stage 2.
    ///
    /// This performs:
    /// 1. DH key exchange with primary's ephemeral public key
    /// 2. DH key exchange with primary's identity public key
    /// 3. HKDF to derive bundle encryption key
    /// 4. AES-GCM encryption of the key bundle
    ///
    /// Returns the wrapped bundle and a new ADV secret derived from the DH exchanges.
    /// The ADV secret should be stored to enable HMAC verification of pair-success.
    pub fn prepare_key_bundle(
        ephemeral_keypair: &KeyPair,
        primary_ephemeral_pub: &[u8; 32],
        primary_identity_pub: &[u8; 32],
        identity_key: &KeyPair,
    ) -> Result<(Vec<u8>, [u8; 32]), PairCodeError> {
        // Parse primary's ephemeral public key
        let primary_eph_pub =
            PublicKey::from_djb_public_key_bytes(primary_ephemeral_pub).map_err(|e| {
                PairCodeError::CryptoError(format!("Invalid primary ephemeral key: {e}"))
            })?;

        // Parse primary's identity public key
        let primary_id_pub =
            PublicKey::from_djb_public_key_bytes(primary_identity_pub).map_err(|e| {
                PairCodeError::CryptoError(format!("Invalid primary identity key: {e}"))
            })?;

        // DH 1: Ephemeral key exchange
        let ephemeral_shared = ephemeral_keypair
            .private_key
            .calculate_agreement(&primary_eph_pub)
            .map_err(|e| PairCodeError::CryptoError(format!("Ephemeral DH failed: {e}")))?;

        // DH 2: Identity key exchange (for ADV secret derivation)
        let identity_shared = identity_key
            .private_key
            .calculate_agreement(&primary_id_pub)
            .map_err(|e| PairCodeError::CryptoError(format!("Identity DH failed: {e}")))?;

        // Generate random bytes for ADV secret derivation
        let mut random_bytes = [0u8; 32];
        rand::rng().fill(&mut random_bytes);

        // Derive ADV secret using HKDF
        // Combined secret = ephemeral_shared + identity_shared + random_bytes
        let mut combined_secret = Vec::with_capacity(96);
        combined_secret.extend_from_slice(&ephemeral_shared);
        combined_secret.extend_from_slice(&identity_shared);
        combined_secret.extend_from_slice(&random_bytes);

        let hk_adv = Hkdf::<Sha256>::new(None, &combined_secret);
        let mut new_adv_secret = [0u8; 32];
        hk_adv
            .expand(b"adv_secret", &mut new_adv_secret)
            .map_err(|_| PairCodeError::CryptoError("HKDF expand for adv_secret failed".into()))?;

        // Prepare bundle: companion_identity_pub (32) + primary_identity_pub (32) + random_bytes (32) = 96 bytes
        let mut bundle = Vec::with_capacity(96);
        bundle.extend_from_slice(identity_key.public_key.public_key_bytes());
        bundle.extend_from_slice(primary_identity_pub);
        bundle.extend_from_slice(&random_bytes);

        // Generate salt for HKDF
        let mut key_bundle_salt = [0u8; 32];
        rand::rng().fill(&mut key_bundle_salt);

        // Derive bundle encryption key using HKDF
        // HKDF(IKM=ephemeral_shared, salt=random_salt, info="link_code_pairing_key_bundle_encryption_key")
        let hk_bundle = Hkdf::<Sha256>::new(Some(&key_bundle_salt), &ephemeral_shared);
        let mut enc_key = [0u8; 32];
        hk_bundle
            .expand(b"link_code_pairing_key_bundle_encryption_key", &mut enc_key)
            .map_err(|_| {
                PairCodeError::CryptoError("HKDF expand for bundle encryption key failed".into())
            })?;

        // Generate random IV for AES-GCM (12 bytes)
        let mut iv = [0u8; 12];
        rand::rng().fill(&mut iv);

        // AES-GCM encrypt the bundle
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| PairCodeError::CryptoError(format!("AES-GCM init failed: {e}")))?;
        let nonce = aes_gcm::Nonce::from_slice(&iv);
        let encrypted_bundle = cipher
            .encrypt(nonce, bundle.as_slice())
            .map_err(|e| PairCodeError::CryptoError(format!("AES-GCM encryption failed: {e}")))?;

        // Wrapped bundle = salt (32) + iv (12) + encrypted_bundle (96 + 16 = 112)
        let mut wrapped_bundle = Vec::with_capacity(32 + 12 + encrypted_bundle.len());
        wrapped_bundle.extend_from_slice(&key_bundle_salt);
        wrapped_bundle.extend_from_slice(&iv);
        wrapped_bundle.extend_from_slice(&encrypted_bundle);

        Ok((wrapped_bundle, new_adv_secret))
    }

    /// Returns the pair code validity duration.
    pub fn code_validity() -> std::time::Duration {
        std::time::Duration::from_secs(PAIR_CODE_VALIDITY_SECS)
    }
}

/// Errors that can occur during pair code operations.
#[derive(Debug, thiserror::Error)]
pub enum PairCodeError {
    #[error("Phone number is required")]
    PhoneNumberRequired,

    #[error("Phone number is too short (must be at least 7 digits)")]
    PhoneNumberTooShort,

    #[error("Phone number must not start with 0 (use international format)")]
    PhoneNumberNotInternational,

    #[error("Invalid custom code: must be 8 characters from Crockford Base32 alphabet")]
    InvalidCustomCode,

    #[error("Invalid wrapped data: expected {expected} bytes, got {got}")]
    InvalidWrappedData { expected: usize, got: usize },

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Not in waiting state for pair code notification")]
    NotWaiting,

    #[error("Server response missing pairing ref")]
    MissingPairingRef,

    #[error("Request failed: {0}")]
    RequestFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code() {
        let code = PairCodeUtils::generate_code();
        assert_eq!(code.len(), 8);
        assert!(PairCodeUtils::validate_code(&code));
    }

    #[test]
    fn test_validate_code_valid() {
        assert!(PairCodeUtils::validate_code("ABCD1234"));
        assert!(PairCodeUtils::validate_code("12345678"));
        assert!(PairCodeUtils::validate_code("VWXYZ123"));
    }

    #[test]
    fn test_validate_code_invalid() {
        // Too short
        assert!(!PairCodeUtils::validate_code("ABC1234"));
        // Too long
        assert!(!PairCodeUtils::validate_code("ABCD12345"));
        // Contains invalid characters (0, O, I, L)
        assert!(!PairCodeUtils::validate_code("ABCD0123")); // 0 is invalid
        assert!(!PairCodeUtils::validate_code("ABCDOIJK")); // O is invalid
        assert!(!PairCodeUtils::validate_code("ABCDIJKL")); // I and L are invalid
    }

    #[test]
    fn test_encode_crockford() {
        // Known test vector: 5 bytes of 0 should give the first character repeated
        let zeros = [0u8; 5];
        let encoded = PairCodeUtils::encode_crockford(&zeros);
        assert_eq!(encoded, "11111111");

        // All 0xFF should give last character repeated
        let ones = [0xFFu8; 5];
        let encoded = PairCodeUtils::encode_crockford(&ones);
        assert_eq!(encoded, "ZZZZZZZZ");
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0u8; 32];
        let key1 = PairCodeUtils::derive_key("ABCD1234", &salt);
        let key2 = PairCodeUtils::derive_key("ABCD1234", &salt);
        assert_eq!(key1, key2);

        // Different code should give different key
        let key3 = PairCodeUtils::derive_key("WXYZ5678", &salt);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_encrypt_ephemeral_output_size() {
        let ephemeral_pub = [0x42u8; 32];
        let wrapped = PairCodeUtils::encrypt_ephemeral_pub(&ephemeral_pub, "ABCD1234");
        assert_eq!(wrapped.len(), 80);

        // Verify structure: salt (32) || iv (16) || ciphertext (32)
        assert_eq!(wrapped[0..32].len(), 32); // salt
        assert_eq!(wrapped[32..48].len(), 16); // iv
        assert_eq!(wrapped[48..80].len(), 32); // ciphertext
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ephemeral_pub = [0x42u8; 32];
        let code = "ABCD1234";

        let wrapped = PairCodeUtils::encrypt_ephemeral_pub(&ephemeral_pub, code);

        // Decrypt using the pair code (extracts salt from wrapped data)
        let decrypted = PairCodeUtils::decrypt_primary_ephemeral_pub(&wrapped, code)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, ephemeral_pub);
    }

    #[test]
    fn test_decrypt_invalid_length() {
        let code = "ABCD1234";

        // Too short
        let result = PairCodeUtils::decrypt_primary_ephemeral_pub(&[0u8; 79], code);
        assert!(matches!(
            result,
            Err(PairCodeError::InvalidWrappedData { .. })
        ));

        // Too long
        let result = PairCodeUtils::decrypt_primary_ephemeral_pub(&[0u8; 81], code);
        assert!(matches!(
            result,
            Err(PairCodeError::InvalidWrappedData { .. })
        ));
    }

    #[test]
    fn test_platform_id_string_enum() {
        // StringEnum derive works correctly
        assert_eq!(PlatformId::Chrome.as_str(), "1");
        assert_eq!(PlatformId::Firefox.to_string(), "2");
        assert_eq!(PlatformId::default(), PlatformId::Chrome);
        // repr(u8) values match DeviceProps.PlatformType protobuf enum
        assert_eq!(PlatformId::Chrome as u8, 1);
    }

    #[test]
    fn test_code_validity_duration() {
        let duration = PairCodeUtils::code_validity();
        assert_eq!(duration.as_secs(), 180);
    }

    #[test]
    fn test_validate_code_case_insensitive() {
        // Lowercase should be valid (will be uppercased)
        assert!(PairCodeUtils::validate_code("abcd1234"));
        assert!(PairCodeUtils::validate_code("AbCd1234"));
        assert!(PairCodeUtils::validate_code("vwxyz123"));
    }

    #[test]
    fn test_validate_code_all_crockford_chars() {
        // All valid Crockford Base32 characters
        assert!(PairCodeUtils::validate_code("12345678"));
        assert!(PairCodeUtils::validate_code("9ABCDEFG"));
        assert!(PairCodeUtils::validate_code("HJKLMNPQ"));
        assert!(PairCodeUtils::validate_code("RSTVWXYZ"));
    }

    #[test]
    fn test_generate_code_uniqueness() {
        // Generate multiple codes and verify they're unique
        let codes: Vec<String> = (0..100).map(|_| PairCodeUtils::generate_code()).collect();
        let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
        // Very unlikely to have duplicates in 100 codes with 40 bits of entropy
        assert!(unique_codes.len() > 95);
    }

    #[test]
    fn test_encrypt_produces_different_output_each_time() {
        // Same input should produce different output due to random salt/iv
        let ephemeral_pub = [0x42u8; 32];
        let code = "ABCD1234";

        let wrapped1 = PairCodeUtils::encrypt_ephemeral_pub(&ephemeral_pub, code);
        let wrapped2 = PairCodeUtils::encrypt_ephemeral_pub(&ephemeral_pub, code);

        // Salt and IV should be different
        assert_ne!(&wrapped1[0..32], &wrapped2[0..32]); // Salt differs
        assert_ne!(&wrapped1[32..48], &wrapped2[32..48]); // IV differs
    }

    #[test]
    fn test_decrypt_with_wrong_code_produces_garbage() {
        let ephemeral_pub = [0x42u8; 32];
        let correct_code = "ABCD1234";
        let wrong_code = "WXYZ5678";

        let wrapped = PairCodeUtils::encrypt_ephemeral_pub(&ephemeral_pub, correct_code);

        // Decrypt with wrong code - should succeed but produce garbage
        let decrypted = PairCodeUtils::decrypt_primary_ephemeral_pub(&wrapped, wrong_code)
            .expect("Decryption should succeed structurally");

        // The decrypted data should NOT match the original
        assert_ne!(decrypted, ephemeral_pub);
    }

    #[test]
    fn test_derive_key_with_different_salts() {
        let code = "ABCD1234";
        let salt1 = [0u8; 32];
        let salt2 = [1u8; 32];

        let key1 = PairCodeUtils::derive_key(code, &salt1);
        let key2 = PairCodeUtils::derive_key(code, &salt2);

        // Different salts should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_pair_code_options_default() {
        let options = PairCodeOptions::default();
        assert!(options.phone_number.is_empty());
        assert!(options.show_push_notification);
        assert!(options.custom_code.is_none());
        assert_eq!(options.platform_id, PlatformId::Chrome);
        assert_eq!(options.platform_display, "Chrome (Linux)");
    }

    #[test]
    fn test_pair_code_options_with_custom_code() {
        let options = PairCodeOptions {
            phone_number: "15551234567".to_string(),
            custom_code: Some("MYCODE12".to_string()),
            ..Default::default()
        };
        assert_eq!(options.phone_number, "15551234567");
        assert_eq!(options.custom_code, Some("MYCODE12".to_string()));
    }

    #[test]
    fn test_pair_code_state_debug() {
        let idle = PairCodeState::Idle;
        assert_eq!(format!("{:?}", idle), "Idle");

        let completed = PairCodeState::Completed;
        assert_eq!(format!("{:?}", completed), "Completed");
    }

    #[test]
    fn test_pair_code_error_display() {
        let err = PairCodeError::PhoneNumberRequired;
        assert_eq!(err.to_string(), "Phone number is required");

        let err = PairCodeError::PhoneNumberTooShort;
        assert_eq!(
            err.to_string(),
            "Phone number is too short (must be at least 7 digits)"
        );

        let err = PairCodeError::InvalidCustomCode;
        assert_eq!(
            err.to_string(),
            "Invalid custom code: must be 8 characters from Crockford Base32 alphabet"
        );

        let err = PairCodeError::InvalidWrappedData {
            expected: 80,
            got: 50,
        };
        assert_eq!(
            err.to_string(),
            "Invalid wrapped data: expected 80 bytes, got 50"
        );
    }

    #[test]
    fn test_crockford_encoding_boundary_values() {
        // Test specific byte patterns
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x1F]; // Last 5 bits = 31 = 'Z'
        let encoded = PairCodeUtils::encode_crockford(&bytes);
        assert_eq!(encoded.chars().last().unwrap(), 'Z');

        let bytes = [0x00, 0x00, 0x00, 0x00, 0x01]; // Last 5 bits = 1 = '2'
        let encoded = PairCodeUtils::encode_crockford(&bytes);
        assert_eq!(encoded.chars().last().unwrap(), '2');
    }
}
