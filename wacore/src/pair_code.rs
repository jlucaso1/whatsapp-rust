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

use crate::companion_reg::{
    CompanionWebClientType, companion_platform_display, companion_web_client_type_for_props,
};
use crate::libsignal::crypto::{CryptoProviderError, aes_256_gcm_encrypt};
use crate::libsignal::protocol::{CurveError, KeyPair, PublicKey};
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;
use wacore_binary::SERVER_JID;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Node, NodeContentRef, NodeRef};
use waproto::whatsapp as wa;

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

/// RFC 2898 PBKDF2 using HMAC-SHA256. Replaces the `pbkdf2` crate dependency
/// which hasn't released a digest 0.11-compatible stable version yet.
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) {
    use hmac::KeyInit as _;
    for (i, chunk) in output.chunks_mut(32).enumerate() {
        let mut u = {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(password).expect("HMAC accepts any key length");
            mac.update(salt);
            mac.update(&((i as u32) + 1).to_be_bytes());
            let result: [u8; 32] = mac.finalize().into_bytes().into();
            result
        };
        chunk.copy_from_slice(&u[..chunk.len()]);
        for _ in 1..rounds {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(password).expect("HMAC accepts any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes().into();
            for (a, b) in chunk.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
    }
}

/// Validity duration for pair codes (approximately).
const PAIR_CODE_VALIDITY_SECS: u64 = 180;

/// Pairs `id` with the display string built from `props.os`. Single
/// source of truth for the os→display step shared by [`derive_companion_platform`]
/// and [`resolve_companion_platform`].
fn build_id_and_display(
    id: CompanionWebClientType,
    props: &wa::DeviceProps,
) -> (CompanionWebClientType, String) {
    let os = props.os.as_deref().unwrap_or("");
    (id, companion_platform_display(id, os))
}

/// `(companion_platform_id, companion_platform_display)` per WA Web's
/// `Alt/DeviceLinkingIq.js`. Display always Browser-valid (see
/// `companion_platform_display`).
pub fn derive_companion_platform(props: &wa::DeviceProps) -> (CompanionWebClientType, String) {
    build_id_and_display(companion_web_client_type_for_props(props), props)
}

/// Honours `PairCodeOptions::platform_id` override; display is always
/// derived (no override — WA Web has none, server rejects arbitrary strings).
pub fn resolve_companion_platform(
    options: &PairCodeOptions,
    props: &wa::DeviceProps,
) -> (CompanionWebClientType, String) {
    let id = options
        .platform_id
        .unwrap_or_else(|| companion_web_client_type_for_props(props));
    build_id_and_display(id, props)
}

/// Options for pair code authentication.
#[derive(Debug, Clone)]
pub struct PairCodeOptions {
    /// Phone number with country code, no leading zeros or special chars (e.g., "15551234567").
    pub phone_number: String,
    /// Whether to show push notification on phone (default `true`, matching WA Web).
    pub show_push_notification: bool,
    /// Custom pairing code (8 chars from Crockford alphabet, or None for random).
    pub custom_code: Option<String>,
    /// `None` auto-derives from `Device.device_props.platform_type`.
    pub platform_id: Option<CompanionWebClientType>,
}

impl Default for PairCodeOptions {
    fn default() -> Self {
        Self {
            phone_number: String::new(),
            show_push_notification: true,
            custom_code: None,
            platform_id: None,
        }
    }
}

impl PairCodeOptions {
    /// Convenience constructor with the phone number preset and other fields defaulted.
    pub fn for_phone(phone_number: impl Into<String>) -> Self {
        Self {
            phone_number: phone_number.into(),
            ..Self::default()
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
        rand::make_rng::<rand::rngs::StdRng>().fill(&mut bytes);
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
        pbkdf2_hmac_sha256(code.as_bytes(), salt, PAIR_CODE_PBKDF2_ITERATIONS, &mut key);
        key
    }

    /// Encrypts the companion ephemeral public key for stage 1.
    ///
    /// Returns the wrapped ephemeral data: `salt (32) || iv (16) || ciphertext (32)` = 80 bytes.
    pub fn encrypt_ephemeral_pub(ephemeral_pub: &[u8; 32], code: &str) -> [u8; 80] {
        // Generate random salt and IV
        let mut salt = [0u8; PAIR_CODE_SALT_SIZE];
        let mut iv = [0u8; PAIR_CODE_IV_SIZE];
        rand::make_rng::<rand::rngs::StdRng>().fill(&mut salt);
        rand::make_rng::<rand::rngs::StdRng>().fill(&mut iv);

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
    ///
    /// `platform_id` and `platform_display` are the resolved strings — callers
    /// typically obtain them through [`resolve_companion_platform`] so that
    /// `Device.device_props` is the single source of truth.
    pub fn build_companion_hello_iq(
        phone_number: &str,
        noise_static_pub: &[u8; 32],
        wrapped_ephemeral: &[u8; 80],
        platform_id: &str,
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
                    .bytes(platform_id.as_bytes().to_vec())
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
    pub fn parse_companion_hello_response(node: &NodeRef<'_>) -> Option<Vec<u8>> {
        node.get_optional_child_by_tag(&["link_code_companion_reg"])
            .and_then(|n| n.get_optional_child_by_tag(&["link_code_pairing_ref"]))
            .and_then(|n| match n.content.as_deref() {
                Some(NodeContentRef::Bytes(b)) => Some(b.to_vec()),
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
        let primary_eph_pub = PublicKey::from_djb_public_key_bytes(primary_ephemeral_pub)
            .map_err(PairCodeError::InvalidPrimaryEphemeralKey)?;

        let primary_id_pub = PublicKey::from_djb_public_key_bytes(primary_identity_pub)
            .map_err(PairCodeError::InvalidPrimaryIdentityKey)?;

        let ephemeral_shared = ephemeral_keypair
            .private_key
            .calculate_agreement(&primary_eph_pub)
            .map_err(PairCodeError::EphemeralKeyAgreement)?;

        let identity_shared = identity_key
            .private_key
            .calculate_agreement(&primary_id_pub)
            .map_err(PairCodeError::IdentityKeyAgreement)?;

        // Generate random bytes for ADV secret derivation
        let mut random_bytes = [0u8; 32];
        rand::make_rng::<rand::rngs::StdRng>().fill(&mut random_bytes);

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
            .map_err(|_| PairCodeError::AdvSecretKeyDerivation)?;

        // Prepare bundle: companion_identity_pub (32) + primary_identity_pub (32) + random_bytes (32) = 96 bytes
        let mut bundle = Vec::with_capacity(96);
        bundle.extend_from_slice(identity_key.public_key.public_key_bytes());
        bundle.extend_from_slice(primary_identity_pub);
        bundle.extend_from_slice(&random_bytes);

        // Generate salt for HKDF
        let mut key_bundle_salt = [0u8; 32];
        rand::make_rng::<rand::rngs::StdRng>().fill(&mut key_bundle_salt);

        // Derive bundle encryption key using HKDF
        // HKDF(IKM=ephemeral_shared, salt=random_salt, info="link_code_pairing_key_bundle_encryption_key")
        let hk_bundle = Hkdf::<Sha256>::new(Some(&key_bundle_salt), &ephemeral_shared);
        let mut enc_key = [0u8; 32];
        hk_bundle
            .expand(b"link_code_pairing_key_bundle_encryption_key", &mut enc_key)
            .map_err(|_| PairCodeError::BundleKeyDerivation)?;

        // Generate random IV for AES-GCM (12 bytes)
        let mut iv = [0u8; 12];
        rand::make_rng::<rand::rngs::StdRng>().fill(&mut iv);

        // Wrapped bundle = salt (32) + iv (12) + encrypted_bundle (96 + 16 = 112)
        let mut wrapped_bundle = Vec::with_capacity(32 + 12 + bundle.len() + 16);
        wrapped_bundle.extend_from_slice(&key_bundle_salt);
        wrapped_bundle.extend_from_slice(&iv);
        aes_256_gcm_encrypt(&enc_key, &iv, b"", &bundle, &mut wrapped_bundle)
            .map_err(PairCodeError::BundleAead)?;

        Ok((wrapped_bundle, new_adv_secret))
    }

    /// Returns the pair code validity duration.
    pub fn code_validity() -> std::time::Duration {
        std::time::Duration::from_secs(PAIR_CODE_VALIDITY_SECS)
    }
}

/// Errors raised by wacore-side pair-code validation, key derivation, and
/// protocol-bundle building. The high-level crate wraps this in
/// `whatsapp_rust::pair_code::PairError` and adds an IQ-failure variant for the
/// transport layer.
#[derive(Debug, thiserror::Error)]
pub enum PairCodeError {
    #[error("phone number is required")]
    PhoneNumberRequired,

    #[error("phone number is too short (must be at least 7 digits)")]
    PhoneNumberTooShort,

    #[error("phone number must not start with 0 (use international format)")]
    PhoneNumberNotInternational,

    #[error("invalid custom code: must be 8 characters from Crockford Base32 alphabet")]
    InvalidCustomCode,

    #[error("invalid wrapped data: expected {expected} bytes, got {got}")]
    InvalidWrappedData { expected: usize, got: usize },

    #[error("primary device sent an invalid ephemeral public key")]
    InvalidPrimaryEphemeralKey(#[source] CurveError),

    #[error("primary device sent an invalid identity public key")]
    InvalidPrimaryIdentityKey(#[source] CurveError),

    #[error("ephemeral key agreement failed")]
    EphemeralKeyAgreement(#[source] CurveError),

    #[error("identity key agreement failed")]
    IdentityKeyAgreement(#[source] CurveError),

    #[error("HKDF expand failed for adv_secret")]
    AdvSecretKeyDerivation,

    #[error("HKDF expand failed for bundle encryption key")]
    BundleKeyDerivation,

    #[error("AES-GCM encryption of key bundle failed")]
    BundleAead(#[source] CryptoProviderError),

    #[error("not in waiting state for pair code notification")]
    NotWaiting,

    #[error("server response missing pairing ref")]
    MissingPairingRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::NodeContent;

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

    fn props(os: Option<&str>, pt: Option<wa::device_props::PlatformType>) -> wa::DeviceProps {
        wa::DeviceProps {
            os: os.map(|s| s.to_string()),
            platform_type: pt.map(|v| v as i32),
            ..Default::default()
        }
    }

    #[test]
    fn derive_chrome_linux_matches_wa_web() {
        let p = props(Some("Linux"), Some(wa::device_props::PlatformType::Chrome));
        assert_eq!(
            derive_companion_platform(&p),
            (CompanionWebClientType::Chrome, "Chrome (Linux)".to_string())
        );
    }

    #[test]
    fn derive_firefox_uses_companion_web_client_wire() {
        let p = props(Some("Linux"), Some(wa::device_props::PlatformType::Firefox));
        let (id, display) = derive_companion_platform(&p);
        assert_eq!(id, CompanionWebClientType::Firefox);
        assert_eq!(id.wire_byte(), b'3');
        assert_eq!(display, "Firefox (Linux)");
    }

    #[test]
    fn derive_edge_uses_companion_web_client_wire() {
        let p = props(Some("Windows"), Some(wa::device_props::PlatformType::Edge));
        let (id, display) = derive_companion_platform(&p);
        assert_eq!(id, CompanionWebClientType::Edge);
        assert_eq!(id.wire_byte(), b'2');
        assert_eq!(display, "Edge (Windows)");
    }

    /// Android `PlatformType` values map to `Chrome` (`'1'`) — what real
    /// WA Web on Chrome-Android emits. The Android letters `'e'`/`'d'`/`'f'`
    /// require explicit opt-in via `PairCodeOptions::platform_id` because
    /// the server validates them against Android-side attestation.
    #[test]
    fn derive_android_platform_types_map_to_chrome() {
        use wa::device_props::PlatformType as P;
        for pt in [P::AndroidPhone, P::AndroidTablet, P::AndroidAmbiguous] {
            let (id, display) = derive_companion_platform(&props(Some("Android"), Some(pt)));
            assert_eq!(id, CompanionWebClientType::Chrome, "{pt:?}");
            assert_eq!(id.wire_byte(), b'1', "{pt:?}");
            assert_eq!(display, "Chrome (Android)", "{pt:?}");
        }
    }

    #[test]
    fn derive_ios_phone_falls_back_to_other_web_client_and_chrome() {
        let p = props(Some("iOS"), Some(wa::device_props::PlatformType::IosPhone));
        let (id, display) = derive_companion_platform(&p);
        assert_eq!(id, CompanionWebClientType::OtherWebClient);
        assert_eq!(display, "Chrome (iOS)");
    }

    #[test]
    fn derive_no_os_substitutes_linux() {
        let p = props(None, Some(wa::device_props::PlatformType::Chrome));
        assert_eq!(
            derive_companion_platform(&p),
            (CompanionWebClientType::Chrome, "Chrome (Linux)".to_string())
        );
    }

    #[test]
    fn derive_empty_os_substitutes_linux() {
        let p = props(Some("   "), Some(wa::device_props::PlatformType::Chrome));
        assert_eq!(
            derive_companion_platform(&p),
            (CompanionWebClientType::Chrome, "Chrome (Linux)".to_string())
        );
    }

    /// Missing/invalid props collapse to `OtherWebClient` (`'9'`), the
    /// catch-all WA Web emits when `info().name` doesn't match a known
    /// browser.
    #[test]
    fn derive_unknown_proto_yields_other_web_client_id_and_chrome_display() {
        let p = props(None, None);
        assert_eq!(
            derive_companion_platform(&p),
            (
                CompanionWebClientType::OtherWebClient,
                "Chrome (Linux)".to_string()
            )
        );
    }

    /// Every proto variant produces a server-acceptable wire byte (`'1'..'9'`)
    /// and a `<Browser> (<OS>)` display with a known browser label.
    #[test]
    fn derive_display_uses_known_label_for_every_proto_variant() {
        use wa::device_props::PlatformType as P;
        const SERVER_ACCEPT_LIST: &[u8] = b"0123456789abcdefghijklm";
        const KNOWN_LABELS: &[&str] = &[
            "Chrome", "Edge", "Firefox", "IE", "Opera", "Safari", "Android",
        ];
        for pt in [
            P::Unknown,
            P::Chrome,
            P::Firefox,
            P::Ie,
            P::Opera,
            P::Safari,
            P::Edge,
            P::Desktop,
            P::Ipad,
            P::AndroidTablet,
            P::Ohana,
            P::Aloha,
            P::Catalina,
            P::TclTv,
            P::IosPhone,
            P::IosCatalyst,
            P::AndroidPhone,
            P::AndroidAmbiguous,
            P::WearOs,
            P::ArWrist,
            P::ArDevice,
            P::Uwp,
            P::Vr,
            P::CloudApi,
            P::Smartglasses,
        ] {
            let p = props(Some("Linux"), Some(pt));
            let (id, display) = derive_companion_platform(&p);
            assert!(
                SERVER_ACCEPT_LIST.contains(&id.wire_byte()),
                "{pt:?} wire byte {:?} outside server accept list",
                id.wire_byte() as char,
            );
            let label = display.split(" (").next().unwrap();
            assert!(
                KNOWN_LABELS.contains(&label),
                "{pt:?} produced display {display:?} with unexpected label {label:?}"
            );
            assert!(
                display.ends_with(" (Linux)"),
                "{pt:?} produced display {display:?} without parenthesised OS"
            );
        }
    }

    #[test]
    fn resolve_explicit_id_overrides_derived() {
        let p = props(
            Some("Android"),
            Some(wa::device_props::PlatformType::AndroidPhone),
        );
        let opts = PairCodeOptions {
            platform_id: Some(CompanionWebClientType::Chrome),
            ..Default::default()
        };
        assert_eq!(
            resolve_companion_platform(&opts, &p),
            (
                CompanionWebClientType::Chrome,
                "Chrome (Android)".to_string()
            )
        );
    }

    #[test]
    fn resolve_default_uses_derived() {
        let p = props(Some("Linux"), Some(wa::device_props::PlatformType::Edge));
        assert_eq!(
            resolve_companion_platform(&PairCodeOptions::default(), &p),
            (CompanionWebClientType::Edge, "Edge (Linux)".to_string())
        );
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

    /// `Default` must not carry any implicit platform identity — the `Chrome (Linux)`
    /// hardcode caused the companion_hello IQ to claim Chrome even when
    /// `DeviceProps` said Android. Keep this assertion as a regression guard.
    #[test]
    fn pair_code_options_default_has_no_platform_hardcode() {
        let options = PairCodeOptions::default();
        assert!(options.phone_number.is_empty());
        assert!(options.show_push_notification, "default must keep push on");
        assert!(options.custom_code.is_none());
        assert!(
            options.platform_id.is_none(),
            "platform_id default must be None so derivation kicks in"
        );
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
        assert_eq!(err.to_string(), "phone number is required");

        let err = PairCodeError::PhoneNumberTooShort;
        assert_eq!(
            err.to_string(),
            "phone number is too short (must be at least 7 digits)"
        );

        let err = PairCodeError::InvalidCustomCode;
        assert_eq!(
            err.to_string(),
            "invalid custom code: must be 8 characters from Crockford Base32 alphabet"
        );

        let err = PairCodeError::InvalidWrappedData {
            expected: 80,
            got: 50,
        };
        assert_eq!(
            err.to_string(),
            "invalid wrapped data: expected 80 bytes, got 50"
        );
    }

    #[test]
    fn invalid_primary_ephemeral_key_preserves_curve_source() {
        let err = PairCodeError::InvalidPrimaryEphemeralKey(CurveError::NoKeyTypeIdentifier);
        let src = std::error::Error::source(&err).expect("source preserved");
        let curve = src
            .downcast_ref::<CurveError>()
            .expect("downcasts to CurveError");
        assert!(matches!(curve, CurveError::NoKeyTypeIdentifier));
    }

    #[test]
    fn bundle_aead_preserves_crypto_provider_source() {
        let err = PairCodeError::BundleAead(CryptoProviderError::BadInput);
        let src = std::error::Error::source(&err).expect("source preserved");
        let cpe = src
            .downcast_ref::<CryptoProviderError>()
            .expect("downcasts to CryptoProviderError");
        assert!(matches!(cpe, CryptoProviderError::BadInput));
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

    // ----- Wire format + regression tests for companion_platform_{id,display} -----

    fn child_bytes<'a>(node: &'a Node, tag: &str) -> &'a [u8] {
        let n = node
            .get_optional_child_by_tag(&[tag])
            .unwrap_or_else(|| panic!("missing <{tag}>"));
        match n.content.as_ref() {
            Some(NodeContent::Bytes(b)) => b.as_slice(),
            other => panic!("expected Bytes for <{tag}>, got {other:?}"),
        }
    }

    fn build_iq(pid: &str, pdisp: &str) -> Node {
        let noise = [0xAAu8; 32];
        let wrapped = [0xBBu8; 80];
        PairCodeUtils::build_companion_hello_iq(
            "15551234567",
            &noise,
            &wrapped,
            pid,
            pdisp,
            true,
            "req-1".to_string(),
        )
    }

    #[test]
    fn companion_hello_iq_shape() {
        let iq = build_iq("e", "Android (Android)");
        assert_eq!(iq.tag, "iq");

        let reg = iq
            .get_optional_child_by_tag(&["link_code_companion_reg"])
            .expect("link_code_companion_reg");
        let attrs: std::collections::HashMap<String, String> = reg
            .attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_str().into_owned()))
            .collect();
        assert_eq!(
            attrs.get("stage").map(String::as_str),
            Some("companion_hello")
        );
        assert_eq!(
            attrs.get("jid").map(String::as_str),
            Some("15551234567@s.whatsapp.net")
        );
        assert_eq!(
            attrs
                .get("should_show_push_notification")
                .map(String::as_str),
            Some("true")
        );

        // Nonce is the string "0", per whatsmeow/baileys parity.
        assert_eq!(child_bytes(reg, "link_code_pairing_nonce"), b"0");
    }

    /// `build_companion_hello_iq` is byte-passthrough for the platform
    /// id/display strings. Pins the explicit Android-letter shape so a
    /// caller that opts in via `PairCodeOptions::platform_id =
    /// Some(AndroidPhone)` still gets the right wire bytes.
    #[test]
    fn companion_hello_iq_passes_through_explicit_android_letter() {
        let iq = build_iq("e", "Android (16)");
        let reg = iq
            .get_optional_child_by_tag(&["link_code_companion_reg"])
            .unwrap();
        assert_eq!(child_bytes(reg, "companion_platform_id"), b"e");
        assert_eq!(
            child_bytes(reg, "companion_platform_display"),
            b"Android (16)"
        );
    }

    #[test]
    fn companion_hello_iq_chrome_linux_wire_parity() {
        // Guarantees the refactor didn't shift wire bytes for the legacy web case.
        let iq = build_iq("1", "Chrome (Linux)");
        let reg = iq
            .get_optional_child_by_tag(&["link_code_companion_reg"])
            .unwrap();
        assert_eq!(child_bytes(reg, "companion_platform_id"), b"1");
        assert_eq!(
            child_bytes(reg, "companion_platform_display"),
            b"Chrome (Linux)"
        );
    }

    /// E2E regression: mobile DeviceProps + default options must emit a
    /// server-accepted `companion_hello`. Android* derives to Chrome
    /// (`'1'`) + `"Chrome (Android)"`, matching real WA Web on
    /// Chrome-Android.
    #[test]
    fn android_device_props_emit_server_accepted_companion_hello() {
        let props = wa::DeviceProps {
            os: Some("Android".into()),
            platform_type: Some(wa::device_props::PlatformType::AndroidPhone as i32),
            ..Default::default()
        };
        let (pid, pdisp) = resolve_companion_platform(&PairCodeOptions::default(), &props);
        assert_eq!(pid, CompanionWebClientType::Chrome);
        assert_eq!(pid.wire_byte(), b'1');
        assert_eq!(pdisp, "Chrome (Android)");

        let iq = build_iq(&pid.to_string(), &pdisp);
        let reg = iq
            .get_optional_child_by_tag(&["link_code_companion_reg"])
            .unwrap();
        assert_eq!(child_bytes(reg, "companion_platform_id"), b"1");
        assert_eq!(
            child_bytes(reg, "companion_platform_display"),
            b"Chrome (Android)"
        );
    }

    #[test]
    fn explicit_options_override_id_and_display_follows() {
        let props = wa::DeviceProps {
            os: Some("Android".into()),
            platform_type: Some(wa::device_props::PlatformType::AndroidPhone as i32),
            ..Default::default()
        };
        let opts = PairCodeOptions {
            platform_id: Some(CompanionWebClientType::Chrome),
            ..Default::default()
        };
        let (pid, pdisp) = resolve_companion_platform(&opts, &props);
        assert_eq!(pid, CompanionWebClientType::Chrome);
        assert_eq!(pdisp, "Chrome (Android)");
    }

    /// Pair-code and QR share derivation.
    #[test]
    fn pair_code_id_matches_qr_id_for_same_device_props() {
        use crate::companion_reg::companion_web_client_type_for_props;
        let p = props(Some("Linux"), Some(wa::device_props::PlatformType::Edge));
        let (pair_code_id, _) = derive_companion_platform(&p);
        let qr_id = companion_web_client_type_for_props(&p);
        assert_eq!(pair_code_id, qr_id);
    }
}
