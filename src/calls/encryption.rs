//! Call encryption via enc_rekey mechanism.
//!
//! This module handles the encryption key exchange for calls using the
//! `enc_rekey` signaling type. The call encryption key is encrypted using
//! the existing Signal Protocol session.
//!
//! # Protocol Overview
//!
//! 1. Caller generates a random 32-byte call master key
//! 2. Key is wrapped in protobuf: `Message { call: Call { call_key: [32 bytes] } }`
//! 3. Protobuf is serialized, padded, and Signal-encrypted to recipient
//! 4. Sent via `<call><enc_rekey><enc type="msg|pkmsg">ciphertext</enc></enc_rekey>` stanza
//! 5. Recipient decrypts using Signal session and extracts call_key
//! 6. Both parties derive SRTP keys from the master key (Phase 2)
//!
//! # Stanza Structure
//!
//! ```xml
//! <call to="recipient@lid">
//!   <enc_rekey call-id="..." call-creator="...">
//!     <enc type="msg" count="1">ciphertext</enc>
//!   </enc_rekey>
//! </call>
//! ```

use super::error::CallError;
use prost::Message as ProtoMessage;
use wacore::libsignal::protocol::{
    CiphertextMessage, IdentityKeyStore, PreKeySignalMessage, PreKeyStore, SessionStore,
    SignalMessage, SignedPreKeyStore, UsePQRatchet, message_decrypt, message_encrypt,
};
use wacore::types::jid::JidExt;
use wacore_binary::jid::Jid;
use waproto::whatsapp::{self as wa, message};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// PKCS7 Padding (used for enc_rekey, not regular messages)
// ============================================================================

const PKCS7_BLOCK_SIZE: usize = 16;

/// Apply PKCS7 padding to data.
fn pad_pkcs7(data: Vec<u8>) -> Vec<u8> {
    let padding_len = PKCS7_BLOCK_SIZE - (data.len() % PKCS7_BLOCK_SIZE);
    let mut padded = data;
    padded.resize(padded.len() + padding_len, padding_len as u8);
    padded
}

/// Remove PKCS7 padding from data.
fn unpad_pkcs7(data: &[u8]) -> Result<&[u8], CallError> {
    if data.is_empty() {
        return Err(CallError::Encryption("empty data for PKCS7 unpad".into()));
    }
    let padding_len = data[data.len() - 1] as usize;
    if padding_len == 0 || padding_len > PKCS7_BLOCK_SIZE || padding_len > data.len() {
        return Err(CallError::Encryption("invalid PKCS7 padding".into()));
    }
    // Verify all padding bytes are correct
    for &byte in &data[data.len() - padding_len..] {
        if byte as usize != padding_len {
            return Err(CallError::Encryption("invalid PKCS7 padding bytes".into()));
        }
    }
    Ok(&data[..data.len() - padding_len])
}

/// Call encryption key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CallEncryptionKey {
    /// 32-byte master key for the call.
    pub master_key: [u8; 32],
    /// Key generation/version number.
    pub generation: u32,
}

impl std::fmt::Debug for CallEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose the master key in debug output
        f.debug_struct("CallEncryptionKey")
            .field("master_key", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

impl CallEncryptionKey {
    /// Generate a new random call encryption key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut master_key = [0u8; 32];
        rand::rng().fill_bytes(&mut master_key);
        Self {
            master_key,
            generation: 1,
        }
    }

    /// Create a protobuf Message containing this call key.
    fn to_protobuf(&self) -> wa::Message {
        wa::Message {
            call: Some(Box::new(message::Call {
                call_key: Some(self.master_key.to_vec()),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Extract call key from a protobuf Message.
    fn from_protobuf(msg: &wa::Message) -> Result<Self, CallError> {
        let call = msg
            .call
            .as_ref()
            .ok_or_else(|| CallError::Encryption("message missing call field".into()))?;

        let call_key = call
            .call_key
            .as_ref()
            .ok_or_else(|| CallError::Encryption("call missing call_key field".into()))?;

        if call_key.len() != 32 {
            return Err(CallError::Encryption(format!(
                "call_key wrong length: expected 32, got {}",
                call_key.len()
            )));
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(call_key);

        Ok(Self {
            master_key,
            generation: 1,
        })
    }
}

/// Encryption type for the `<enc>` node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncType {
    /// Signal message (existing session)
    Msg,
    /// PreKey Signal message (new session)
    PkMsg,
}

impl EncType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Msg => "msg",
            Self::PkMsg => "pkmsg",
        }
    }
}

impl std::str::FromStr for EncType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "msg" => Ok(Self::Msg),
            "pkmsg" => Ok(Self::PkMsg),
            _ => Err(()),
        }
    }
}

/// Encrypted payload ready for transmission.
#[derive(Debug, Clone)]
pub struct EncryptedCallKey {
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// The encryption type ("msg" or "pkmsg").
    pub enc_type: EncType,
}

/// Encrypt a call key for a recipient using Signal Protocol.
///
/// This encrypts the call key wrapped in a protobuf Message, ready for
/// inclusion in an `<enc_rekey>` stanza.
pub async fn encrypt_call_key<S, I>(
    session_store: &mut S,
    identity_store: &mut I,
    recipient: &Jid,
    key: &CallEncryptionKey,
) -> Result<EncryptedCallKey, CallError>
where
    S: SessionStore,
    I: IdentityKeyStore,
{
    // Create protobuf message with call key
    let proto_msg = key.to_protobuf();
    let serialized = proto_msg.encode_to_vec();

    // Pad using PKCS7 (enc_rekey uses PKCS7, not random v2 padding)
    let padded = pad_pkcs7(serialized);

    // Encrypt using Signal Protocol
    let signal_address = recipient.to_protocol_address();
    let encrypted = message_encrypt(&padded, &signal_address, session_store, identity_store)
        .await
        .map_err(|e| CallError::Encryption(format!("Signal encryption failed: {}", e)))?;

    let (enc_type, ciphertext) = match encrypted {
        CiphertextMessage::SignalMessage(msg) => (EncType::Msg, msg.serialized().to_vec()),
        CiphertextMessage::PreKeySignalMessage(msg) => (EncType::PkMsg, msg.serialized().to_vec()),
        _ => {
            return Err(CallError::Encryption(
                "unexpected ciphertext message type".into(),
            ));
        }
    };

    Ok(EncryptedCallKey {
        ciphertext,
        enc_type,
    })
}

/// Decrypt a call key received from a sender.
///
/// This decrypts the ciphertext from an `<enc>` node inside `<enc_rekey>`,
/// extracts the protobuf Message, and returns the call key.
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_call_key<S, I, P, SP, R>(
    session_store: &mut S,
    identity_store: &mut I,
    prekey_store: &mut P,
    signed_prekey_store: &SP,
    sender: &Jid,
    ciphertext: &[u8],
    enc_type: EncType,
    csprng: &mut R,
) -> Result<CallEncryptionKey, CallError>
where
    S: SessionStore,
    I: IdentityKeyStore,
    P: PreKeyStore,
    SP: SignedPreKeyStore,
    R: rand::Rng + rand::CryptoRng,
{
    let signal_address = sender.to_protocol_address();

    // Parse the ciphertext based on enc_type
    let ciphertext_message = match enc_type {
        EncType::Msg => {
            let signal_msg = SignalMessage::try_from(ciphertext)
                .map_err(|e| CallError::Encryption(format!("invalid signal message: {}", e)))?;
            CiphertextMessage::SignalMessage(signal_msg)
        }
        EncType::PkMsg => {
            let prekey_msg = PreKeySignalMessage::try_from(ciphertext)
                .map_err(|e| CallError::Encryption(format!("invalid prekey message: {}", e)))?;
            CiphertextMessage::PreKeySignalMessage(prekey_msg)
        }
    };

    // Decrypt using Signal Protocol
    let plaintext = message_decrypt(
        &ciphertext_message,
        &signal_address,
        session_store,
        identity_store,
        prekey_store,
        signed_prekey_store,
        csprng,
        UsePQRatchet::No,
    )
    .await
    .map_err(|e| CallError::Encryption(format!("Signal decryption failed: {}", e)))?;

    // Unpad using PKCS7 (enc_rekey uses PKCS7, not random v2 padding)
    let unpadded = unpad_pkcs7(&plaintext)?;

    // Decode protobuf message
    let proto_msg = wa::Message::decode(unpadded)
        .map_err(|e| CallError::Encryption(format!("protobuf decode failed: {}", e)))?;

    // Extract call key
    CallEncryptionKey::from_protobuf(&proto_msg)
}

// ============================================================================
// SRTP Key Derivation
// ============================================================================

// HKDF labels extracted from VoIP WASM binary (Lpz4jsoR-Am.wasm)
const HKDF_LABEL_HBH_SRTP: &[u8] = b"hbh srtp key";
const HKDF_LABEL_UPLINK_SRTCP: &[u8] = b"uplink hbh srtcp key";
const HKDF_LABEL_DOWNLINK_SRTCP: &[u8] = b"downlink hbh srtcp key";
const HKDF_LABEL_E2E_SFRAME: &[u8] = b"e2e sframe key";
const HKDF_LABEL_WARP_AUTH: &[u8] = b"warp auth key";

/// SRTP keying material derived from call master key.
///
/// RFC 3711 SRTP uses a 128-bit master key and 112-bit master salt.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SrtpKeyingMaterial {
    /// 128-bit (16 bytes) master key for SRTP encryption
    pub master_key: [u8; 16],
    /// 112-bit (14 bytes) master salt for SRTP
    pub master_salt: [u8; 14],
}

impl std::fmt::Debug for SrtpKeyingMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpKeyingMaterial")
            .field("master_key", &"[REDACTED]")
            .field("master_salt", &"[REDACTED]")
            .finish()
    }
}

/// Complete derived key set for a call.
#[derive(Clone)]
pub struct DerivedCallKeys {
    /// Hop-by-hop SRTP keys (client <-> relay)
    pub hbh_srtp: SrtpKeyingMaterial,
    /// Uplink SRTCP keys (client -> relay)
    pub uplink_srtcp: SrtpKeyingMaterial,
    /// Downlink SRTCP keys (relay -> client)
    pub downlink_srtcp: SrtpKeyingMaterial,
    /// E2E sframe key (client <-> client, 32 bytes)
    pub e2e_sframe: [u8; 32],
    /// WARP authentication key (32 bytes)
    pub warp_auth: [u8; 32],
}

impl std::fmt::Debug for DerivedCallKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedCallKeys")
            .field("hbh_srtp", &self.hbh_srtp)
            .field("uplink_srtcp", &self.uplink_srtcp)
            .field("downlink_srtcp", &self.downlink_srtcp)
            .field("e2e_sframe", &"[REDACTED]")
            .field("warp_auth", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for DerivedCallKeys {
    fn zeroize(&mut self) {
        self.hbh_srtp.zeroize();
        self.uplink_srtcp.zeroize();
        self.downlink_srtcp.zeroize();
        self.e2e_sframe.zeroize();
        self.warp_auth.zeroize();
    }
}

impl Drop for DerivedCallKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn derive_srtp_material(hkdf: &hkdf::Hkdf<sha2::Sha256>, label: &[u8]) -> SrtpKeyingMaterial {
    let mut output = [0u8; 30]; // 16 bytes key + 14 bytes salt
    hkdf.expand(label, &mut output)
        .expect("valid output length");

    let mut master_key = [0u8; 16];
    let mut master_salt = [0u8; 14];
    master_key.copy_from_slice(&output[..16]);
    master_salt.copy_from_slice(&output[16..30]);

    SrtpKeyingMaterial {
        master_key,
        master_salt,
    }
}

/// Derive all call keys from the master call key using HKDF-SHA256.
pub fn derive_call_keys(call_key: &CallEncryptionKey) -> DerivedCallKeys {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(None, &call_key.master_key);

    let hbh_srtp = derive_srtp_material(&hkdf, HKDF_LABEL_HBH_SRTP);
    let uplink_srtcp = derive_srtp_material(&hkdf, HKDF_LABEL_UPLINK_SRTCP);
    let downlink_srtcp = derive_srtp_material(&hkdf, HKDF_LABEL_DOWNLINK_SRTCP);

    let mut e2e_sframe = [0u8; 32];
    hkdf.expand(HKDF_LABEL_E2E_SFRAME, &mut e2e_sframe)
        .expect("valid output length");

    let mut warp_auth = [0u8; 32];
    hkdf.expand(HKDF_LABEL_WARP_AUTH, &mut warp_auth)
        .expect("valid output length");

    DerivedCallKeys {
        hbh_srtp,
        uplink_srtcp,
        downlink_srtcp,
        e2e_sframe,
        warp_auth,
    }
}

/// Derive SRTP keying material for send and receive directions.
pub fn derive_srtp_keys(
    call_key: &CallEncryptionKey,
    is_initiator: bool,
) -> (SrtpKeyingMaterial, SrtpKeyingMaterial) {
    let keys = derive_call_keys(call_key);

    if is_initiator {
        (keys.uplink_srtcp.clone(), keys.downlink_srtcp.clone())
    } else {
        (keys.downlink_srtcp.clone(), keys.uplink_srtcp.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = CallEncryptionKey::generate();
        let key2 = CallEncryptionKey::generate();

        // Keys should be different (random)
        assert_ne!(key1.master_key, key2.master_key);
        // Generation starts at 1
        assert_eq!(key1.generation, 1);
    }

    #[test]
    fn test_key_to_protobuf() {
        let key = CallEncryptionKey::generate();
        let proto = key.to_protobuf();

        // Check that call field is present
        assert!(proto.call.is_some());
        let call = proto.call.as_ref().unwrap();
        assert!(call.call_key.is_some());
        let call_key = call.call_key.as_ref().unwrap();
        assert_eq!(call_key.len(), 32);
        assert_eq!(call_key.as_slice(), &key.master_key);
    }

    #[test]
    fn test_key_from_protobuf() {
        let original = CallEncryptionKey::generate();
        let proto = original.to_protobuf();
        let restored = CallEncryptionKey::from_protobuf(&proto).unwrap();

        assert_eq!(original.master_key, restored.master_key);
    }

    #[test]
    fn test_key_protobuf_roundtrip() {
        let original = CallEncryptionKey::generate();

        // Serialize to protobuf bytes
        let proto = original.to_protobuf();
        let bytes = proto.encode_to_vec();

        // Deserialize back
        let decoded = wa::Message::decode(bytes.as_slice()).unwrap();
        let restored = CallEncryptionKey::from_protobuf(&decoded).unwrap();

        assert_eq!(original.master_key, restored.master_key);
    }

    #[test]
    fn test_key_from_protobuf_missing_call() {
        let proto = wa::Message::default();
        let result = CallEncryptionKey::from_protobuf(&proto);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing call field")
        );
    }

    #[test]
    fn test_key_from_protobuf_missing_call_key() {
        let proto = wa::Message {
            call: Some(Box::new(message::Call::default())),
            ..Default::default()
        };
        let result = CallEncryptionKey::from_protobuf(&proto);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing call_key field")
        );
    }

    #[test]
    fn test_key_from_protobuf_wrong_length() {
        let proto = wa::Message {
            call: Some(Box::new(message::Call {
                call_key: Some(vec![0u8; 16]), // Wrong length
                ..Default::default()
            })),
            ..Default::default()
        };
        let result = CallEncryptionKey::from_protobuf(&proto);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong length"));
    }

    #[test]
    fn test_enc_type_from_str() {
        assert_eq!("msg".parse(), Ok(EncType::Msg));
        assert_eq!("pkmsg".parse(), Ok(EncType::PkMsg));
        assert!("unknown".parse::<EncType>().is_err());
    }

    #[test]
    fn test_enc_type_as_str() {
        assert_eq!(EncType::Msg.as_str(), "msg");
        assert_eq!(EncType::PkMsg.as_str(), "pkmsg");
    }

    #[test]
    fn test_derive_call_keys() {
        let call_key = CallEncryptionKey::generate();
        let keys = derive_call_keys(&call_key);

        // All keys should be non-zero
        assert_ne!(keys.hbh_srtp.master_key, [0u8; 16]);
        assert_ne!(keys.uplink_srtcp.master_key, [0u8; 16]);
        assert_ne!(keys.downlink_srtcp.master_key, [0u8; 16]);
        assert_ne!(keys.e2e_sframe, [0u8; 32]);
        assert_ne!(keys.warp_auth, [0u8; 32]);

        // Different labels should produce different keys
        assert_ne!(keys.hbh_srtp.master_key, keys.uplink_srtcp.master_key);
        assert_ne!(keys.uplink_srtcp.master_key, keys.downlink_srtcp.master_key);
    }

    #[test]
    fn test_srtp_key_derivation() {
        let call_key = CallEncryptionKey::generate();

        let (send_initiator, recv_initiator) = derive_srtp_keys(&call_key, true);
        let (send_responder, recv_responder) = derive_srtp_keys(&call_key, false);

        // Initiator's send keys should match responder's receive keys
        assert_eq!(send_initiator.master_key, recv_responder.master_key);
        assert_eq!(send_initiator.master_salt, recv_responder.master_salt);

        // Responder's send keys should match initiator's receive keys
        assert_eq!(send_responder.master_key, recv_initiator.master_key);
        assert_eq!(send_responder.master_salt, recv_initiator.master_salt);
    }

    #[test]
    fn test_srtp_keys_deterministic() {
        let call_key = CallEncryptionKey::generate();

        let keys1 = derive_call_keys(&call_key);
        let keys2 = derive_call_keys(&call_key);

        assert_eq!(keys1.hbh_srtp.master_key, keys2.hbh_srtp.master_key);
        assert_eq!(keys1.e2e_sframe, keys2.e2e_sframe);
        assert_eq!(keys1.warp_auth, keys2.warp_auth);
    }

    #[test]
    fn test_different_master_keys_produce_different_derived_keys() {
        let key1 = CallEncryptionKey::generate();
        let key2 = CallEncryptionKey::generate();

        let derived1 = derive_call_keys(&key1);
        let derived2 = derive_call_keys(&key2);

        assert_ne!(derived1.hbh_srtp.master_key, derived2.hbh_srtp.master_key);
        assert_ne!(derived1.e2e_sframe, derived2.e2e_sframe);
    }

    #[test]
    fn test_pkcs7_padding() {
        // 15 bytes -> padded to 16 with 1 byte of 0x01
        let data = vec![0u8; 15];
        let padded = pad_pkcs7(data);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[15], 1);

        // 16 bytes -> padded to 32 with 16 bytes of 0x10
        let data = vec![0u8; 16];
        let padded = pad_pkcs7(data);
        assert_eq!(padded.len(), 32);
        assert!(padded[16..].iter().all(|&b| b == 16));

        // 1 byte -> padded to 16 with 15 bytes of 0x0f
        let data = vec![0u8; 1];
        let padded = pad_pkcs7(data);
        assert_eq!(padded.len(), 16);
        assert!(padded[1..].iter().all(|&b| b == 15));
    }

    #[test]
    fn test_pkcs7_roundtrip() {
        let original = vec![1, 2, 3, 4, 5];
        let padded = pad_pkcs7(original.clone());
        let unpadded = unpad_pkcs7(&padded).unwrap();
        assert_eq!(unpadded, original.as_slice());
    }

    #[test]
    fn test_pkcs7_unpad_invalid() {
        // Empty data
        assert!(unpad_pkcs7(&[]).is_err());

        // Invalid padding value (0)
        assert!(unpad_pkcs7(&[1, 2, 3, 0]).is_err());

        // Padding value too large
        assert!(unpad_pkcs7(&[1, 2, 3, 17]).is_err());

        // Inconsistent padding bytes
        assert!(unpad_pkcs7(&[1, 2, 2, 3]).is_err());
    }
}
