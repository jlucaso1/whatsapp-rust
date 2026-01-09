//! SRTP (Secure Real-time Transport Protocol) encryption.
//!
//! Implements RFC 3711 SRTP for encrypting/decrypting RTP media packets.
//!
//! # Key Derivation
//!
//! SRTP derives session keys from the master key and salt using a PRF:
//! - Session encryption key (128 bits)
//! - Session authentication key (160 bits for HMAC-SHA1)
//! - Session salt (112 bits)

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::rtp::{RtpHeader, RtpPacket};
use crate::calls::SrtpKeyingMaterial;

/// SRTP crypto context for a single direction (send or receive).
#[derive(Clone)]
pub struct SrtpContext {
    /// Session encryption key (16 bytes for AES-128).
    session_key: [u8; 16],
    /// Session salt (14 bytes).
    session_salt: [u8; 14],
    /// Session authentication key (20 bytes for HMAC-SHA1).
    auth_key: [u8; 20],
    /// Rollover counter for extended sequence number.
    roc: u32,
    /// Last seen sequence number (for ROC calculation).
    last_seq: u16,
    /// Whether this context has been initialized with a packet.
    initialized: bool,
}

impl std::fmt::Debug for SrtpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpContext")
            .field("session_key", &"[REDACTED]")
            .field("session_salt", &"[REDACTED]")
            .field("auth_key", &"[REDACTED]")
            .field("roc", &self.roc)
            .field("last_seq", &self.last_seq)
            .field("initialized", &self.initialized)
            .finish()
    }
}

/// SRTP authentication tag length (10 bytes for RTP, as per RFC 3711).
pub const SRTP_AUTH_TAG_LEN: usize = 10;

/// SRTP key derivation label for encryption key.
const LABEL_RTP_ENCRYPTION: u8 = 0x00;
/// SRTP key derivation label for authentication key.
const LABEL_RTP_AUTH: u8 = 0x01;
/// SRTP key derivation label for salt.
const LABEL_RTP_SALT: u8 = 0x02;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type HmacSha1 = Hmac<Sha1>;

impl SrtpContext {
    /// Create a new SRTP context from keying material.
    pub fn new(keying: &SrtpKeyingMaterial) -> Self {
        // Derive session keys using SRTP PRF (AES-CM)
        let session_key = Self::derive_key(
            &keying.master_key,
            &keying.master_salt,
            LABEL_RTP_ENCRYPTION,
            16,
        );
        let auth_key =
            Self::derive_key(&keying.master_key, &keying.master_salt, LABEL_RTP_AUTH, 20);
        let salt_bytes =
            Self::derive_key(&keying.master_key, &keying.master_salt, LABEL_RTP_SALT, 14);

        let mut session_key_arr = [0u8; 16];
        let mut auth_key_arr = [0u8; 20];
        let mut session_salt = [0u8; 14];

        session_key_arr.copy_from_slice(&session_key);
        auth_key_arr.copy_from_slice(&auth_key);
        session_salt.copy_from_slice(&salt_bytes);

        Self {
            session_key: session_key_arr,
            session_salt,
            auth_key: auth_key_arr,
            roc: 0,
            last_seq: 0,
            initialized: false,
        }
    }

    /// Derive a session key using SRTP PRF (AES-CM).
    fn derive_key(master_key: &[u8; 16], master_salt: &[u8; 14], label: u8, len: usize) -> Vec<u8> {
        // Key derivation rate = 0 (derive once)
        // x = (label << 48) for 112-bit salt
        let mut x = [0u8; 16];
        // Copy salt to first 14 bytes
        x[..14].copy_from_slice(master_salt);
        // XOR label at byte 7 (label is at bit 48 from the right in the 112-bit value)
        x[7] ^= label;

        // Generate keystream using AES-CM
        let mut output = vec![0u8; len];
        let iv = x;

        // Use AES-CTR to generate key material
        let mut cipher = Aes128Ctr::new(master_key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut output);

        output
    }

    /// Update ROC based on sequence number.
    fn update_roc(&mut self, seq: u16) {
        if !self.initialized {
            self.last_seq = seq;
            self.initialized = true;
            return;
        }

        // Detect sequence number rollover
        let seq_i32 = seq as i32;
        let last_i32 = self.last_seq as i32;
        let diff = seq_i32 - last_i32;

        if diff > 32768 {
            // Sequence went backwards significantly - ROC should decrease
            // This shouldn't normally happen
        } else if diff < -32768 {
            // Sequence wrapped around - increment ROC
            self.roc = self.roc.wrapping_add(1);
        }

        self.last_seq = seq;
    }

    /// Get the 48-bit packet index (ROC || SEQ).
    fn packet_index(&self, seq: u16) -> u64 {
        ((self.roc as u64) << 16) | (seq as u64)
    }

    /// Generate IV for AES-CTR encryption.
    fn generate_iv(&self, ssrc: u32, index: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];

        // IV = (salt << 16) XOR (SSRC << 64) XOR (index << 16)
        // First, copy salt (14 bytes) starting at byte 0
        iv[..14].copy_from_slice(&self.session_salt);

        // XOR SSRC at bytes 4-7
        ssrc.to_be_bytes()
            .iter()
            .zip(&mut iv[4..8])
            .for_each(|(src, dst)| *dst ^= src);

        // XOR index at bytes 8-13 (48-bit index, 6 bytes)
        index.to_be_bytes()[2..]
            .iter()
            .zip(&mut iv[8..14])
            .for_each(|(src, dst)| *dst ^= src);

        iv
    }

    /// Encrypt an RTP packet (returns SRTP packet).
    ///
    /// The output format is:
    /// - RTP header (12+ bytes)
    /// - Encrypted payload
    /// - Authentication tag (10 bytes)
    pub fn protect(&mut self, packet: &RtpPacket) -> Result<Vec<u8>, SrtpError> {
        self.update_roc(packet.header.sequence_number);
        let index = self.packet_index(packet.header.sequence_number);

        // Encode header
        let header_size = packet.header.size();
        let mut output = vec![0u8; header_size + packet.payload.len() + SRTP_AUTH_TAG_LEN];

        packet
            .header
            .encode(&mut output[..header_size])
            .map_err(|e| SrtpError::Encryption(e.to_string()))?;

        // Encrypt payload using AES-CTR
        let iv = self.generate_iv(packet.header.ssrc, index);
        let mut cipher = Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into());

        // Copy and encrypt payload
        output[header_size..header_size + packet.payload.len()].copy_from_slice(&packet.payload);
        cipher.apply_keystream(&mut output[header_size..header_size + packet.payload.len()]);

        // Calculate authentication tag
        let auth_portion_len = header_size + packet.payload.len();
        let tag = self.compute_auth_tag(&output[..auth_portion_len], self.roc)?;
        output[auth_portion_len..].copy_from_slice(&tag);

        Ok(output)
    }

    /// Decrypt an SRTP packet (returns RTP packet).
    pub fn unprotect(&mut self, data: &[u8]) -> Result<RtpPacket, SrtpError> {
        if data.len() < 12 + SRTP_AUTH_TAG_LEN {
            return Err(SrtpError::PacketTooShort(data.len()));
        }

        // Parse header to get sequence number and SSRC
        let header = RtpHeader::decode(data).map_err(|e| SrtpError::Decryption(e.to_string()))?;

        let header_size = header.size();
        let payload_len = data.len() - header_size - SRTP_AUTH_TAG_LEN;

        // Update ROC and get packet index
        self.update_roc(header.sequence_number);
        let index = self.packet_index(header.sequence_number);

        // Verify authentication tag
        let auth_portion = &data[..data.len() - SRTP_AUTH_TAG_LEN];
        let received_tag = &data[data.len() - SRTP_AUTH_TAG_LEN..];
        let computed_tag = self.compute_auth_tag(auth_portion, self.roc)?;

        if received_tag != computed_tag.as_slice() {
            return Err(SrtpError::AuthenticationFailed);
        }

        // Decrypt payload
        let iv = self.generate_iv(header.ssrc, index);
        let mut cipher = Aes128Ctr::new(self.session_key.as_slice().into(), iv.as_slice().into());

        let mut payload = data[header_size..header_size + payload_len].to_vec();
        cipher.apply_keystream(&mut payload);

        Ok(RtpPacket::new(header, payload))
    }

    /// Compute HMAC-SHA1 authentication tag.
    fn compute_auth_tag(
        &self,
        data: &[u8],
        roc: u32,
    ) -> Result<[u8; SRTP_AUTH_TAG_LEN], SrtpError> {
        let mut mac = HmacSha1::new_from_slice(&self.auth_key)
            .map_err(|e| SrtpError::Encryption(e.to_string()))?;

        mac.update(data);
        mac.update(&roc.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut tag = [0u8; SRTP_AUTH_TAG_LEN];
        tag.copy_from_slice(&result[..SRTP_AUTH_TAG_LEN]);

        Ok(tag)
    }
}

/// SRTP session with send and receive contexts.
pub struct SrtpSession {
    /// Context for encrypting outgoing packets.
    pub send_ctx: SrtpContext,
    /// Context for decrypting incoming packets.
    pub recv_ctx: SrtpContext,
}

impl SrtpSession {
    /// Create a new SRTP session.
    ///
    /// # Arguments
    /// * `send_key` - Keying material for encrypting outgoing packets
    /// * `recv_key` - Keying material for decrypting incoming packets
    pub fn new(send_key: &SrtpKeyingMaterial, recv_key: &SrtpKeyingMaterial) -> Self {
        Self {
            send_ctx: SrtpContext::new(send_key),
            recv_ctx: SrtpContext::new(recv_key),
        }
    }

    /// Encrypt an outgoing RTP packet.
    pub fn protect(&mut self, packet: &RtpPacket) -> Result<Vec<u8>, SrtpError> {
        self.send_ctx.protect(packet)
    }

    /// Decrypt an incoming SRTP packet.
    pub fn unprotect(&mut self, data: &[u8]) -> Result<RtpPacket, SrtpError> {
        self.recv_ctx.unprotect(data)
    }
}

impl std::fmt::Debug for SrtpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrtpSession")
            .field("send_ctx", &self.send_ctx)
            .field("recv_ctx", &self.recv_ctx)
            .finish()
    }
}

/// Errors from SRTP operations.
#[derive(Debug, thiserror::Error)]
pub enum SrtpError {
    #[error("Packet too short: {0} bytes")]
    PacketTooShort(usize),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calls::media::rtp::RtpHeader;

    fn test_keying_material() -> SrtpKeyingMaterial {
        SrtpKeyingMaterial {
            master_key: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            master_salt: [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            ],
        }
    }

    #[test]
    fn test_srtp_context_creation() {
        let keying = test_keying_material();
        let ctx = SrtpContext::new(&keying);

        assert_eq!(ctx.roc, 0);
        assert!(!ctx.initialized);
    }

    #[test]
    fn test_srtp_protect_unprotect_roundtrip() {
        let keying = test_keying_material();
        let mut send_ctx = SrtpContext::new(&keying);
        let mut recv_ctx = SrtpContext::new(&keying);

        let header = RtpHeader::new(111, 1000, 160000, 0x12345678);
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let packet = RtpPacket::new(header, payload.clone());

        // Encrypt
        let encrypted = send_ctx.protect(&packet).unwrap();

        // Should be larger than original (auth tag added)
        assert!(encrypted.len() > 12 + payload.len());
        assert_eq!(encrypted.len(), 12 + payload.len() + SRTP_AUTH_TAG_LEN);

        // Payload should be encrypted (different from original)
        let encrypted_payload = &encrypted[12..12 + payload.len()];
        assert_ne!(encrypted_payload, payload.as_slice());

        // Decrypt
        let decrypted = recv_ctx.unprotect(&encrypted).unwrap();

        assert_eq!(decrypted.header.sequence_number, 1000);
        assert_eq!(decrypted.header.timestamp, 160000);
        assert_eq!(decrypted.header.ssrc, 0x12345678);
        assert_eq!(decrypted.payload, payload);
    }

    #[test]
    fn test_srtp_session_roundtrip() {
        let send_key = test_keying_material();
        let recv_key = test_keying_material();

        let mut session = SrtpSession::new(&send_key, &recv_key);

        let header = RtpHeader::new(111, 5000, 800000, 0xDEADBEEF);
        let payload = b"Hello SRTP!".to_vec();
        let packet = RtpPacket::new(header, payload.clone());

        let encrypted = session.protect(&packet).unwrap();
        let decrypted = session.unprotect(&encrypted).unwrap();

        assert_eq!(decrypted.payload, payload);
    }

    #[test]
    fn test_srtp_authentication_failure() {
        let keying = test_keying_material();
        let mut send_ctx = SrtpContext::new(&keying);
        let mut recv_ctx = SrtpContext::new(&keying);

        let header = RtpHeader::new(111, 1000, 160000, 0x12345678);
        let payload = vec![1, 2, 3, 4, 5];
        let packet = RtpPacket::new(header, payload);

        let mut encrypted = send_ctx.protect(&packet).unwrap();

        // Tamper with the encrypted data
        encrypted[15] ^= 0xFF;

        // Decryption should fail due to auth check
        let result = recv_ctx.unprotect(&encrypted);
        assert!(matches!(result, Err(SrtpError::AuthenticationFailed)));
    }

    #[test]
    fn test_srtp_sequence_number_progression() {
        let keying = test_keying_material();
        let mut send_ctx = SrtpContext::new(&keying);
        let mut recv_ctx = SrtpContext::new(&keying);

        // Send multiple packets with increasing sequence numbers
        for seq in 1000u16..1010 {
            let header = RtpHeader::new(111, seq, seq as u32 * 160, 0x12345678);
            let payload = vec![seq as u8; 10];
            let packet = RtpPacket::new(header, payload.clone());

            let encrypted = send_ctx.protect(&packet).unwrap();
            let decrypted = recv_ctx.unprotect(&encrypted).unwrap();

            assert_eq!(decrypted.header.sequence_number, seq);
            assert_eq!(decrypted.payload, payload);
        }
    }

    #[test]
    fn test_srtp_different_keys_fail() {
        let send_key = SrtpKeyingMaterial {
            master_key: [1u8; 16],
            master_salt: [2u8; 14],
        };
        let recv_key = SrtpKeyingMaterial {
            master_key: [3u8; 16], // Different key
            master_salt: [4u8; 14],
        };

        let mut send_ctx = SrtpContext::new(&send_key);
        let mut recv_ctx = SrtpContext::new(&recv_key);

        let header = RtpHeader::new(111, 1000, 160000, 0x12345678);
        let packet = RtpPacket::new(header, vec![1, 2, 3, 4, 5]);

        let encrypted = send_ctx.protect(&packet).unwrap();

        // Should fail with different keys
        let result = recv_ctx.unprotect(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_srtp_packet_too_short() {
        let keying = test_keying_material();
        let mut ctx = SrtpContext::new(&keying);

        // Packet that's too short (less than header + auth tag)
        let short_data = vec![0u8; 10];
        let result = ctx.unprotect(&short_data);
        assert!(matches!(result, Err(SrtpError::PacketTooShort(_))));
    }
}
