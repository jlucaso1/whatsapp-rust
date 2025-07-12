use crate::store::Device;
use crate::runtime::ProcessResult;

/// Core client containing only platform-independent protocol logic
pub struct CoreClient {
    /// Core device data
    pub device: Device,
}

impl CoreClient {
    /// Creates a new core client with the given device
    pub fn new(device: Device) -> Self {
        Self { device }
    }

    /// Processes an incoming message/event and returns the result
    /// This is a pure function that doesn't perform any I/O
    pub fn process_incoming_data(
        &self,
        _data: &[u8],
    ) -> ProcessResult {
        // TODO: Implement core message processing logic
        // This would include:
        // - Binary protocol parsing
        // - Message decryption
        // - Event generation
        // But without any I/O operations
        
        ProcessResult::new()
    }

    /// Prepares outgoing data for sending
    /// This is a pure function that doesn't perform any I/O
    pub fn prepare_outgoing_message(
        &self,
        _message: &str, // placeholder
    ) -> ProcessResult {
        // TODO: Implement core message preparation logic
        // This would include:
        // - Message encryption
        // - Binary protocol encoding
        // But without any network operations
        
        ProcessResult::new()
    }

    /// Gets the current device state
    pub fn get_device(&self) -> &Device {
        &self.device
    }

    /// Updates device state (pure function)
    pub fn update_device(&mut self, device: Device) {
        self.device = device;
    }
}

/// Core message utilities that work without I/O
pub struct MessageUtils;

impl MessageUtils {
    /// Pads a message for encryption (pure function)
    pub fn pad_message_v2(mut plaintext: Vec<u8>) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut pad_val = rng.r#gen::<u8>() & 0x0F;
        if pad_val == 0 {
            pad_val = 0x0F;
        }

        let padding = vec![pad_val; pad_val as usize];
        plaintext.extend_from_slice(&padding);
        plaintext
    }

    /// Unpads a decrypted message (pure function)
    pub fn unpad_message(plaintext: &[u8], version: u8) -> Result<&[u8], String> {
        if version < 3 {
            if plaintext.is_empty() {
                return Err("plaintext is empty, cannot unpad".to_string());
            }
            let pad_len = plaintext[plaintext.len() - 1] as usize;
            if pad_len == 0 || pad_len > plaintext.len() {
                return Err(format!("invalid padding length: {}", pad_len));
            }

            // Validate that all padding bytes are correct
            let (data, padding) = plaintext.split_at(plaintext.len() - pad_len);
            for &byte in padding {
                if byte != pad_len as u8 {
                    return Err("invalid padding bytes".to_string());
                }
            }
            Ok(data)
        } else {
            Ok(plaintext)
        }
    }

    /// Creates a participant list hash (pure function)
    pub fn participant_list_hash(devices: &[crate::types::jid::Jid]) -> String {
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
        use sha2::{Digest, Sha256};

        let mut jids: Vec<String> = devices.iter().map(|j| j.to_ad_string()).collect();
        jids.sort();

        // Concatenate all JIDs into a single string before hashing
        let concatenated_jids = jids.join("");

        let mut hasher = Sha256::new();
        hasher.update(concatenated_jids.as_bytes());
        let full_hash = hasher.finalize();

        // Truncate the hash to the first 6 bytes
        let truncated_hash = &full_hash[..6];

        // Encode using base64 without padding
        format!("2:{hash}", hash = STANDARD_NO_PAD.encode(truncated_hash))
    }
}