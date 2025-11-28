use crate::libsignal::crypto::CryptographicHash;
use anyhow::{Result, anyhow};
use base64::Engine as _;
use rand_core::{OsRng, TryRngCore};

pub struct MessageUtils;

impl MessageUtils {
    pub fn pad_message_v2(mut plaintext: Vec<u8>) -> Vec<u8> {
        let mut rng = OsRng;
        let mut pad_val = (rng
            .try_next_u32()
            .expect("OsRng failed while generating padding") as u8)
            & 0x0F;
        if pad_val == 0 {
            pad_val = 0x0F;
        }

        let padding = vec![pad_val; pad_val as usize];
        plaintext.extend_from_slice(&padding);
        plaintext
    }

    pub fn participant_list_hash(devices: &[wacore_binary::jid::Jid]) -> Result<String> {
        let mut jids: Vec<String> = devices.iter().map(|j| j.to_ad_string()).collect();
        jids.sort();

        let concatenated_jids = jids.join("");

        let full_hash = {
            let mut h = CryptographicHash::new("SHA-256")
                .map_err(|e| anyhow!("failed to initialize SHA-256 hasher: {:?}", e))?;
            h.update(concatenated_jids.as_bytes());
            let v = h.finalize();
            <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| anyhow!("unexpected SHA-256 hash length"))?
        };

        let truncated_hash = &full_hash[..6];

        Ok(format!(
            "2:{hash}",
            hash = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(truncated_hash)
        ))
    }

    pub fn unpad_message_ref(plaintext: &[u8], version: u8) -> Result<&[u8], anyhow::Error> {
        if version == 3 {
            return Ok(plaintext);
        }
        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
        }
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        if pad_len == 0 || pad_len > plaintext.len() {
            return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
        }
        let (data, padding) = plaintext.split_at(plaintext.len() - pad_len);
        for &byte in padding {
            if byte != pad_len as u8 {
                return Err(anyhow::anyhow!("invalid padding bytes"));
            }
        }
        Ok(data)
    }
}
