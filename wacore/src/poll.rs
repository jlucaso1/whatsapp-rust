//! Poll vote encryption/decryption (AES-256-GCM + HKDF-SHA256).
//!
//! Matches WAWebPollVoteEncryptMsgData / WAUseCaseSecret.

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::libsignal::crypto::{Aes256GcmDecryption, Aes256GcmEncryption};

const GCM_IV_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;

/// Votes reference options by SHA-256 hash, not by name.
pub fn compute_option_hash(option_name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(option_name.as_bytes());
    hasher.finalize().into()
}

/// HKDF-SHA256: info = stanzaId || pollCreator || voter || "Poll Vote", no salt.
/// Matches WA Web's `createUseCaseSecret()` with UseCase = "Poll Vote".
pub fn derive_vote_encryption_key(
    message_secret: &[u8],
    stanza_id: &str,
    poll_creator_jid: &str,
    voter_jid: &str,
) -> Result<[u8; 32]> {
    if message_secret.len() != 32 {
        return Err(anyhow!(
            "Invalid messageSecret size: expected 32, got {}",
            message_secret.len()
        ));
    }

    let mut info = Vec::new();
    info.extend_from_slice(stanza_id.as_bytes());
    info.extend_from_slice(poll_creator_jid.as_bytes());
    info.extend_from_slice(voter_jid.as_bytes());
    info.extend_from_slice(b"Poll Vote");

    let hk = Hkdf::<Sha256>::new(None, message_secret);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;

    Ok(key)
}

/// AAD = stanzaId + "\0" + voterJid (WAWebAddonEncryption.js:10)
fn build_vote_aad(stanza_id: &str, voter_jid: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(stanza_id.len() + 1 + voter_jid.len());
    aad.extend_from_slice(stanza_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(voter_jid.as_bytes());
    aad
}

/// Returns `(encrypted_payload_with_tag, iv)`.
pub fn encrypt_poll_vote(
    selected_option_hashes: &[Vec<u8>],
    encryption_key: &[u8; 32],
    stanza_id: &str,
    voter_jid: &str,
) -> Result<(Vec<u8>, [u8; GCM_IV_SIZE])> {
    use prost::Message;
    use rand::RngExt;

    let vote_msg = waproto::whatsapp::message::PollVoteMessage {
        selected_options: selected_option_hashes.to_vec(),
    };

    let mut plaintext = Vec::new();
    vote_msg.encode(&mut plaintext)?;

    let mut iv = [0u8; GCM_IV_SIZE];
    rand::make_rng::<rand::rngs::StdRng>().fill(&mut iv);

    let aad = build_vote_aad(stanza_id, voter_jid);

    let mut payload = plaintext;
    let mut enc = Aes256GcmEncryption::new(encryption_key, &iv, &aad)
        .map_err(|e| anyhow!("AES-GCM init failed: {e}"))?;
    enc.encrypt(&mut payload);
    let tag = enc.compute_tag();
    payload.extend_from_slice(&tag);

    Ok((payload, iv))
}

/// Returns the selected option hashes (each 32 bytes).
pub fn decrypt_poll_vote(
    enc_payload: &[u8],
    iv: &[u8],
    encryption_key: &[u8; 32],
    stanza_id: &str,
    voter_jid: &str,
) -> Result<Vec<Vec<u8>>> {
    use prost::Message as _;

    if iv.len() != GCM_IV_SIZE {
        return Err(anyhow!(
            "Invalid IV size: expected {GCM_IV_SIZE}, got {}",
            iv.len()
        ));
    }

    if enc_payload.len() < GCM_TAG_SIZE {
        return Err(anyhow!(
            "Encrypted payload too short: need at least {GCM_TAG_SIZE} bytes for tag, got {}",
            enc_payload.len()
        ));
    }

    let (ciphertext, tag) = enc_payload.split_at(enc_payload.len() - GCM_TAG_SIZE);
    let aad = build_vote_aad(stanza_id, voter_jid);

    let mut plaintext = ciphertext.to_vec();
    let mut dec = Aes256GcmDecryption::new(encryption_key, iv, &aad)
        .map_err(|e| anyhow!("AES-GCM init failed: {e}"))?;
    dec.decrypt(&mut plaintext);
    dec.verify_tag(tag)
        .map_err(|_| anyhow!("Poll vote GCM tag verification failed"))?;

    let vote_msg = waproto::whatsapp::message::PollVoteMessage::decode(&plaintext[..])?;
    Ok(vote_msg.selected_options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_hash_deterministic() {
        let h1 = compute_option_hash("Option A");
        let h2 = compute_option_hash("Option A");
        let h3 = compute_option_hash("Option B");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn vote_key_derivation_deterministic() {
        let secret = [0xABu8; 32];
        let k1 = derive_vote_encryption_key(
            &secret,
            "msg123",
            "creator@s.whatsapp.net",
            "voter@s.whatsapp.net",
        )
        .unwrap();
        let k2 = derive_vote_encryption_key(
            &secret,
            "msg123",
            "creator@s.whatsapp.net",
            "voter@s.whatsapp.net",
        )
        .unwrap();
        assert_eq!(k1, k2);

        let k3 = derive_vote_encryption_key(
            &secret,
            "msg123",
            "creator@s.whatsapp.net",
            "other@s.whatsapp.net",
        )
        .unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn vote_encrypt_decrypt_roundtrip() {
        let secret = [0xCDu8; 32];
        let stanza_id = "3EB0ABCD1234";
        let creator = "creator@s.whatsapp.net";
        let voter = "voter@s.whatsapp.net";

        let key = derive_vote_encryption_key(&secret, stanza_id, creator, voter).unwrap();

        let option_hashes = vec![
            compute_option_hash("Yes").to_vec(),
            compute_option_hash("No").to_vec(),
        ];

        let (enc_payload, iv) = encrypt_poll_vote(&option_hashes, &key, stanza_id, voter).unwrap();
        let decrypted = decrypt_poll_vote(&enc_payload, &iv, &key, stanza_id, voter).unwrap();

        assert_eq!(decrypted, option_hashes);
    }

    #[test]
    fn vote_decrypt_wrong_key_fails() {
        let secret = [0xCDu8; 32];
        let stanza_id = "3EB0ABCD1234";
        let creator = "creator@s.whatsapp.net";
        let voter = "voter@s.whatsapp.net";

        let key = derive_vote_encryption_key(&secret, stanza_id, creator, voter).unwrap();
        let option_hashes = vec![compute_option_hash("Yes").to_vec()];
        let (enc_payload, iv) = encrypt_poll_vote(&option_hashes, &key, stanza_id, voter).unwrap();

        let wrong_key =
            derive_vote_encryption_key(&secret, stanza_id, creator, "wrong@s.whatsapp.net")
                .unwrap();
        assert!(
            decrypt_poll_vote(
                &enc_payload,
                &iv,
                &wrong_key,
                stanza_id,
                "wrong@s.whatsapp.net"
            )
            .is_err()
        );
    }

    #[test]
    fn vote_decrypt_wrong_aad_fails() {
        let secret = [0xCDu8; 32];
        let stanza_id = "3EB0ABCD1234";
        let creator = "creator@s.whatsapp.net";
        let voter = "voter@s.whatsapp.net";

        let key = derive_vote_encryption_key(&secret, stanza_id, creator, voter).unwrap();
        let option_hashes = vec![compute_option_hash("Yes").to_vec()];
        let (enc_payload, iv) = encrypt_poll_vote(&option_hashes, &key, stanza_id, voter).unwrap();

        assert!(decrypt_poll_vote(&enc_payload, &iv, &key, "wrong_stanza", voter).is_err());
    }

    #[test]
    fn empty_vote_roundtrip() {
        let secret = [0xEFu8; 32];
        let key = derive_vote_encryption_key(&secret, "id", "c@s.whatsapp.net", "v@s.whatsapp.net")
            .unwrap();

        let (enc, iv) = encrypt_poll_vote(&[], &key, "id", "v@s.whatsapp.net").unwrap();
        let dec = decrypt_poll_vote(&enc, &iv, &key, "id", "v@s.whatsapp.net").unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn vote_decrypt_invalid_iv_length_fails() {
        let secret = [0xCDu8; 32];
        let key = derive_vote_encryption_key(&secret, "id", "c@s.whatsapp.net", "v@s.whatsapp.net")
            .unwrap();
        let option_hashes = vec![compute_option_hash("Yes").to_vec()];
        let (enc_payload, _iv) =
            encrypt_poll_vote(&option_hashes, &key, "id", "v@s.whatsapp.net").unwrap();

        let bad_iv = [0u8; 8]; // wrong length
        assert!(decrypt_poll_vote(&enc_payload, &bad_iv, &key, "id", "v@s.whatsapp.net").is_err());
    }
}
