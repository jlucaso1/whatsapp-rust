//! Media retry protocol: crypto + node building for requesting media reupload.
//!
//! When a media download fails (e.g., expired URL), the client can request
//! the server to re-upload the media. This module handles:
//! - Encrypting the `ServerErrorReceipt` protobuf (HKDF + AES-256-GCM)
//! - Building the `<receipt type="server-error">` stanza
//! - Decrypting the `MediaRetryNotification` response
//! - Parsing the notification node
//!
//! Reference: WAWebCryptoMediaRetry, WAWebSendServerErrorReceiptJob,
//! WAWebHandleMediaRetryNotification (docs/captured-js/).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use prost::Message;
use rand::Rng;
use sha2::Sha256;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};
use waproto::whatsapp as wa;

const MEDIA_RETRY_HKDF_INFO: &str = "WhatsApp Media Retry Notification";
const ENC_IV_SIZE: usize = 12;

/// Result of a media retry request.
#[derive(Debug, Clone)]
pub enum MediaRetryResult {
    /// Server re-uploaded the media; new path available.
    Success {
        direct_path: String,
    },
    GeneralError,
    NotFound,
    DecryptionError,
}

/// Derive a 32-byte AES-256-GCM key from a media key using HKDF-SHA256.
///
/// WA Web: `WACryptoHkdf.extractAndExpand(mediaKey, "WhatsApp Media Retry Notification", 32)`
fn derive_media_retry_key(media_key: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, media_key);
    let mut key = [0u8; 32];
    hk.expand(MEDIA_RETRY_HKDF_INFO.as_bytes(), &mut key)
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;
    Ok(key)
}

/// Extract byte content from a Node.
fn get_bytes_content(node: &Node) -> Option<&[u8]> {
    match &node.content {
        Some(NodeContent::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

/// Encrypt a `ServerErrorReceipt` protobuf for a media retry request.
///
/// Returns `(ciphertext, iv)`.
///
/// WA Web: `WAWebCryptoMediaRetry.encryptServerErrorReceipt(mediaKey, stanzaId)`
pub fn encrypt_media_retry_receipt(
    media_key: &[u8],
    stanza_id: &str,
) -> Result<(Vec<u8>, [u8; ENC_IV_SIZE])> {
    let key = derive_media_retry_key(media_key)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES-GCM key init failed: {e}"))?;

    let mut iv = [0u8; ENC_IV_SIZE];
    rand::make_rng::<rand::rngs::StdRng>().fill_bytes(&mut iv);

    let receipt = wa::ServerErrorReceipt {
        stanza_id: Some(stanza_id.to_string()),
    };
    let plaintext = receipt.encode_to_vec();

    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: stanza_id.as_bytes(),
            },
        )
        .map_err(|e| anyhow!("AES-GCM encrypt failed: {e}"))?;

    Ok((ciphertext, iv))
}

/// Decrypt a `MediaRetryNotification` protobuf from the server response.
///
/// WA Web: `WAWebCryptoMediaRetry.decryptMediaRetryNotification(mediaKey, stanzaId, iv, ciphertext)`
pub fn decrypt_media_retry_notification(
    media_key: &[u8],
    stanza_id: &str,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<wa::MediaRetryNotification> {
    let key = derive_media_retry_key(media_key)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("AES-GCM key init failed: {e}"))?;

    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: stanza_id.as_bytes(),
            },
        )
        .map_err(|e| anyhow!("AES-GCM decrypt failed: {e}"))?;

    wa::MediaRetryNotification::decode(plaintext.as_slice())
        .map_err(|e| anyhow!("protobuf decode failed: {e}"))
}

/// Build the `<receipt type="server-error">` node for a media retry request.
///
/// WA Web: `WAWebSendServerErrorReceiptJob`
///
/// ```text
/// <receipt type="server-error" to="{own_jid}" id="{msg_id}">
///   <encrypt>
///     <enc_p>{ciphertext}</enc_p>
///     <enc_iv>{iv}</enc_iv>
///   </encrypt>
///   <rmr jid="{chat_jid}" from_me="{is_from_me}" participant="{participant}"/>
/// </receipt>
/// ```
pub fn build_media_retry_receipt(
    own_jid: &Jid,
    msg_id: &str,
    chat_jid: &Jid,
    is_from_me: bool,
    participant: Option<&Jid>,
    ciphertext: &[u8],
    iv: &[u8],
) -> Node {
    let encrypt_node = NodeBuilder::new("encrypt")
        .children([
            NodeBuilder::new("enc_p").bytes(ciphertext.to_vec()).build(),
            NodeBuilder::new("enc_iv").bytes(iv.to_vec()).build(),
        ])
        .build();

    let mut rmr_builder = NodeBuilder::new("rmr")
        .attr("jid", chat_jid.to_string())
        .attr("from_me", is_from_me.to_string());

    if let Some(p) = participant {
        rmr_builder = rmr_builder.attr("participant", p.to_string());
    }

    NodeBuilder::new("receipt")
        .attr("type", "server-error")
        .attr("to", own_jid.to_string())
        .attr("id", msg_id)
        .children([encrypt_node, rmr_builder.build()])
        .build()
}

/// Parse a `<notification type="mediaretry">` node into a `MediaRetryResult`.
///
/// The node may contain:
/// - `<error code="N">` — server-side error
/// - `<encrypt>` with `<enc_p>` and `<enc_iv>` — encrypted success response
///
/// WA Web: `WAWebHandleMediaRetryNotification`
pub fn parse_media_retry_notification(node: &Node, media_key: &[u8]) -> Result<MediaRetryResult> {
    let msg_id = node
        .attrs()
        .optional_string("id")
        .ok_or_else(|| anyhow!("notification missing 'id' attribute"))?
        .to_string();

    // Check for error child first
    if let Some(error_node) = node.get_optional_child_by_tag(&["error"]) {
        let code = error_node
            .attrs()
            .optional_string("code")
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);
        return Ok(match code {
            2 => MediaRetryResult::NotFound,
            3 => MediaRetryResult::DecryptionError,
            _ => MediaRetryResult::GeneralError,
        });
    }

    // Decrypt success response
    let encrypt_node = node
        .get_optional_child_by_tag(&["encrypt"])
        .ok_or_else(|| anyhow!("notification has neither <error> nor <encrypt> child"))?;

    let enc_p = encrypt_node
        .get_optional_child_by_tag(&["enc_p"])
        .and_then(get_bytes_content)
        .ok_or_else(|| anyhow!("missing enc_p in encrypt node"))?;

    let enc_iv = encrypt_node
        .get_optional_child_by_tag(&["enc_iv"])
        .and_then(get_bytes_content)
        .ok_or_else(|| anyhow!("missing enc_iv in encrypt node"))?;

    let notification = decrypt_media_retry_notification(media_key, &msg_id, enc_iv, enc_p)?;

    // Validate stanza ID matches
    if let Some(ref returned_id) = notification.stanza_id
        && returned_id != &msg_id
    {
        return Err(anyhow!(
            "stanza ID mismatch: expected {msg_id}, got {returned_id}"
        ));
    }

    // Check result enum
    let result_type = notification.result.unwrap_or(0);
    match wa::media_retry_notification::ResultType::try_from(result_type) {
        Ok(wa::media_retry_notification::ResultType::Success) => {
            let direct_path = notification
                .direct_path
                .ok_or_else(|| anyhow!("SUCCESS result but no directPath"))?;
            Ok(MediaRetryResult::Success { direct_path })
        }
        Ok(wa::media_retry_notification::ResultType::NotFound) => Ok(MediaRetryResult::NotFound),
        Ok(wa::media_retry_notification::ResultType::DecryptionError) => {
            Ok(MediaRetryResult::DecryptionError)
        }
        _ => Ok(MediaRetryResult::GeneralError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let media_key = [42u8; 32];
        let stanza_id = "TEST-MSG-ID-123";

        let (ciphertext, iv) = encrypt_media_retry_receipt(&media_key, stanza_id).unwrap();

        let notification =
            decrypt_media_retry_notification(&media_key, stanza_id, &iv, &ciphertext).unwrap();

        assert_eq!(notification.stanza_id.as_deref(), Some(stanza_id));
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let media_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let stanza_id = "TEST-MSG-ID-456";

        let (ciphertext, iv) = encrypt_media_retry_receipt(&media_key, stanza_id).unwrap();

        let result = decrypt_media_retry_notification(&wrong_key, stanza_id, &iv, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn build_receipt_node_structure() {
        let own_jid = Jid::pn("1234567890");
        let chat_jid = Jid::pn("9876543210");
        let msg_id = "ABC123";

        let (ciphertext, iv) = encrypt_media_retry_receipt(&[1u8; 32], msg_id).unwrap();

        let node =
            build_media_retry_receipt(&own_jid, msg_id, &chat_jid, false, None, &ciphertext, &iv);

        assert_eq!(node.tag.as_ref(), "receipt");
        assert_eq!(
            node.attrs().optional_string("type").unwrap().as_ref(),
            "server-error"
        );
        assert_eq!(node.attrs().optional_string("id").unwrap().as_ref(), msg_id);

        let encrypt = node.get_optional_child_by_tag(&["encrypt"]);
        assert!(encrypt.is_some());

        let rmr = node.get_optional_child_by_tag(&["rmr"]);
        assert!(rmr.is_some());
        let rmr = rmr.unwrap();
        assert_eq!(
            rmr.attrs().optional_string("from_me").unwrap().as_ref(),
            "false"
        );
    }

    #[test]
    fn build_receipt_with_participant() {
        let own_jid = Jid::pn("1234567890");
        let chat_jid = Jid::group("120363040237990503");
        let participant = Jid::pn("9876543210");

        let (ciphertext, iv) = encrypt_media_retry_receipt(&[1u8; 32], "MSG1").unwrap();

        let node = build_media_retry_receipt(
            &own_jid,
            "MSG1",
            &chat_jid,
            false,
            Some(&participant),
            &ciphertext,
            &iv,
        );

        let rmr = node.get_optional_child_by_tag(&["rmr"]).unwrap();
        assert!(rmr.attrs().optional_string("participant").is_some());
    }
}
