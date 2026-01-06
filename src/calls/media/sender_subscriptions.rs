//! SenderSubscriptions builder for STUN 0x4000 attribute.
//!
//! WhatsApp uses a protobuf-encoded SenderSubscriptions message in the
//! STUN Allocate request to tell the relay what streams we're sending.
//!
//! This module provides helpers to construct these subscription messages.

use prost::Message;
use waproto::voip::{PayloadType, SenderSubscription, SenderSubscriptions, StreamLayer};

/// Create a minimal SenderSubscriptions for a 1:1 audio call.
///
/// This is the minimal subscription needed for a basic audio call:
/// - SSRC: Our RTP synchronization source identifier
/// - StreamLayer: Audio
/// - PayloadType: Media
///
/// # Arguments
/// * `ssrc` - Our RTP SSRC (must match the SSRC used in RTP packets)
///
/// # Returns
/// Protobuf-encoded bytes suitable for the 0x4000 STUN attribute
///
/// # Example
/// ```ignore
/// let sender_subscriptions = create_audio_sender_subscriptions(0x12345678);
/// let stun_msg = StunMessage::allocate_request(tx_id)
///     .with_sender_subscriptions(sender_subscriptions);
/// ```
pub fn create_audio_sender_subscriptions(ssrc: u32) -> Vec<u8> {
    let subscription = SenderSubscription {
        sender_jid: None,
        pid: None,
        ssrc: Some(ssrc),
        ssrcs: Vec::new(),
        stream_layer: Some(StreamLayer::Audio.into()),
        payload_type: Some(PayloadType::Media.into()),
    };

    let subscriptions = SenderSubscriptions {
        senders: vec![subscription],
    };

    subscriptions.encode_to_vec()
}

/// Create SenderSubscriptions with a device JID for multi-party calls.
///
/// # Arguments
/// * `ssrc` - Our RTP SSRC
/// * `sender_jid` - Device JID (e.g., "user@s.whatsapp.net:0")
///
/// # Returns
/// Protobuf-encoded bytes suitable for the 0x4000 STUN attribute
pub fn create_audio_sender_subscriptions_with_jid(ssrc: u32, sender_jid: String) -> Vec<u8> {
    let subscription = SenderSubscription {
        sender_jid: Some(sender_jid),
        pid: None,
        ssrc: Some(ssrc),
        ssrcs: Vec::new(),
        stream_layer: Some(StreamLayer::Audio.into()),
        payload_type: Some(PayloadType::Media.into()),
    };

    let subscriptions = SenderSubscriptions {
        senders: vec![subscription],
    };

    subscriptions.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_subscription_encoding() {
        let data = create_audio_sender_subscriptions(0x12345678);

        // Should produce valid protobuf that can be decoded
        let decoded = SenderSubscriptions::decode(data.as_slice()).unwrap();
        assert_eq!(decoded.senders.len(), 1);
        assert_eq!(decoded.senders[0].ssrc, Some(0x12345678));
        assert_eq!(decoded.senders[0].stream_layer, Some(StreamLayer::Audio.into()));
        assert_eq!(decoded.senders[0].payload_type, Some(PayloadType::Media.into()));
    }

    #[test]
    fn test_audio_subscription_with_jid() {
        let jid = "user@s.whatsapp.net:0".to_string();
        let data = create_audio_sender_subscriptions_with_jid(0xABCDEF00, jid.clone());

        let decoded = SenderSubscriptions::decode(data.as_slice()).unwrap();
        assert_eq!(decoded.senders.len(), 1);
        assert_eq!(decoded.senders[0].ssrc, Some(0xABCDEF00));
        assert_eq!(decoded.senders[0].sender_jid, Some(jid));
    }

    #[test]
    fn test_encoding_size() {
        let data = create_audio_sender_subscriptions(0x12345678);

        // Should be relatively small (< 20 bytes for minimal subscription)
        assert!(data.len() < 20);
        println!("Minimal audio subscription size: {} bytes", data.len());
        println!("Encoded bytes: {:?}", data);
    }
}
