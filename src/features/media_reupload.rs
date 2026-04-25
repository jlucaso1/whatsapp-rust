//! Media reupload feature: request the server to re-upload expired media.
//!
//! When a media download fails because the URL has expired, this feature
//! sends a `<receipt type="server-error">` stanza and waits for a
//! `<notification type="mediaretry">` response with a new `directPath`.
//!
//! Reference: WAWebRequestMediaReuploadManager.

use crate::client::{Client, ClientError, NodeFilter};
use anyhow::Result;
use log::debug;
use std::time::Duration;
pub use wacore::media_retry::MediaRetryResult;
use wacore::media_retry::{
    build_media_retry_receipt, encrypt_media_retry_receipt, parse_media_retry_notification,
};
use wacore_binary::{Jid, JidExt as _};

const MEDIA_RETRY_TIMEOUT: Duration = Duration::from_secs(30);

/// Parameters for a media reupload request.
pub struct MediaReuploadRequest<'a> {
    /// The message ID containing the media.
    pub msg_id: &'a str,
    /// The chat JID where the message was received.
    pub chat_jid: &'a Jid,
    /// The raw media key bytes (32 bytes, from the message's `mediaKey` field).
    pub media_key: &'a [u8],
    /// Whether the message was sent by us.
    pub is_from_me: bool,
    /// For group/broadcast messages, the participant JID who sent the message.
    pub participant: Option<&'a Jid>,
}

pub struct MediaReupload<'a> {
    client: &'a Client,
}

impl<'a> MediaReupload<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Request the server to re-upload media for a message with an expired URL.
    ///
    /// Returns the new `directPath` on success, or an error variant indicating
    /// why the reupload failed.
    ///
    /// # Protocol flow
    /// 1. Encrypt `ServerErrorReceipt` protobuf with HKDF-derived key from media key
    /// 2. Send `<receipt type="server-error">` with encrypted payload + `<rmr>` metadata
    /// 3. Wait for `<notification type="mediaretry">` response
    /// 4. Decrypt response and extract new `directPath`
    pub async fn request(&self, req: &MediaReuploadRequest<'_>) -> Result<MediaRetryResult> {
        // WA Web: ServerErrorReceiptJob rejects newsletter messages (no media keys).
        anyhow::ensure!(
            !req.chat_jid.is_newsletter(),
            "media reupload is not supported for newsletter messages"
        );

        debug!(
            "[media][rmr] Requesting media reupload for msg {} in chat {}",
            req.msg_id, req.chat_jid
        );

        // Encrypt the ServerErrorReceipt
        let (ciphertext, iv) = encrypt_media_retry_receipt(req.media_key, req.msg_id)?;

        // Get own JID for the receipt's `to` attribute
        let device_snapshot = self.client.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot.pn.clone().ok_or(ClientError::NotLoggedIn)?;

        // Register waiter BEFORE sending (to avoid race)
        let waiter = self.client.wait_for_node(
            NodeFilter::tag("notification")
                .attr("type", "mediaretry")
                .attr("id", req.msg_id),
        );

        // Build and send the receipt node
        let receipt_node = build_media_retry_receipt(
            &own_jid,
            req.msg_id,
            req.chat_jid,
            req.is_from_me,
            req.participant,
            &ciphertext,
            &iv,
        );

        self.client.send_node(receipt_node).await?;

        debug!(
            "[media][rmr] Sent server-error receipt for {}, waiting for response",
            req.msg_id
        );

        // Wait for the mediaretry notification
        let notification_node =
            wacore::runtime::timeout(&*self.client.runtime, MEDIA_RETRY_TIMEOUT, waiter)
                .await
                .map_err(|_| anyhow::anyhow!("media retry notification timed out after 30s"))?
                .map_err(|_| anyhow::anyhow!("media retry waiter cancelled"))?;

        debug!(
            "[media][rmr] Received mediaretry notification for {}",
            req.msg_id
        );

        // Parse and decrypt the response
        parse_media_retry_notification(notification_node.get(), req.media_key)
    }
}

impl Client {
    /// Access media reupload operations.
    pub fn media_reupload(&self) -> MediaReupload<'_> {
        MediaReupload::new(self)
    }
}
