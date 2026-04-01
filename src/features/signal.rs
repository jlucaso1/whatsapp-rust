//! Low-level Signal protocol and raw transport APIs.
//!
//! Encryption, decryption, session management, and participant node creation.

use anyhow::{Result, anyhow};
use prost::Message as ProtoMessage;
use wacore::libsignal::protocol::{
    CiphertextMessage, PreKeySignalMessage, SignalMessage, UsePQRatchet, message_decrypt,
    message_encrypt,
};
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::messages::MessageUtils;
use wacore::types::jid::JidExt;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

use crate::client::Client;

/// Feature handle for Signal protocol operations.
pub struct Signal<'a> {
    client: &'a Client,
}

impl<'a> Signal<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Encrypt plaintext for a single recipient using the Signal protocol.
    ///
    /// Returns `("msg" | "pkmsg", ciphertext_bytes)`. The caller is
    /// responsible for padding if needed; this method encrypts raw bytes.
    pub async fn encrypt_message(
        &self,
        jid: &Jid,
        plaintext: &[u8],
    ) -> Result<(&'static str, Vec<u8>)> {
        let signal_addr = jid.to_protocol_address();
        let signal_addr_str = jid.to_protocol_address_string();

        let lock = self.client.session_lock_for(&signal_addr_str).await;
        let _guard = lock.lock().await;
        let mut adapter = self.client.signal_adapter().await;

        let encrypted = message_encrypt(
            plaintext,
            &signal_addr,
            &mut adapter.session_store,
            &mut adapter.identity_store,
        )
        .await?;

        match encrypted {
            CiphertextMessage::PreKeySignalMessage(msg) => Ok(("pkmsg", msg.serialized().to_vec())),
            CiphertextMessage::SignalMessage(msg) => Ok(("msg", msg.serialized().to_vec())),
            _ => Err(anyhow!("unexpected ciphertext variant")),
        }
    }

    /// Decrypt a Signal protocol message from a sender.
    ///
    /// `msg_type` must be `"msg"` or `"pkmsg"`. Returns unpadded plaintext.
    pub async fn decrypt_message(
        &self,
        jid: &Jid,
        msg_type: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let signal_addr = jid.to_protocol_address();
        let signal_addr_str = jid.to_protocol_address_string();

        let parsed = match msg_type {
            "pkmsg" => {
                CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ciphertext)?)
            }
            "msg" => CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext)?),
            other => return Err(anyhow!("invalid msg_type: {other}")),
        };

        let lock = self.client.session_lock_for(&signal_addr_str).await;
        let _guard = lock.lock().await;
        let mut adapter = self.client.signal_adapter().await;
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();

        let padded = message_decrypt(
            &parsed,
            &signal_addr,
            &mut adapter.session_store,
            &mut adapter.identity_store,
            &mut adapter.pre_key_store,
            &adapter.signed_pre_key_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await?;

        let unpadded = MessageUtils::unpad_message_ref(&padded, 2)?;
        Ok(unpadded.to_vec())
    }

    /// Encrypt plaintext for a group using sender keys.
    ///
    /// Returns `(skdm_bytes, ciphertext_bytes)`.
    ///
    /// **Warning:** This regenerates the SKDM on every call. Callers must
    /// distribute the SKDM to participants who don't yet hold the sender key.
    /// For repeated sends to the same group, prefer using
    /// `create_participant_nodes` which handles distribution tracking.
    pub async fn encrypt_group_message(
        &self,
        group_jid: &Jid,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let own_jid = self
            .client
            .persistence_manager
            .get_device_snapshot()
            .await
            .pn
            .clone()
            .ok_or_else(|| anyhow!("not logged in"))?;

        let mut adapter = self.client.signal_adapter().await;
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();

        let skdm_bytes = wacore::send::create_sender_key_distribution_message_for_group(
            &mut adapter.sender_key_store,
            group_jid,
            &own_jid,
        )
        .await?;

        let ciphertext = wacore::send::encrypt_group_message(
            &mut adapter.sender_key_store,
            group_jid,
            &own_jid,
            plaintext,
            &mut rng,
        )
        .await?;

        Ok((skdm_bytes, ciphertext.serialized().to_vec()))
    }

    /// Decrypt a group (sender-key) message.
    pub async fn decrypt_group_message(
        &self,
        group_jid: &Jid,
        sender_jid: &Jid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let sender_key_name = SenderKeyName::new(
            group_jid.to_string(),
            sender_jid.to_protocol_address().to_string(),
        );

        let mut adapter = self.client.signal_adapter().await;

        let padded = wacore::libsignal::protocol::group_decrypt(
            ciphertext,
            &mut adapter.sender_key_store,
            &sender_key_name,
        )
        .await?;

        let unpadded = MessageUtils::unpad_message_ref(&padded, 2)?;
        Ok(unpadded.to_vec())
    }

    /// Check whether a Signal session exists for `jid`.
    pub async fn validate_session(&self, jid: &Jid) -> Result<bool> {
        let signal_addr = jid.to_protocol_address();
        let device_store = self.client.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        self.client
            .signal_cache
            .has_session(&signal_addr, &*device_guard.backend)
            .await
            .map_err(|e| anyhow!("session check failed: {e}"))
    }

    /// Delete Signal sessions for the given JIDs (cache + persistent store).
    pub async fn delete_sessions(&self, jids: &[Jid]) -> Result<()> {
        let device_store = self.client.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;

        for jid in jids {
            let addr = jid.to_protocol_address();
            let signal_addr_str = jid.to_protocol_address_string();

            // Acquire per-address session lock to prevent races with encrypt/decrypt
            let lock = self.client.session_lock_for(&signal_addr_str).await;
            let _guard = lock.lock().await;

            self.client.signal_cache.delete_session(&addr).await;
            device_guard
                .backend
                .delete_session(addr.as_str())
                .await
                .map_err(|e| anyhow!("failed to delete session for {jid}: {e}"))?;
        }
        Ok(())
    }

    /// Create encrypted participant `<to>` nodes for the given recipient JIDs.
    ///
    /// Resolves devices, ensures Signal sessions, encrypts the message for
    /// each device, and returns the resulting XML nodes.
    ///
    /// Returns `(nodes, should_include_device_identity)`.
    pub async fn create_participant_nodes(
        &self,
        recipient_jids: &[Jid],
        message: &waproto::whatsapp::Message,
    ) -> Result<(Vec<Node>, bool)> {
        let device_jids = self.client.get_user_devices(recipient_jids).await?;
        self.client.ensure_e2e_sessions(&device_jids).await?;

        let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
        let mut adapter = self.client.signal_adapter().await;
        let mediatype = wacore::send::media_type_from_message(message);
        let hide_decrypt_fail = wacore::send::should_hide_decrypt_fail(message);

        let mut stores = adapter.as_signal_stores();
        let result = wacore::send::encrypt_for_devices(
            &mut stores,
            self.client,
            &device_jids,
            &plaintext,
            hide_decrypt_fail,
            mediatype,
        )
        .await?;

        Ok((result.participant_nodes, result.includes_prekey_message))
    }

    /// Ensure E2E sessions exist for the given JIDs.
    pub async fn assert_sessions(&self, jids: &[Jid]) -> Result<()> {
        self.client.ensure_e2e_sessions(jids).await
    }

    /// Get all known device JIDs for the given user JIDs via usync.
    pub async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>> {
        self.client.get_user_devices(jids).await
    }
}

impl Client {
    /// Access low-level Signal protocol operations.
    pub fn signal(&self) -> Signal<'_> {
        Signal::new(self)
    }
}
