//! Low-level Signal protocol and raw transport APIs.
//!
//! Encryption, decryption, session management, and participant node creation.

use anyhow::{Result, anyhow};
use wacore::libsignal::protocol::{
    CiphertextMessage, PreKeySignalMessage, SignalMessage, UsePQRatchet, message_decrypt,
    message_encrypt,
};
use wacore::message_processing::EncType;
use wacore::messages::MessageUtils;
use wacore::types::jid::{JidExt, make_sender_key_name};
use wacore_binary::Jid;
use wacore_binary::Node;

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
    /// Returns `(EncType, ciphertext_bytes)`. The caller is responsible
    /// for padding if needed; this method encrypts raw bytes.
    ///
    /// PN JIDs are resolved to LID when a LID session exists, matching
    /// the internal send path.
    pub async fn encrypt_message(&self, jid: &Jid, plaintext: &[u8]) -> Result<(EncType, Vec<u8>)> {
        // Resolve PN→LID to use the correct Signal session (matches send path)
        let encryption_jid = self.client.resolve_encryption_jid(jid).await;
        let signal_addr = encryption_jid.to_protocol_address();

        let lock = self.client.session_lock_for(signal_addr.as_str()).await;
        let _guard = lock.lock().await;
        let mut adapter = self.client.signal_adapter().await;

        let encrypted = message_encrypt(
            plaintext,
            &signal_addr,
            &mut adapter.session_store,
            &mut adapter.identity_store,
        )
        .await?;

        drop(_guard);
        self.client.flush_signal_cache().await?;

        let (_, is_prekey, bytes) = wacore::send::extract_ciphertext(encrypted)
            .ok_or_else(|| anyhow!("unexpected ciphertext variant"))?;
        let enc_type = if is_prekey {
            EncType::PreKeyMessage
        } else {
            EncType::Message
        };
        Ok((enc_type, bytes.into_vec()))
    }

    /// Decrypt a Signal protocol message from a sender.
    ///
    /// Returns raw padded plaintext. Use [`MessageUtils::unpad_message_ref`]
    /// with the stanza's `v` attribute if WhatsApp message unpadding is needed.
    ///
    /// PN JIDs are resolved to LID when a LID session exists, matching
    /// the internal receive path.
    pub async fn decrypt_message(
        &self,
        jid: &Jid,
        enc_type: EncType,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let parsed = match enc_type {
            EncType::PreKeyMessage => {
                CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ciphertext)?)
            }
            EncType::Message => {
                CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext)?)
            }
            EncType::SenderKey => {
                return Err(anyhow!("use decrypt_group_message for sender-key messages"));
            }
        };

        let encryption_jid = self.client.resolve_encryption_jid(jid).await;
        let signal_addr = encryption_jid.to_protocol_address();

        let lock = self.client.session_lock_for(signal_addr.as_str()).await;
        let _guard = lock.lock().await;
        let mut adapter = self.client.signal_adapter().await;
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();

        let plaintext = message_decrypt(
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

        drop(_guard);
        self.client.flush_signal_cache().await?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt plaintext for a group using sender keys.
    ///
    /// Returns `(Option<skdm_bytes>, ciphertext_bytes)`. The SKDM is `Some`
    /// only when a new sender key was created (first encrypt for this group
    /// or after key rotation). Callers must distribute the SKDM to all group
    /// participants when present. This matches WA Web which only creates
    /// SKDM on first group encrypt or after sender key rotation.
    ///
    /// Not safe to call concurrently with `decrypt_group_message` for the
    /// same group — sender key state is not internally locked.
    pub async fn encrypt_group_message(
        &self,
        group_jid: &Jid,
        plaintext: &[u8],
    ) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
        let own_jid = self.client.get_own_jid_for_group(group_jid).await?;
        let sender_addr = own_jid.to_protocol_address();
        let sender_key_name = make_sender_key_name(group_jid, &sender_addr);

        // Only create SKDM when no sender key exists (matches WA Web behavior)
        let device_store = self.client.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let key_exists = self
            .client
            .signal_cache
            .get_sender_key(&sender_key_name, &*device_guard.backend)
            .await?
            .is_some();
        drop(device_guard);

        let mut adapter = self.client.signal_adapter().await;
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();

        let skdm_bytes = if !key_exists {
            Some(
                wacore::send::create_sender_key_distribution_message_for_group(
                    &mut adapter.sender_key_store,
                    group_jid,
                    &sender_addr,
                )
                .await?,
            )
        } else {
            None
        };

        let ciphertext = wacore::send::encrypt_group_message(
            &mut adapter.sender_key_store,
            group_jid,
            &sender_addr,
            plaintext,
            &mut rng,
        )
        .await?;

        self.client.flush_signal_cache().await?;

        Ok((skdm_bytes, ciphertext.into_serialized().into_vec()))
    }

    /// Decrypt a group (sender-key) message.
    ///
    /// Returns raw padded plaintext. Use [`MessageUtils::unpad_message_ref`]
    /// with the stanza's `v` attribute if WhatsApp message unpadding is needed.
    ///
    /// Not safe to call concurrently with `encrypt_group_message` for the
    /// same group — sender key state is not internally locked.
    pub async fn decrypt_group_message(
        &self,
        group_jid: &Jid,
        sender_jid: &Jid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let sender_key_name =
            make_sender_key_name(group_jid, &sender_jid.to_non_ad().to_protocol_address());

        let mut adapter = self.client.signal_adapter().await;

        let plaintext = wacore::libsignal::protocol::group_decrypt(
            ciphertext,
            &mut adapter.sender_key_store,
            &sender_key_name,
        )
        .await?;

        self.client.flush_signal_cache().await?;

        Ok(plaintext.to_vec())
    }

    /// Check whether a Signal session exists for `jid`.
    ///
    /// PN JIDs are resolved to LID when a LID mapping exists, matching
    /// the encrypt/decrypt paths.
    pub async fn validate_session(&self, jid: &Jid) -> Result<bool> {
        let resolved = self.client.resolve_encryption_jid(jid).await;
        let signal_addr = resolved.to_protocol_address();
        let device_store = self.client.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        self.client
            .signal_cache
            .has_session(&signal_addr, &*device_guard.backend)
            .await
            .map_err(|e| anyhow!("session check failed: {e}"))
    }

    /// Delete Signal sessions and identity keys for the given JIDs.
    ///
    /// Matches WA Web's `deleteRemoteSession` which removes both session
    /// and identity as a paired operation. Changes are flushed to the
    /// persistent backend before returning.
    ///
    /// PN JIDs are resolved to LID when a LID mapping exists, matching
    /// the encrypt/decrypt paths.
    pub async fn delete_sessions(&self, jids: &[Jid]) -> Result<()> {
        for jid in jids {
            let resolved = self.client.resolve_encryption_jid(jid).await;
            let addr = resolved.to_protocol_address();

            let lock = self.client.session_lock_for(addr.as_str()).await;
            let _guard = lock.lock().await;

            // WA Web removes session + identity together (deleteRemoteSession)
            self.client.signal_cache.delete_session(&addr).await;
            self.client.signal_cache.delete_identity(&addr).await;
        }

        self.client.flush_signal_cache().await?;
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

        // Acquire per-device session locks before encrypting (matches DM send path)
        let lock_jids = self.client.build_session_lock_keys(&device_jids).await;
        let session_mutexes = self.client.session_mutexes_for(&lock_jids).await;
        let mut _session_guards = Vec::with_capacity(session_mutexes.len());
        for mutex in &session_mutexes {
            _session_guards.push(mutex.lock().await);
        }

        let plaintext = MessageUtils::encode_and_pad(message);
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

        drop(_session_guards);
        self.client.flush_signal_cache().await?;

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
