//! Call encryption helpers for Client.
//!
//! This module provides methods to encrypt and decrypt call keys using
//! Signal Protocol. These are used when accepting/initiating VoIP calls.

use wacore_binary::jid::Jid;

use crate::calls::{
    CallEncryptionKey, CallError, EncType, EncryptedCallKey, decrypt_call_key, encrypt_call_key,
};

use super::Client;

impl Client {
    /// Check if we have a Signal session with the given JID.
    pub async fn has_signal_session(&self, jid: &Jid) -> bool {
        use wacore::types::jid::JidExt;

        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let signal_addr = jid.to_protocol_address();

        wacore::libsignal::store::SessionStore::contains_session(&*device_guard, &signal_addr)
            .await
            .unwrap_or(false)
    }

    /// Ensure a Signal session exists with the given JID.
    ///
    /// This fetches the device list and prekeys if needed, establishing
    /// a Signal session that can be used for call key encryption.
    ///
    /// # Arguments
    /// * `jid` - The JID to establish a session with (phone number JID preferred)
    ///
    /// # Returns
    /// The device JID that was used to establish the session, or an error.
    pub async fn ensure_call_session(&self, jid: &Jid) -> Result<Jid, CallError> {
        // Get device list for the JID
        let devices = self
            .get_user_devices(std::slice::from_ref(jid))
            .await
            .map_err(|e| CallError::Encryption(format!("Failed to get devices: {}", e)))?;

        if devices.is_empty() {
            return Err(CallError::Encryption(format!(
                "No devices found for {}",
                jid
            )));
        }

        // Establish sessions with the devices
        self.ensure_e2e_sessions(devices.clone())
            .await
            .map_err(|e| CallError::Encryption(format!("Failed to establish session: {}", e)))?;

        // Return the primary device (device 0) or first device
        let target = devices
            .into_iter()
            .find(|d| d.device == 0)
            .unwrap_or_else(|| jid.clone());

        log::debug!("Established call session with {}", target);
        Ok(target)
    }

    /// Encrypt a call key for a recipient using Signal Protocol.
    ///
    /// This generates a new random 32-byte call key, encrypts it using the
    /// Signal session with the recipient, and returns both the key and the
    /// encrypted payload ready for inclusion in an accept/offer stanza.
    ///
    /// # Arguments
    /// * `recipient` - The JID to encrypt the key for (usually the call creator)
    ///
    /// # Returns
    /// A tuple of (CallEncryptionKey, EncryptedCallKey) where:
    /// - `CallEncryptionKey` contains the raw 32-byte master key for SRTP derivation
    /// - `EncryptedCallKey` contains the ciphertext and type for the `<enc>` stanza
    ///
    /// # Example
    /// ```ignore
    /// let (call_key, encrypted) = client.encrypt_call_key_for(&peer_jid).await?;
    ///
    /// // Use encrypted for the accept stanza
    /// let stanza = call_manager.accept_call_with_key(&call_id, Some(encrypted)).await?;
    ///
    /// // Use call_key to derive SRTP keys
    /// let keys = derive_call_keys(&call_key);
    /// ```
    pub async fn encrypt_call_key_for(
        &self,
        recipient: &Jid,
    ) -> Result<(CallEncryptionKey, EncryptedCallKey), CallError> {
        use wacore::types::jid::JidExt;

        // Ensure we have a session with the recipient
        let device_store = self.persistence_manager.get_device_arc().await;
        {
            let device_guard = device_store.read().await;
            let signal_addr = recipient.to_protocol_address();
            let has_session = wacore::libsignal::store::SessionStore::contains_session(
                &*device_guard,
                &signal_addr,
            )
            .await
            .map_err(|e| CallError::Encryption(format!("Failed to check session: {}", e)))?;

            if !has_session {
                return Err(CallError::Encryption(format!(
                    "No Signal session with {} - cannot encrypt call key",
                    recipient
                )));
            }
        }

        // Generate a new call key
        let call_key = CallEncryptionKey::generate();

        // Create adapter to access stores
        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

        // Encrypt the call key
        let encrypted = encrypt_call_key(
            &mut adapter.session_store,
            &mut adapter.identity_store,
            recipient,
            &call_key,
        )
        .await?;

        log::debug!(
            "Encrypted call key for {}: type={:?}, {} bytes",
            recipient,
            encrypted.enc_type,
            encrypted.ciphertext.len()
        );

        Ok((call_key, encrypted))
    }

    /// Decrypt a call key received from a sender.
    ///
    /// This decrypts the ciphertext from an `<enc>` element inside an offer/enc_rekey
    /// stanza and returns the call encryption key.
    ///
    /// # Arguments
    /// * `sender` - The JID of the call creator/sender
    /// * `ciphertext` - The encrypted call key from the `<enc>` element
    /// * `enc_type` - The encryption type ("msg" or "pkmsg")
    ///
    /// # Returns
    /// The decrypted `CallEncryptionKey` for SRTP key derivation.
    ///
    /// # Example
    /// ```ignore
    /// let call_key = client.decrypt_call_key_from(
    ///     &offer.call_creator,
    ///     &offer.enc_data.ciphertext,
    ///     offer.enc_data.enc_type,
    /// ).await?;
    ///
    /// // Derive SRTP keys
    /// let keys = derive_call_keys(&call_key);
    /// ```
    pub async fn decrypt_call_key_from(
        &self,
        sender: &Jid,
        ciphertext: &[u8],
        enc_type: EncType,
    ) -> Result<CallEncryptionKey, CallError> {
        use rand::TryRngCore;

        let device_store = self.persistence_manager.get_device_arc().await;

        // Create adapter to access stores
        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

        // Decrypt the call key
        let call_key = decrypt_call_key(
            &mut adapter.session_store,
            &mut adapter.identity_store,
            &mut adapter.pre_key_store,
            &adapter.signed_pre_key_store,
            sender,
            ciphertext,
            enc_type,
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await?;

        log::debug!(
            "Decrypted call key from {}: generation={}",
            sender,
            call_key.generation
        );

        Ok(call_key)
    }
}
