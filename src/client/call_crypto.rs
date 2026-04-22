//! Call encryption helpers for Client using Signal Protocol.

use wacore_binary::jid::Jid;

use crate::calls::{
    CallEncryptionKey, CallError, EncType, EncryptedCallKey, decrypt_call_key, encrypt_call_key,
};

use super::Client;

impl Client {
    pub async fn has_signal_session(&self, jid: &Jid) -> bool {
        use wacore::types::jid::JidExt;

        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let signal_addr = jid.to_protocol_address();

        wacore::libsignal::store::SessionStore::contains_session(&*device_guard, &signal_addr)
            .await
            .unwrap_or(false)
    }

    /// Ensure a Signal session exists with the given JID, returning the
    /// **primary** device JID (device=0). Convenience wrapper for callers
    /// that only need to address the primary device; for multi-device
    /// fan-out use [`ensure_call_sessions_all`] instead.
    ///
    /// [`ensure_call_sessions_all`]: Self::ensure_call_sessions_all
    pub async fn ensure_call_session(&self, jid: &Jid) -> Result<Jid, CallError> {
        let devices = self.ensure_call_sessions_all(jid).await?;
        let target = devices
            .into_iter()
            .find(|d| d.device == 0)
            .unwrap_or_else(|| jid.clone());

        log::debug!("Established call session with {}", target);
        Ok(target)
    }

    /// Ensure a Signal session exists with **every** device belonging to
    /// `peer`, and return the full device JID list (including companion
    /// devices with `device != 0`). Matches WA Web's
    /// `SendSignalingXmpp.js::ensureE2ESessions([deviceWid, defaultDeviceWid])`
    /// — every device must be able to decrypt the call key or it will
    /// miss the incoming call entirely.
    pub async fn ensure_call_sessions_all(&self, peer: &Jid) -> Result<Vec<Jid>, CallError> {
        let devices = self
            .get_user_devices(std::slice::from_ref(peer))
            .await
            .map_err(|e| CallError::Encryption(format!("Failed to get devices: {}", e)))?;

        if devices.is_empty() {
            return Err(CallError::Encryption(format!(
                "No devices found for {}",
                peer
            )));
        }

        self.ensure_e2e_sessions(&devices)
            .await
            .map_err(|e| CallError::Encryption(format!("Failed to establish session: {}", e)))?;

        log::debug!(
            "Established call sessions with {} device(s) for {}",
            devices.len(),
            peer
        );
        Ok(devices)
    }

    /// Encrypt a call key for a recipient, returning the key and encrypted payload.
    pub async fn encrypt_call_key_for(
        &self,
        recipient: &Jid,
    ) -> Result<(CallEncryptionKey, EncryptedCallKey), CallError> {
        if !self.has_signal_session(recipient).await {
            return Err(CallError::Encryption(format!(
                "No Signal session with {} - cannot encrypt call key",
                recipient
            )));
        }

        let device_store = self.persistence_manager.get_device_arc().await;
        let call_key = CallEncryptionKey::generate();

        let mut adapter = crate::store::signal_adapter::SignalProtocolStoreAdapter::new(
            device_store,
            self.signal_cache.clone(),
        );

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
    pub async fn decrypt_call_key_from(
        &self,
        sender: &Jid,
        ciphertext: &[u8],
        enc_type: EncType,
    ) -> Result<CallEncryptionKey, CallError> {
        let device_store = self.persistence_manager.get_device_arc().await;

        let mut adapter = crate::store::signal_adapter::SignalProtocolStoreAdapter::new(
            device_store,
            self.signal_cache.clone(),
        );

        let mut rng: rand::rngs::StdRng = rand::make_rng();
        let call_key = decrypt_call_key(
            &mut adapter.session_store,
            &mut adapter.identity_store,
            &mut adapter.pre_key_store,
            &adapter.signed_pre_key_store,
            sender,
            ciphertext,
            enc_type,
            &mut rng,
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
