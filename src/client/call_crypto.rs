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

    /// Ensure a Signal session exists with the given JID, returning the device JID used.
    pub async fn ensure_call_session(&self, jid: &Jid) -> Result<Jid, CallError> {
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

        self.ensure_e2e_sessions(devices.clone())
            .await
            .map_err(|e| CallError::Encryption(format!("Failed to establish session: {}", e)))?;

        let target = devices
            .into_iter()
            .find(|d| d.device == 0)
            .unwrap_or_else(|| jid.clone());

        log::debug!("Established call session with {}", target);
        Ok(target)
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

        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

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
        use rand::TryRngCore;

        let device_store = self.persistence_manager.get_device_arc().await;

        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

        let mut rng = rand::rngs::OsRng.unwrap_err();
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
