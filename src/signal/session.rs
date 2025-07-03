use super::address::SignalAddress;
use super::protocol::{CiphertextMessage, SignalMessage};
use super::store::SignalProtocolStore;
use std::sync::Arc;

// Corresponds to session/Cipher.go
pub struct SessionCipher<S: SignalProtocolStore> {
    store: Arc<S>,
    remote_address: SignalAddress,
}

impl<S: SignalProtocolStore> SessionCipher<S> {
    pub fn new(store: Arc<S>, remote_address: SignalAddress) -> Self {
        Self {
            store,
            remote_address,
        }
    }

    // Corresponds to SessionCipher.Encrypt()
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<Box<dyn CiphertextMessage>, Box<dyn std::error::Error>> {
        let mut session_record = self
            .store
            .load_session(&self.remote_address)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        let session_state = session_record.session_state_mut();

        let chain_key = session_state.sender_chain_key(); // We need to implement this method on SessionState
        let message_keys = chain_key.message_keys();

        let ciphertext = self.encrypt_internal(&message_keys, plaintext)?;

        // This is a simplified version. The real implementation is more complex.
        let signal_message = SignalMessage {
            sender_ratchet_key: session_state.sender_ratchet_key(), // Also need to implement this
            counter: chain_key.index(),
            previous_counter: session_state.previous_counter(),
            ciphertext,
            serialized_form: Vec::new(), // This will be set on serialization
        };

        // Now, we would check if we need to wrap it in a PreKeySignalMessage
        if session_state.has_unacknowledged_prekey_message() {
            // ... logic to create and return a PreKeySignalMessage
            // For now, we'll just return the SignalMessage
        }

        // Update the state
        session_state.set_sender_chain_key(chain_key.next_key());
        self.store
            .store_session(&self.remote_address, &session_record)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        Ok(Box::new(signal_message))
    }

    fn encrypt_internal(
        &self,
        message_keys: &super::message_key::MessageKeys,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Here we would use a real crypto library like `aes_gcm`
        // For now, we'll just simulate it.
        let mut ciphertext = plaintext.to_vec();
        // This is NOT real encryption.
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= message_keys.iv()[i % message_keys.iv().len()];
        }
        Ok(ciphertext)
    }

    // We will add the decrypt method later
}
