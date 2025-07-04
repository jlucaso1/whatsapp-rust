// Corresponds to libsignal-protocol-go/groups/GroupSessionBuilder.go

use crate::signal::groups::message::SenderKeyDistributionMessage;
use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::store::SenderKeyStore;
use crate::signal::util::keyhelper;
use std::error::Error;
use std::sync::Arc;

pub struct GroupSessionBuilder<S: SenderKeyStore> {
    sender_key_store: Arc<S>,
}

impl<S: SenderKeyStore> GroupSessionBuilder<S> {
    pub fn new(sender_key_store: Arc<S>) -> Self {
        Self { sender_key_store }
    }

    // Corresponds to GroupSessionBuilder.Process
    pub async fn process(
        &self,
        sender_key_name: &SenderKeyName,
        msg: &SenderKeyDistributionMessage,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut sender_key_record = self
            .sender_key_store
            .load_sender_key(sender_key_name)
            .await?;
        sender_key_record.add_sender_key_state(
            msg.id(),
            msg.iteration(),
            msg.chain_key(),
            msg.signing_key().clone(),
        );
        self.sender_key_store
            .store_sender_key(sender_key_name, sender_key_record)
            .await?;
        Ok(())
    }

    // Corresponds to GroupSessionBuilder.Create
    pub async fn create(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyDistributionMessage, Box<dyn Error + Send + Sync>> {
        let mut record = self
            .sender_key_store
            .load_sender_key(sender_key_name)
            .await?;
        if record.is_empty() {
            let signing_key = keyhelper::generate_sender_signing_key();
            let chain_key = keyhelper::generate_sender_key();
            let key_id = keyhelper::generate_sender_key_id();
            record.set_sender_key_state(key_id, 0, &chain_key, signing_key);
        }
        let state = record.get_sender_key_state().ok_or("No sender key state")?;
        let msg = crate::signal::groups::message::SenderKeyDistributionMessage::new(
            state.key_id(),
            state.sender_chain_key().iteration(),
            state.sender_chain_key().chain_key_bytes().to_vec(),
            state.signing_key().public_key.clone(),
        );
        if record.is_empty() {
            self.sender_key_store
                .store_sender_key(sender_key_name, record)
                .await?;
        }
        Ok(msg)
    }
}
