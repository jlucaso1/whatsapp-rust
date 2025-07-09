// Corresponds to libsignal-protocol-go/groups/GroupSessionBuilder.go

use whatsapp_proto::whatsapp::SenderKeyDistributionMessage;

use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::store::SenderKeyStore;
use crate::signal::util::keyhelper;
use std::error::Error;

pub struct GroupSessionBuilder<S: SenderKeyStore> {
    sender_key_store: S,
}

impl<S: SenderKeyStore> GroupSessionBuilder<S> {
    pub fn new(sender_key_store: S) -> Self {
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
            msg.signing_key(),
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
        let state = record.sender_key_state().ok_or("No sender key state")?;
        let signing_key_proto = state.sender_signing_key.as_ref().ok_or("No signing key")?;
        let signing_key_pub_bytes: [u8; 32] = signing_key_proto
            .public
            .as_deref()
            .ok_or("No public key")?
            .try_into()
            .map_err(|_| "Invalid public key length")?;
        let chain_key_proto = state.sender_chain_key.as_ref().ok_or("No chain key")?;
        let msg = SenderKeyDistributionMessage {
            id: Some(state.sender_key_id.unwrap_or(0)),
            iteration: Some(chain_key_proto.iteration.unwrap_or(0)),
            chain_key: Some(chain_key_proto.seed.as_deref().unwrap_or(&[]).to_vec()),
            signing_key: Some(signing_key_pub_bytes.to_vec()),
        };
        self.sender_key_store
            .store_sender_key(sender_key_name, record)
            .await?;
        Ok(msg)
    }
}
