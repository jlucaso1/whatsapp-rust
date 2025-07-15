// Corresponds to libsignal-protocol-go/groups/GroupSessionBuilder.go

use crate::signal::ecc::keys::EcPublicKey;
use waproto::whatsapp::SenderKeyDistributionMessage;

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
        // Check if the current state has a private key. If not, we must create a new one.
        let has_private_key = record
            .sender_key_state()
            .and_then(|s| s.sender_signing_key.as_ref())
            .and_then(|sk| sk.private.as_ref())
            .is_some();

        if !has_private_key {
            let signing_key = keyhelper::generate_sender_signing_key();
            let chain_key = keyhelper::generate_sender_key();
            let key_id = keyhelper::generate_sender_key_id();
            record.set_sender_key_state(key_id, 0, &chain_key, signing_key);
        }
        let state = record.sender_key_state().ok_or("No sender key state")?;
        let signing_key_proto = state.sender_signing_key.as_ref().ok_or("No signing key")?;
        let public_key_slice = signing_key_proto.public.as_deref().ok_or("No public key")?;
        if public_key_slice.len() != 32 {
            return Err(format!(
                "Invalid public key length in store: expected 32, got {}",
                public_key_slice.len()
            )
            .into());
        }
        let mut pk32 = [0u8; 32];
        pk32.copy_from_slice(public_key_slice);
        // Serialize with prefix for wire format
        let serialized_signing_key =
            crate::signal::ecc::keys::DjbEcPublicKey::new(pk32).serialize();

        let chain_key_proto = state.sender_chain_key.as_ref().ok_or("No chain key")?;
        let msg = SenderKeyDistributionMessage {
            id: Some(state.sender_key_id.unwrap_or(0)),
            iteration: Some(chain_key_proto.iteration.unwrap_or(0)),
            chain_key: Some(chain_key_proto.seed.as_deref().unwrap_or(&[]).to_vec()),
            signing_key: Some(serialized_signing_key),
        };
        self.sender_key_store
            .store_sender_key(sender_key_name, record)
            .await?;
        Ok(msg)
    }
}
