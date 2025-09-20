use std::collections::HashMap;

use rand::{Rng as _, TryRngCore as _};
use wacore::client::context::{GroupInfo, SendContextResolver};
use wacore::libsignal::protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, KeyPair, PreKeyBundle,
    ProtocolAddress, SENDERKEY_MESSAGE_CURRENT_VERSION, SenderKeyRecord, SessionRecord,
};
use wacore::libsignal::store::GroupSenderKeyStore;
use wacore::types::message::AddressingMode;
use wacore_binary::jid::Jid;

struct NoopSessionStore;
#[async_trait::async_trait]
impl wacore::libsignal::protocol::SessionStore for NoopSessionStore {
    async fn load_session(
        &self,
        _address: &ProtocolAddress,
    ) -> wacore::libsignal::protocol::error::Result<Option<SessionRecord>> {
        Ok(None)
    }
    async fn store_session(
        &mut self,
        _address: &ProtocolAddress,
        _record: &SessionRecord,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        Ok(())
    }
}

struct NoopIdentityStore;
#[async_trait::async_trait]
impl wacore::libsignal::protocol::IdentityKeyStore for NoopIdentityStore {
    async fn get_identity_key_pair(
        &self,
    ) -> wacore::libsignal::protocol::error::Result<IdentityKeyPair> {
        Ok(IdentityKeyPair::generate(
            &mut rand::rngs::OsRng.unwrap_err(),
        ))
    }
    async fn get_local_registration_id(&self) -> wacore::libsignal::protocol::error::Result<u32> {
        Ok(1)
    }
    async fn save_identity(
        &mut self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
    ) -> wacore::libsignal::protocol::error::Result<IdentityChange> {
        Ok(IdentityChange::NewOrUnchanged)
    }
    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
        _direction: Direction,
    ) -> wacore::libsignal::protocol::error::Result<bool> {
        Ok(true)
    }
    async fn get_identity(
        &self,
        _address: &ProtocolAddress,
    ) -> wacore::libsignal::protocol::error::Result<Option<IdentityKey>> {
        Ok(None)
    }
}

struct NoopPreKeyStore;
#[async_trait::async_trait]
impl wacore::libsignal::protocol::PreKeyStore for NoopPreKeyStore {
    async fn get_pre_key(
        &self,
        _prekey_id: wacore::libsignal::protocol::PreKeyId,
    ) -> wacore::libsignal::protocol::error::Result<wacore::libsignal::protocol::PreKeyRecord> {
        Err(
            wacore::libsignal::protocol::SignalProtocolError::InvalidState(
                "noop",
                "no prekey".into(),
            ),
        )
    }
    async fn save_pre_key(
        &mut self,
        _prekey_id: wacore::libsignal::protocol::PreKeyId,
        _record: &wacore::libsignal::protocol::PreKeyRecord,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        Ok(())
    }
    async fn remove_pre_key(
        &mut self,
        _prekey_id: wacore::libsignal::protocol::PreKeyId,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        Ok(())
    }
}

struct NoopSignedPreKeyStore;
#[async_trait::async_trait]
impl wacore::libsignal::protocol::SignedPreKeyStore for NoopSignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        _signed_prekey_id: wacore::libsignal::protocol::SignedPreKeyId,
    ) -> wacore::libsignal::protocol::error::Result<wacore::libsignal::protocol::SignedPreKeyRecord>
    {
        Err(wacore::libsignal::protocol::SignalProtocolError::InvalidState("noop", "no spk".into()))
    }
    async fn save_signed_pre_key(
        &mut self,
        _signed_prekey_id: wacore::libsignal::protocol::SignedPreKeyId,
        _record: &wacore::libsignal::protocol::SignedPreKeyRecord,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        Ok(())
    }
}

struct InMemoryGroupSenderKeyStore;
#[async_trait::async_trait]
impl GroupSenderKeyStore for InMemoryGroupSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        _group_id: &Jid,
        _sender: &ProtocolAddress,
        _record: &SenderKeyRecord,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    async fn load_sender_key(
        &self,
        _group_id: &Jid,
        _sender: &ProtocolAddress,
    ) -> anyhow::Result<Option<SenderKeyRecord>> {
        // Provide a valid sender key record with one state
        let signing = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let chain_id = (rand::rngs::OsRng.unwrap_err().random::<u32>()) >> 1;
        let seed: [u8; 32] = rand::rngs::OsRng.unwrap_err().random();
        let mut rec = SenderKeyRecord::new_empty();
        rec.add_sender_key_state(
            SENDERKEY_MESSAGE_CURRENT_VERSION,
            chain_id,
            0,
            &seed,
            signing.public_key,
            Some(signing.private_key),
        );
        Ok(Some(rec))
    }
}

struct MockResolver {
    devices_calls: std::sync::Mutex<Vec<Vec<Jid>>>,
    encryption_calls: std::sync::Mutex<Vec<Vec<Jid>>>,
    encryption_map: HashMap<Jid, Jid>,
}

#[async_trait::async_trait]
impl SendContextResolver for MockResolver {
    async fn resolve_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        self.devices_calls.lock().unwrap().push(jids.to_vec());
        Ok(jids.to_vec())
    }

    async fn fetch_prekeys(
        &self,
        _jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn fetch_prekeys_for_identity_check(
        &self,
        _jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn resolve_group_info(&self, _jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        unreachable!()
    }

    async fn resolve_encryption_jids(
        &self,
        pns: &[Jid],
    ) -> Result<HashMap<Jid, Jid>, anyhow::Error> {
        self.encryption_calls.lock().unwrap().push(pns.to_vec());
        Ok(self.encryption_map.clone())
    }
}

#[tokio::test]
async fn test_prepare_group_stanza_pn_mode_no_mapping_call() {
    let mut stores = wacore::send::SignalStores {
        sender_key_store: &mut InMemoryGroupSenderKeyStore,
        session_store: &mut NoopSessionStore,
        identity_store: &mut NoopIdentityStore,
        prekey_store: &mut NoopPreKeyStore,
        signed_prekey_store: &NoopSignedPreKeyStore,
    };

    let resolver = MockResolver {
        devices_calls: Default::default(),
        encryption_calls: Default::default(),
        encryption_map: HashMap::new(),
    };

    let mut group_info = GroupInfo {
        participants: vec!["1111@s.whatsapp.net".parse().unwrap()],
        addressing_mode: AddressingMode::Pn,
    };
    let own_pn: Jid = "9999@s.whatsapp.net".parse().unwrap();
    let own_lid: Jid = "9999@lid".parse().unwrap();
    let group_jid: Jid = "12345@g.us".parse().unwrap();

    let msg = waproto::whatsapp::Message::default();
    let _stanza = wacore::send::prepare_group_stanza(
        &mut stores,
        &resolver,
        &mut group_info,
        &own_pn,
        &own_lid,
        None,
        group_jid,
        &msg,
        "req-1".to_string(),
        false,
        None,
    )
    .await
    .unwrap();

    // In PN mode, we shouldn't call encryption resolver, and we don't resolve devices
    assert_eq!(resolver.encryption_calls.lock().unwrap().len(), 0);
    let dcalls = resolver.devices_calls.lock().unwrap();
    assert_eq!(dcalls.len(), 0);
}

#[tokio::test]
async fn test_prepare_group_stanza_lid_mode_with_mapping() {
    let mut stores = wacore::send::SignalStores {
        sender_key_store: &mut InMemoryGroupSenderKeyStore,
        session_store: &mut NoopSessionStore,
        identity_store: &mut NoopIdentityStore,
        prekey_store: &mut NoopPreKeyStore,
        signed_prekey_store: &NoopSignedPreKeyStore,
    };

    // Map PN 1111 -> LID 1111@lid, and PN 9999 -> LID 9999@lid
    let mut encryption_map = HashMap::new();
    encryption_map.insert(
        "1111@s.whatsapp.net".parse().unwrap(),
        "1111@lid".parse().unwrap(),
    );
    encryption_map.insert(
        "9999@s.whatsapp.net".parse().unwrap(),
        "9999@lid".parse().unwrap(),
    );

    let resolver = MockResolver {
        devices_calls: Default::default(),
        encryption_calls: Default::default(),
        encryption_map,
    };

    let mut group_info = GroupInfo {
        participants: vec!["1111@s.whatsapp.net".parse().unwrap()],
        addressing_mode: AddressingMode::Lid,
    };
    let own_pn: Jid = "9999@s.whatsapp.net".parse().unwrap();
    let own_lid: Jid = "9999@lid".parse().unwrap();
    let group_jid: Jid = "12345@g.us".parse().unwrap();

    let msg = waproto::whatsapp::Message::default();
    let _stanza = wacore::send::prepare_group_stanza(
        &mut stores,
        &resolver,
        &mut group_info,
        &own_pn,
        &own_lid,
        None,
        group_jid,
        &msg,
        "req-2".to_string(),
        false,
        None,
    )
    .await
    .unwrap();

    // Should call resolve_encryption_jids once, but not resolve devices unless SKDM is forced
    assert_eq!(resolver.encryption_calls.lock().unwrap().len(), 1);
    let dcalls = resolver.devices_calls.lock().unwrap();
    assert_eq!(dcalls.len(), 0);
}
