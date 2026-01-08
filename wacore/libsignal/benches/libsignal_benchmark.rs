use std::collections::HashMap;

use async_trait::async_trait;
use iai_callgrind::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use std::hint::black_box;
use wacore_libsignal::protocol::{
    CiphertextMessage, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, SenderKeyRecord, SenderKeyStore, SessionRecord, SessionStore, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp, UsePQRatchet,
    create_sender_key_distribution_message, group_decrypt, group_encrypt, message_decrypt,
    message_encrypt, process_prekey_bundle, process_sender_key_distribution_message,
};
use wacore_libsignal::store::sender_key_name::SenderKeyName;

struct InMemoryIdentityKeyStore {
    identity_key_pair: IdentityKeyPair,
    registration_id: u32,
    identities: HashMap<ProtocolAddress, IdentityKey>,
}

impl InMemoryIdentityKeyStore {
    fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity_key_pair,
            registration_id,
            identities: HashMap::new(),
        }
    }
}

#[async_trait]
impl IdentityKeyStore for InMemoryIdentityKeyStore {
    async fn get_identity_key_pair(
        &self,
    ) -> wacore_libsignal::protocol::error::Result<IdentityKeyPair> {
        Ok(self.identity_key_pair)
    }

    async fn get_local_registration_id(&self) -> wacore_libsignal::protocol::error::Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> wacore_libsignal::protocol::error::Result<IdentityChange> {
        let changed = self
            .identities
            .get(address)
            .is_some_and(|existing| existing != identity);
        self.identities.insert(address.clone(), *identity);
        Ok(IdentityChange::from_changed(changed))
    }

    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
        _direction: Direction,
    ) -> wacore_libsignal::protocol::error::Result<bool> {
        Ok(true)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> wacore_libsignal::protocol::error::Result<Option<IdentityKey>> {
        Ok(self.identities.get(address).cloned())
    }
}

struct InMemoryPreKeyStore {
    prekeys: HashMap<PreKeyId, PreKeyRecord>,
}

impl InMemoryPreKeyStore {
    fn new() -> Self {
        Self {
            prekeys: HashMap::new(),
        }
    }
}

#[async_trait]
impl PreKeyStore for InMemoryPreKeyStore {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
    ) -> wacore_libsignal::protocol::error::Result<PreKeyRecord> {
        self.prekeys
            .get(&prekey_id)
            .cloned()
            .ok_or(wacore_libsignal::protocol::SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> wacore_libsignal::protocol::error::Result<()> {
        self.prekeys.insert(prekey_id, record.clone());
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
    ) -> wacore_libsignal::protocol::error::Result<()> {
        self.prekeys.remove(&prekey_id);
        Ok(())
    }
}

struct InMemorySignedPreKeyStore {
    signed_prekeys: HashMap<SignedPreKeyId, SignedPreKeyRecord>,
}

impl InMemorySignedPreKeyStore {
    fn new() -> Self {
        Self {
            signed_prekeys: HashMap::new(),
        }
    }
}

#[async_trait]
impl SignedPreKeyStore for InMemorySignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> wacore_libsignal::protocol::error::Result<SignedPreKeyRecord> {
        self.signed_prekeys
            .get(&signed_prekey_id)
            .cloned()
            .ok_or(wacore_libsignal::protocol::SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> wacore_libsignal::protocol::error::Result<()> {
        self.signed_prekeys.insert(signed_prekey_id, record.clone());
        Ok(())
    }
}

struct InMemorySessionStore {
    sessions: HashMap<ProtocolAddress, SessionRecord>,
}

impl InMemorySessionStore {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> wacore_libsignal::protocol::error::Result<Option<SessionRecord>> {
        Ok(self.sessions.get(address).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> wacore_libsignal::protocol::error::Result<()> {
        self.sessions.insert(address.clone(), record.clone());
        Ok(())
    }
}

struct InMemorySenderKeyStore {
    sender_keys: HashMap<SenderKeyName, SenderKeyRecord>,
}

impl InMemorySenderKeyStore {
    fn new() -> Self {
        Self {
            sender_keys: HashMap::new(),
        }
    }
}

#[async_trait]
impl SenderKeyStore for InMemorySenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> wacore_libsignal::protocol::error::Result<()> {
        self.sender_keys
            .insert(sender_key_name.clone(), record.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> wacore_libsignal::protocol::error::Result<Option<SenderKeyRecord>> {
        Ok(self.sender_keys.get(sender_key_name).cloned())
    }
}

struct User {
    address: ProtocolAddress,
    identity_store: InMemoryIdentityKeyStore,
    prekey_store: InMemoryPreKeyStore,
    signed_prekey_store: InMemorySignedPreKeyStore,
    session_store: InMemorySessionStore,
    sender_key_store: InMemorySenderKeyStore,
    prekey_id: PreKeyId,
    signed_prekey_id: SignedPreKeyId,
    prekey_pair: KeyPair,
    signed_prekey_pair: KeyPair,
    signed_prekey_signature: Vec<u8>,
}

impl User {
    fn new(name: &str, device_id: u32) -> Self {
        let mut rng = rand::rng();

        let identity_key_pair = IdentityKeyPair::generate(&mut rng);
        let registration_id = rand::random::<u32>() & 0x3FFF;

        let prekey_id: PreKeyId = 1.into();
        let prekey_pair = KeyPair::generate(&mut rng);
        let prekey_record = PreKeyRecord::new(prekey_id, &prekey_pair);

        let signed_prekey_id: SignedPreKeyId = 1.into();
        let signed_prekey_pair = KeyPair::generate(&mut rng);
        let signed_prekey_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_prekey_pair.public_key.serialize(), &mut rng)
            .expect("signature");
        let signed_prekey_record = SignedPreKeyRecord::new(
            signed_prekey_id,
            Timestamp::from_epoch_millis(0),
            &signed_prekey_pair,
            &signed_prekey_signature,
        );

        let identity_store = InMemoryIdentityKeyStore::new(identity_key_pair, registration_id);
        let mut prekey_store = InMemoryPreKeyStore::new();
        let mut signed_prekey_store = InMemorySignedPreKeyStore::new();
        let session_store = InMemorySessionStore::new();
        let sender_key_store = InMemorySenderKeyStore::new();

        futures::executor::block_on(async {
            prekey_store
                .save_pre_key(prekey_id, &prekey_record)
                .await
                .unwrap();
            signed_prekey_store
                .save_signed_pre_key(signed_prekey_id, &signed_prekey_record)
                .await
                .unwrap();
        });

        let address = ProtocolAddress::new(name.to_string(), device_id.into());

        Self {
            address,
            identity_store,
            prekey_store,
            signed_prekey_store,
            session_store,
            sender_key_store,
            prekey_id,
            signed_prekey_id,
            prekey_pair,
            signed_prekey_pair,
            signed_prekey_signature: signed_prekey_signature.to_vec(),
        }
    }

    fn get_prekey_bundle(&self) -> PreKeyBundle {
        PreKeyBundle::new(
            self.identity_store.registration_id,
            1.into(),
            Some((self.prekey_id, self.prekey_pair.public_key)),
            self.signed_prekey_id,
            self.signed_prekey_pair.public_key,
            self.signed_prekey_signature.clone(),
            *self.identity_store.identity_key_pair.identity_key(),
        )
        .expect("valid bundle")
    }
}

fn setup_dm_users() -> (User, User) {
    let alice = User::new("alice", 1);
    let bob = User::new("bob", 1);
    (alice, bob)
}

fn setup_dm_session() -> (User, User) {
    let (mut alice, bob) = setup_dm_users();

    let bob_bundle = bob.get_prekey_bundle();
    let mut rng = rand::rng();

    futures::executor::block_on(async {
        process_prekey_bundle(
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
            &bob_bundle,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("session established");
    });

    (alice, bob)
}

fn setup_dm_with_first_message() -> (User, User, Vec<u8>) {
    let (mut alice, bob) = setup_dm_session();

    let plaintext = b"Hello Bob! This is Alice.";
    let ciphertext = futures::executor::block_on(async {
        message_encrypt(
            plaintext,
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encryption")
    });

    (alice, bob, ciphertext.serialize().to_vec())
}

fn setup_established_dm_session() -> (User, User) {
    let (mut alice, mut bob) = setup_dm_session();

    let plaintext = b"Hello Bob!";
    futures::executor::block_on(async {
        let ct = message_encrypt(
            plaintext,
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encryption");

        let ct_msg = CiphertextMessage::PreKeySignalMessage(
            wacore_libsignal::protocol::PreKeySignalMessage::try_from(ct.serialize()).unwrap(),
        );
        let mut rng = rand::rng();
        message_decrypt(
            &ct_msg,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decryption");
    });

    (alice, bob)
}

fn setup_group_sender() -> (User, SenderKeyName) {
    let alice = User::new("alice", 1);
    let group_id = "group123@g.us".to_string();
    let sender_key_name = SenderKeyName::new(group_id, alice.address.name().to_string());
    (alice, sender_key_name)
}

fn setup_group_with_distribution() -> (User, User, SenderKeyName) {
    let (mut alice, sender_key_name) = setup_group_sender();
    let mut bob = User::new("bob", 1);

    futures::executor::block_on(async {
        let mut rng = rand::rng();
        let skdm = create_sender_key_distribution_message(
            &sender_key_name,
            &mut alice.sender_key_store,
            &mut rng,
        )
        .await
        .expect("skdm");

        let bob_sender_key_name = SenderKeyName::new(
            sender_key_name.group_id().to_string(),
            alice.address.name().to_string(),
        );
        process_sender_key_distribution_message(
            &bob_sender_key_name,
            &skdm,
            &mut bob.sender_key_store,
        )
        .await
        .expect("process skdm");
    });

    (alice, bob, sender_key_name)
}

#[library_benchmark]
#[bench::setup(setup = setup_dm_users)]
fn bench_dm_session_establishment(data: (User, User)) {
    let (mut alice, bob) = data;
    let bob_bundle = bob.get_prekey_bundle();
    let mut rng = rand::rng();

    futures::executor::block_on(async {
        process_prekey_bundle(
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
            &bob_bundle,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("session");
    });

    black_box(alice);
}

#[library_benchmark]
#[bench::first_msg(setup = setup_dm_session)]
fn bench_dm_encrypt_first_message(data: (User, User)) {
    let (mut alice, bob) = data;
    let plaintext = b"Hello Bob! This is the first message.";

    let ciphertext = futures::executor::block_on(async {
        message_encrypt(
            plaintext,
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encryption")
    });

    black_box(ciphertext);
}

#[library_benchmark]
#[bench::decrypt_prekey(setup = setup_dm_with_first_message)]
fn bench_dm_decrypt_first_message(data: (User, User, Vec<u8>)) {
    let (alice, mut bob, ciphertext_bytes) = data;
    let mut rng = rand::rng();

    let plaintext = futures::executor::block_on(async {
        let ciphertext = CiphertextMessage::PreKeySignalMessage(
            wacore_libsignal::protocol::PreKeySignalMessage::try_from(ciphertext_bytes.as_slice())
                .unwrap(),
        );
        message_decrypt(
            &ciphertext,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decryption")
    });

    black_box(plaintext);
}

#[library_benchmark]
#[bench::subsequent(setup = setup_established_dm_session)]
fn bench_dm_encrypt_subsequent_message(data: (User, User)) {
    let (mut alice, bob) = data;
    let plaintext = b"This is a follow-up message after session is established.";

    let ciphertext = futures::executor::block_on(async {
        message_encrypt(
            plaintext,
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encryption")
    });

    black_box(ciphertext);
}

#[library_benchmark]
#[bench::create(setup = setup_group_sender)]
fn bench_group_create_distribution_message(data: (User, SenderKeyName)) {
    let (mut alice, sender_key_name) = data;
    let mut rng = rand::rng();

    let skdm = futures::executor::block_on(async {
        create_sender_key_distribution_message(
            &sender_key_name,
            &mut alice.sender_key_store,
            &mut rng,
        )
        .await
        .expect("skdm")
    });

    black_box(skdm);
}

#[library_benchmark]
#[bench::encrypt(setup = setup_group_with_distribution)]
fn bench_group_encrypt_message(data: (User, User, SenderKeyName)) {
    let (mut alice, _bob, sender_key_name) = data;
    let plaintext = b"Hello group! This is a group message from Alice.";
    let mut rng = rand::rng();

    let ciphertext = futures::executor::block_on(async {
        group_encrypt(
            &mut alice.sender_key_store,
            &sender_key_name,
            plaintext,
            &mut rng,
        )
        .await
        .expect("group encrypt")
    });

    black_box(ciphertext);
}

fn setup_group_with_encrypted_message() -> (User, User, SenderKeyName, Vec<u8>) {
    let (mut alice, bob, sender_key_name) = setup_group_with_distribution();

    let ciphertext = futures::executor::block_on(async {
        let mut rng = rand::rng();
        let skm = group_encrypt(
            &mut alice.sender_key_store,
            &sender_key_name,
            b"Group message content",
            &mut rng,
        )
        .await
        .expect("group encrypt");
        skm.serialized().to_vec()
    });

    (alice, bob, sender_key_name, ciphertext)
}

#[library_benchmark]
#[bench::decrypt(setup = setup_group_with_encrypted_message)]
fn bench_group_decrypt_message(data: (User, User, SenderKeyName, Vec<u8>)) {
    let (alice, mut bob, sender_key_name, ciphertext) = data;

    let bob_sender_key_name = SenderKeyName::new(
        sender_key_name.group_id().to_string(),
        alice.address.name().to_string(),
    );

    let plaintext = futures::executor::block_on(async {
        group_decrypt(&ciphertext, &mut bob.sender_key_store, &bob_sender_key_name)
            .await
            .expect("group decrypt")
    });

    black_box(plaintext);
}

fn setup_conversation_data() -> (User, User) {
    setup_dm_users()
}

#[library_benchmark]
#[bench::full(setup = setup_conversation_data)]
fn bench_full_dm_conversation(data: (User, User)) {
    let (mut alice, mut bob) = data;
    let mut rng = rand::rng();

    futures::executor::block_on(async {
        let bob_bundle = bob.get_prekey_bundle();
        process_prekey_bundle(
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
            &bob_bundle,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("session");

        let msg1 = message_encrypt(
            b"Hello Bob!",
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encrypt1");

        let ct1 = CiphertextMessage::PreKeySignalMessage(
            wacore_libsignal::protocol::PreKeySignalMessage::try_from(msg1.serialize()).unwrap(),
        );
        let _ = message_decrypt(
            &ct1,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt1");

        let msg2 = message_encrypt(
            b"Hi Alice!",
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
        )
        .await
        .expect("encrypt2");

        let ct2 = CiphertextMessage::SignalMessage(
            wacore_libsignal::protocol::SignalMessage::try_from(msg2.serialize()).unwrap(),
        );
        let _ = message_decrypt(
            &ct2,
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
            &mut alice.prekey_store,
            &alice.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt2");

        let msg3 = message_encrypt(
            b"How are you?",
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encrypt3");

        let ct3 = CiphertextMessage::SignalMessage(
            wacore_libsignal::protocol::SignalMessage::try_from(msg3.serialize()).unwrap(),
        );
        let _ = message_decrypt(
            &ct3,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt3");
    });

    black_box((alice, bob));
}

library_benchmark_group!(
    name = dm_group;
    benchmarks =
        bench_dm_session_establishment,
        bench_dm_encrypt_first_message,
        bench_dm_decrypt_first_message,
        bench_dm_encrypt_subsequent_message
);

library_benchmark_group!(
    name = group_messaging_group;
    benchmarks =
        bench_group_create_distribution_message,
        bench_group_encrypt_message,
        bench_group_decrypt_message
);

library_benchmark_group!(
    name = conversation_group;
    benchmarks = bench_full_dm_conversation
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups =
        dm_group,
        group_messaging_group,
        conversation_group
);
