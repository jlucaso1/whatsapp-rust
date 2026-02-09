use std::collections::HashMap;

use async_trait::async_trait;
use iai_callgrind::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use std::hint::black_box;
use wacore_libsignal::protocol::{
    ChainKey, CiphertextMessage, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, MessageKeyGenerator, PreKeyBundle, PreKeyId,
    PreKeyRecord, PreKeyStore, ProtocolAddress, RootKey, SenderKeyRecord, SenderKeyStore,
    SessionRecord, SessionState, SessionStore, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, UsePQRatchet, consts, create_sender_key_distribution_message,
    group_decrypt, group_encrypt, message_decrypt, message_encrypt, process_prekey_bundle,
    process_sender_key_distribution_message,
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
        Ok(self.identity_key_pair.clone())
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

// Signature-specific benchmarks to measure the XEdDSA optimization
fn setup_keypair_with_message() -> (KeyPair, [u8; 64]) {
    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);
    let message = [0x42u8; 64]; // Fixed message for consistent benchmarking
    (keypair, message)
}

// Benchmark raw signature creation (the main target of the caching optimization).
// This measures signing with a pre-created key, which is the common case in real usage.
#[library_benchmark]
#[bench::sign(setup = setup_keypair_with_message)]
fn bench_signature_creation(data: (KeyPair, [u8; 64])) {
    let (keypair, message) = data;
    let mut rng = rand::rng();

    // Sign multiple times to amortize any setup overhead
    for _ in 0..10 {
        let signature = keypair
            .calculate_signature(&message, &mut rng)
            .expect("signature");
        black_box(signature);
    }
}

// Benchmark signature verification
#[library_benchmark]
#[bench::verify(setup = setup_keypair_with_message)]
fn bench_signature_verification(data: (KeyPair, [u8; 64])) {
    let (keypair, message) = data;
    let mut rng = rand::rng();
    let signature = keypair
        .calculate_signature(&message, &mut rng)
        .expect("signature");

    // Verify multiple times
    for _ in 0..10 {
        let valid = keypair.public_key.verify_signature(&message, &signature);
        black_box(valid);
    }
}

// Benchmark key generation (shows the added cost of caching)
#[library_benchmark]
#[bench::keygen()]
fn bench_key_generation() {
    let mut rng = rand::rng();
    for _ in 0..10 {
        let keypair = KeyPair::generate(&mut rng);
        black_box(keypair);
    }
}

/// Creates a session with multiple archived previous sessions.
/// This simulates a scenario where Alice has re-keyed multiple times.
fn setup_with_archived_sessions() -> (User, User, Vec<Vec<u8>>) {
    let mut alice = User::new("alice", 1);
    let mut bob = User::new("bob", 1);
    let mut rng = rand::rng();

    // Store ciphertexts encrypted with each session version
    let mut old_ciphertexts = Vec::new();

    futures::executor::block_on(async {
        // Create initial session and send first message
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
        .expect("session 1");

        // Send a message with this session (to be used for previous session decryption)
        let msg = message_encrypt(
            b"Message from session 1",
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encrypt");
        old_ciphertexts.push(msg.serialize().to_vec());

        // Bob processes Alice's first message to establish his side
        let ct = CiphertextMessage::PreKeySignalMessage(
            wacore_libsignal::protocol::PreKeySignalMessage::try_from(
                old_ciphertexts[0].as_slice(),
            )
            .unwrap(),
        );
        message_decrypt(
            &ct,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt");

        // Now create multiple new sessions to archive the old one
        // Each new PreKey message from Alice will archive Bob's current session
        for i in 2..=10 {
            // Alice creates a fresh session (simulating re-keying)
            alice.session_store = InMemorySessionStore::new();

            // Generate new prekeys for Bob
            bob.prekey_id = (i as u32).into();
            bob.prekey_pair = KeyPair::generate(&mut rng);
            let prekey_record = PreKeyRecord::new(bob.prekey_id, &bob.prekey_pair);
            bob.prekey_store
                .save_pre_key(bob.prekey_id, &prekey_record)
                .await
                .unwrap();

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
            .expect("new session");

            // Send PreKey message to establish new session on Bob's side
            let msg = message_encrypt(
                format!("Message from session {}", i).as_bytes(),
                &bob.address,
                &mut alice.session_store,
                &mut alice.identity_store,
            )
            .await
            .expect("encrypt");

            let ct = CiphertextMessage::PreKeySignalMessage(
                wacore_libsignal::protocol::PreKeySignalMessage::try_from(msg.serialize()).unwrap(),
            );
            message_decrypt(
                &ct,
                &alice.address,
                &mut bob.session_store,
                &mut bob.identity_store,
                &mut bob.prekey_store,
                &bob.signed_prekey_store,
                &mut rng,
                UsePQRatchet::No,
            )
            .await
            .expect("decrypt");

            // Store the message encrypted with this session
            let msg2 = message_encrypt(
                format!("Another message from session {}", i).as_bytes(),
                &bob.address,
                &mut alice.session_store,
                &mut alice.identity_store,
            )
            .await
            .expect("encrypt");
            old_ciphertexts.push(msg2.serialize().to_vec());
        }
    });

    (alice, bob, old_ciphertexts)
}

// Benchmark decryption that requires searching through previous sessions.
// This tests the take/restore optimization for previous session iteration.
#[library_benchmark]
#[bench::previous_session(setup = setup_with_archived_sessions)]
fn bench_decrypt_with_previous_session(data: (User, User, Vec<Vec<u8>>)) {
    let (alice, mut bob, ciphertexts) = data;
    let mut rng = rand::rng();

    // Try to decrypt an old message (encrypted with a previous session)
    // This forces the decryption to iterate through previous sessions
    futures::executor::block_on(async {
        for ciphertext in ciphertexts.iter().take(5) {
            // Try to parse as SignalMessage (non-PreKey)
            if let Ok(signal_msg) =
                wacore_libsignal::protocol::SignalMessage::try_from(ciphertext.as_slice())
            {
                let ct = CiphertextMessage::SignalMessage(signal_msg);
                let result = message_decrypt(
                    &ct,
                    &alice.address,
                    &mut bob.session_store,
                    &mut bob.identity_store,
                    &mut bob.prekey_store,
                    &bob.signed_prekey_store,
                    &mut rng,
                    UsePQRatchet::No,
                )
                .await;
                let _ = black_box(result);
            }
        }
    });
}

// Setup for out-of-order message benchmark.
// Creates a fully established session and prepares multiple SignalMessages.
fn setup_out_of_order_messages() -> (User, User, Vec<Vec<u8>>) {
    let (mut alice, mut bob) = setup_dm_session();
    let mut messages = Vec::new();

    futures::executor::block_on(async {
        let mut rng = rand::rng();

        // Alice sends initial PreKey message to Bob
        let msg = message_encrypt(
            b"Initial message",
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encrypt");

        let ct = CiphertextMessage::PreKeySignalMessage(
            wacore_libsignal::protocol::PreKeySignalMessage::try_from(msg.serialize()).unwrap(),
        );
        message_decrypt(
            &ct,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt initial");

        // Bob replies to Alice - this completes the session establishment
        let reply = message_encrypt(
            b"Reply from Bob",
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
        )
        .await
        .expect("encrypt reply");

        let ct_reply = CiphertextMessage::SignalMessage(
            wacore_libsignal::protocol::SignalMessage::try_from(reply.serialize()).unwrap(),
        );
        message_decrypt(
            &ct_reply,
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
            &mut alice.prekey_store,
            &alice.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt reply");

        // Now Alice can send SignalMessages (not PreKey)
        for i in 0..20 {
            let msg = message_encrypt(
                format!("Message {}", i).as_bytes(),
                &bob.address,
                &mut alice.session_store,
                &mut alice.identity_store,
            )
            .await
            .expect("encrypt");
            messages.push(msg.serialize().to_vec());
        }
    });

    (alice, bob, messages)
}

// Benchmark out-of-order message decryption.
// This tests the set_message_keys optimization (push vs insert(0)).
// Messages are decrypted in reverse order, causing maximum message key storage.
#[library_benchmark]
#[bench::out_of_order(setup = setup_out_of_order_messages)]
fn bench_out_of_order_decryption(data: (User, User, Vec<Vec<u8>>)) {
    let (alice, mut bob, messages) = data;
    let mut rng = rand::rng();

    futures::executor::block_on(async {
        // Decrypt messages in reverse order (worst case for message key storage)
        for ciphertext in messages.iter().rev() {
            let signal_msg =
                wacore_libsignal::protocol::SignalMessage::try_from(ciphertext.as_slice())
                    .expect("parse");
            let ct = CiphertextMessage::SignalMessage(signal_msg);
            let result = message_decrypt(
                &ct,
                &alice.address,
                &mut bob.session_store,
                &mut bob.identity_store,
                &mut bob.prekey_store,
                &bob.signed_prekey_store,
                &mut rng,
                UsePQRatchet::No,
            )
            .await
            .expect("decrypt");
            black_box(result);
        }
    });
}

/// Setup for promote_matching_session benchmark.
/// Creates a session record with many archived sessions, then creates a PreKey
/// message that should match and promote one of the previous sessions.
fn setup_promote_matching_session() -> (User, User, Vec<u8>) {
    let mut alice = User::new("alice", 1);
    let mut bob = User::new("bob", 1);
    let mut rng = rand::rng();

    let prekey_message = futures::executor::block_on(async {
        // Create initial session
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

        // Send initial message to establish Bob's session
        let msg = message_encrypt(
            b"First contact",
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encrypt");

        let ct = CiphertextMessage::PreKeySignalMessage(
            wacore_libsignal::protocol::PreKeySignalMessage::try_from(msg.serialize()).unwrap(),
        );
        message_decrypt(
            &ct,
            &alice.address,
            &mut bob.session_store,
            &mut bob.identity_store,
            &mut bob.prekey_store,
            &bob.signed_prekey_store,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("decrypt");

        // Create many new sessions to push the original to previous_sessions
        for i in 2..=20 {
            // Generate new prekeys for Bob
            bob.prekey_id = (i as u32).into();
            bob.prekey_pair = KeyPair::generate(&mut rng);
            let prekey_record = PreKeyRecord::new(bob.prekey_id, &bob.prekey_pair);
            bob.prekey_store
                .save_pre_key(bob.prekey_id, &prekey_record)
                .await
                .unwrap();

            // Alice starts fresh session
            alice.session_store = InMemorySessionStore::new();
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
            .expect("new session");

            let msg = message_encrypt(
                format!("Session {}", i).as_bytes(),
                &bob.address,
                &mut alice.session_store,
                &mut alice.identity_store,
            )
            .await
            .expect("encrypt");

            let ct = CiphertextMessage::PreKeySignalMessage(
                wacore_libsignal::protocol::PreKeySignalMessage::try_from(msg.serialize()).unwrap(),
            );
            message_decrypt(
                &ct,
                &alice.address,
                &mut bob.session_store,
                &mut bob.identity_store,
                &mut bob.prekey_store,
                &bob.signed_prekey_store,
                &mut rng,
                UsePQRatchet::No,
            )
            .await
            .expect("decrypt");
        }

        // Now Alice sends another PreKey message with the CURRENT session
        // This should trigger promote_matching_session to find and promote it
        let final_msg = message_encrypt(
            b"Final message with current session",
            &bob.address,
            &mut alice.session_store,
            &mut alice.identity_store,
        )
        .await
        .expect("encrypt");

        final_msg.serialize().to_vec()
    });

    (alice, bob, prekey_message)
}

// Benchmark promote_matching_session during PreKey processing.
// This tests the find_matching_previous_session_index optimization.
#[library_benchmark]
#[bench::promote(setup = setup_promote_matching_session)]
fn bench_promote_matching_session(data: (User, User, Vec<u8>)) {
    let (alice, mut bob, prekey_message) = data;
    let mut rng = rand::rng();

    futures::executor::block_on(async {
        // Process multiple PreKey messages to exercise promote_matching_session
        for _ in 0..5 {
            let ct = CiphertextMessage::PreKeySignalMessage(
                wacore_libsignal::protocol::PreKeySignalMessage::try_from(
                    prekey_message.as_slice(),
                )
                .unwrap(),
            );
            let result = message_decrypt(
                &ct,
                &alice.address,
                &mut bob.session_store,
                &mut bob.identity_store,
                &mut bob.prekey_store,
                &bob.signed_prekey_store,
                &mut rng,
                UsePQRatchet::No,
            )
            .await;
            let _ = black_box(result);
        }
    });
}

/// Helper function to create a test message key generator.
fn create_test_message_key_generator(counter: u32) -> MessageKeyGenerator {
    let mut seed = [0u8; 32];
    seed[0] = counter as u8;
    seed[1] = (counter >> 8) as u8;
    seed[2] = (counter >> 16) as u8;
    seed[3] = (counter >> 24) as u8;
    MessageKeyGenerator::new_from_seed(&seed, counter)
}

/// Helper function to create a minimal valid SessionState for testing.
fn create_test_session_state(
    version: u8,
    base_key: &wacore_libsignal::protocol::PublicKey,
) -> SessionState {
    let mut csprng = rand::rng();
    let identity_keypair = KeyPair::generate(&mut csprng);
    let their_identity = IdentityKey::new(identity_keypair.public_key);
    let our_identity = IdentityKey::new(KeyPair::generate(&mut csprng).public_key);
    let root_key = RootKey::new([0u8; 32]);

    let mut state = SessionState::new(version, &our_identity, &their_identity, &root_key, base_key);

    // Add a sender chain to make it usable
    let sender_keypair = KeyPair::generate(&mut csprng);
    let chain_key = ChainKey::new([1u8; 32], 0);
    state.set_sender_chain(&sender_keypair, &chain_key);

    state
}

/// Setup for message key eviction benchmark.
/// Creates a session with a receiver chain pre-filled near capacity.
fn setup_message_key_eviction() -> (SessionState, wacore_libsignal::protocol::PublicKey) {
    let mut csprng = rand::rng();
    let base_key = KeyPair::generate(&mut csprng).public_key;
    let mut state = create_test_session_state(3, &base_key);

    // Add a receiver chain
    let sender_key = KeyPair::generate(&mut csprng).public_key;
    let chain_key = ChainKey::new([2u8; 32], 0);
    state.add_receiver_chain(&sender_key, &chain_key);

    // Pre-fill the chain to MAX_MESSAGE_KEYS - 1 (one less than capacity)
    // This simulates a session that has been receiving out-of-order messages
    // and is about to hit the eviction threshold
    for counter in 0..(consts::MAX_MESSAGE_KEYS - 1) as u32 {
        let keys = create_test_message_key_generator(counter);
        state.set_message_keys(&sender_key, keys).unwrap();
    }

    (state, sender_key)
}

// Benchmark message key insertion with amortized eviction.
// This tests the set_message_keys optimization with PRUNE_THRESHOLD.
// We insert 200 keys beyond MAX_MESSAGE_KEYS to measure multiple eviction cycles.
#[library_benchmark]
#[bench::eviction(setup = setup_message_key_eviction)]
fn bench_message_key_eviction(data: (SessionState, wacore_libsignal::protocol::PublicKey)) {
    let (mut state, sender_key) = data;
    let start_counter = (consts::MAX_MESSAGE_KEYS - 1) as u32;

    // Insert 200 keys beyond capacity - this will trigger eviction cycles
    // With PRUNE_THRESHOLD=50, we expect ~4 eviction events
    for i in 0..200u32 {
        let counter = start_counter + i;
        let keys = create_test_message_key_generator(counter);
        state.set_message_keys(&sender_key, keys).unwrap();
    }

    black_box(state);
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

library_benchmark_group!(
    name = signature_group;
    benchmarks =
        bench_signature_creation,
        bench_signature_verification,
        bench_key_generation
);

library_benchmark_group!(
    name = session_optimization_group;
    benchmarks =
        bench_decrypt_with_previous_session,
        bench_out_of_order_decryption,
        bench_promote_matching_session,
        bench_message_key_eviction
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups =
        dm_group,
        group_messaging_group,
        conversation_group,
        signature_group,
        session_optimization_group
);
