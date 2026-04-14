//! Full send/receive pipeline benchmarks using real `prepare_*_stanza` functions.

use async_trait::async_trait;
use iai_callgrind::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use prost::Message as ProtoMessage;
use std::collections::HashMap;
use std::hint::black_box;
use wacore::client::context::{GroupInfo, SendContextResolver};
use wacore::messages::MessageUtils;
use wacore::send::{SignalStores, prepare_group_stanza, prepare_peer_stanza};
use wacore::types::jid::{JidExt, make_sender_key_name};
use wacore::types::message::AddressingMode;
use wacore_binary::jid::Jid;
use wacore_binary::marshal::marshal;
use wacore_binary::node::{Node, NodeContent};
use wacore_libsignal::protocol::{
    CiphertextMessage, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, PreKeyBundle, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SenderKeyRecord, SenderKeyStore,
    SessionRecord, SessionStore, SignalMessage, SignedPreKeyId, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, UsePQRatchet, create_sender_key_distribution_message,
    group_decrypt, message_decrypt, message_encrypt, process_prekey_bundle,
    process_sender_key_distribution_message,
};
use wacore_libsignal::store::sender_key_name::SenderKeyName;
use waproto::whatsapp as wa;

type SigResult<T> = wacore_libsignal::protocol::error::Result<T>;

// ---------------------------------------------------------------------------
// In-memory Signal stores
// ---------------------------------------------------------------------------

struct MemIdentityStore {
    key_pair: IdentityKeyPair,
    reg_id: u32,
    identities: HashMap<ProtocolAddress, IdentityKey>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityKeyStore for MemIdentityStore {
    async fn get_identity_key_pair(&self) -> SigResult<IdentityKeyPair> {
        Ok(self.key_pair.clone())
    }
    async fn get_local_registration_id(&self) -> SigResult<u32> {
        Ok(self.reg_id)
    }
    async fn save_identity(
        &mut self,
        a: &ProtocolAddress,
        id: &IdentityKey,
    ) -> SigResult<IdentityChange> {
        let changed = self.identities.get(a).is_some_and(|e| e != id);
        self.identities.insert(a.clone(), *id);
        Ok(IdentityChange::from_changed(changed))
    }
    async fn is_trusted_identity(
        &self,
        _: &ProtocolAddress,
        _: &IdentityKey,
        _: Direction,
    ) -> SigResult<bool> {
        Ok(true)
    }
    async fn get_identity(&self, a: &ProtocolAddress) -> SigResult<Option<IdentityKey>> {
        Ok(self.identities.get(a).cloned())
    }
}

struct MemPreKeyStore(HashMap<PreKeyId, PreKeyRecord>);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PreKeyStore for MemPreKeyStore {
    async fn get_pre_key(&self, id: PreKeyId) -> SigResult<PreKeyRecord> {
        self.0
            .get(&id)
            .cloned()
            .ok_or(wacore_libsignal::protocol::SignalProtocolError::InvalidPreKeyId)
    }
    async fn save_pre_key(&mut self, id: PreKeyId, r: &PreKeyRecord) -> SigResult<()> {
        self.0.insert(id, r.clone());
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> SigResult<()> {
        self.0.remove(&id);
        Ok(())
    }
}

struct MemSignedPreKeyStore(HashMap<SignedPreKeyId, SignedPreKeyRecord>);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SignedPreKeyStore for MemSignedPreKeyStore {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SigResult<SignedPreKeyRecord> {
        self.0
            .get(&id)
            .cloned()
            .ok_or(wacore_libsignal::protocol::SignalProtocolError::InvalidSignedPreKeyId)
    }
    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        r: &SignedPreKeyRecord,
    ) -> SigResult<()> {
        self.0.insert(id, r.clone());
        Ok(())
    }
}

struct MemSessionStore(HashMap<ProtocolAddress, SessionRecord>);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SessionStore for MemSessionStore {
    async fn load_session(&self, a: &ProtocolAddress) -> SigResult<Option<SessionRecord>> {
        Ok(self.0.get(a).cloned())
    }
    async fn has_session(&self, a: &ProtocolAddress) -> SigResult<bool> {
        Ok(self.0.contains_key(a))
    }
    async fn store_session(&mut self, a: &ProtocolAddress, r: SessionRecord) -> SigResult<()> {
        self.0.insert(a.clone(), r);
        Ok(())
    }
}

struct MemSenderKeyStore(HashMap<SenderKeyName, SenderKeyRecord>);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SenderKeyStore for MemSenderKeyStore {
    async fn store_sender_key(&mut self, n: &SenderKeyName, r: SenderKeyRecord) -> SigResult<()> {
        self.0.insert(n.clone(), r);
        Ok(())
    }
    async fn load_sender_key(&self, n: &SenderKeyName) -> SigResult<Option<SenderKeyRecord>> {
        Ok(self.0.get(n).cloned())
    }
}

// ---------------------------------------------------------------------------
// User: bundles all Signal stores for one participant
// ---------------------------------------------------------------------------

struct User {
    jid: Jid,
    address: ProtocolAddress,
    identity: MemIdentityStore,
    prekeys: MemPreKeyStore,
    signed_prekeys: MemSignedPreKeyStore,
    sessions: MemSessionStore,
    sender_keys: MemSenderKeyStore,
    prekey_pair: KeyPair,
    signed_prekey_pair: KeyPair,
    signed_prekey_sig: Vec<u8>,
}

impl User {
    fn new(user: &str, server: &str) -> Self {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let identity_key_pair = IdentityKeyPair::generate(&mut rng);
        let reg_id = rand::random::<u32>() & 0x3FFF;

        let pk_id: PreKeyId = 1.into();
        let pk_pair = KeyPair::generate(&mut rng);
        let pk_record = PreKeyRecord::new(pk_id, &pk_pair);

        let spk_id: SignedPreKeyId = 1.into();
        let spk_pair = KeyPair::generate(&mut rng);
        let spk_sig = identity_key_pair
            .private_key()
            .calculate_signature(&spk_pair.public_key.serialize(), &mut rng)
            .unwrap();
        let spk_record =
            SignedPreKeyRecord::new(spk_id, Timestamp::from_epoch_millis(0), &spk_pair, &spk_sig);

        let mut prekeys = MemPreKeyStore(HashMap::new());
        let mut signed_prekeys = MemSignedPreKeyStore(HashMap::new());
        futures::executor::block_on(async {
            prekeys.save_pre_key(pk_id, &pk_record).await.unwrap();
            signed_prekeys
                .save_signed_pre_key(spk_id, &spk_record)
                .await
                .unwrap();
        });

        let jid = Jid::new(
            user,
            wacore_binary::jid::Server::try_from(server)
                .expect("invalid server in benchmark fixture"),
        );
        let address = jid.to_protocol_address();

        Self {
            jid,
            address,
            identity: MemIdentityStore {
                key_pair: identity_key_pair,
                reg_id,
                identities: HashMap::new(),
            },
            prekeys,
            signed_prekeys,
            sessions: MemSessionStore(HashMap::new()),
            sender_keys: MemSenderKeyStore(HashMap::new()),
            prekey_pair: pk_pair,
            signed_prekey_pair: spk_pair,
            signed_prekey_sig: spk_sig.to_vec(),
        }
    }

    fn prekey_bundle(&self) -> PreKeyBundle {
        PreKeyBundle::new(
            self.identity.reg_id,
            1.into(),
            Some((1.into(), self.prekey_pair.public_key)),
            1.into(),
            self.signed_prekey_pair.public_key,
            self.signed_prekey_sig.clone(),
            *self.identity.key_pair.identity_key(),
        )
        .unwrap()
    }
}

fn establish_session(sender: &mut User, receiver: &User) {
    let bundle = receiver.prekey_bundle();
    let mut rng = rand::make_rng::<rand::rngs::StdRng>();
    futures::executor::block_on(async {
        process_prekey_bundle(
            &receiver.address,
            &mut sender.sessions,
            &mut sender.identity,
            &bundle,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .unwrap();
    });
}

/// Establish bidirectional session by sending one message in each direction.
fn establish_bidirectional(a: &mut User, b: &mut User) {
    establish_session(a, b);
    futures::executor::block_on(async {
        let ct = message_encrypt(b"init", &b.address, &mut a.sessions, &mut a.identity)
            .await
            .unwrap();
        let ct_msg = CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ct.serialize()).unwrap(),
        );
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        message_decrypt(
            &ct_msg,
            &a.address,
            &mut b.sessions,
            &mut b.identity,
            &mut b.prekeys,
            &b.signed_prekeys,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .unwrap();
    });
}

// ---------------------------------------------------------------------------
// Mock resolver (returns pre-configured devices, no server)
// ---------------------------------------------------------------------------

struct MockResolver(Vec<Jid>);

#[async_trait]
impl SendContextResolver for MockResolver {
    async fn resolve_devices(&self, _: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        Ok(self.0.clone())
    }
    async fn fetch_prekeys(&self, _: &[Jid]) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        Ok(HashMap::new())
    }
    async fn fetch_prekeys_for_identity_check(
        &self,
        _: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        Ok(HashMap::new())
    }
    async fn resolve_group_info(&self, _: &Jid) -> Result<GroupInfo, anyhow::Error> {
        Ok(GroupInfo::new(self.0.clone(), AddressingMode::Pn))
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn text_msg() -> wa::Message {
    wa::Message {
        conversation: Some("Hello, this is a benchmark message.".to_string()),
        ..Default::default()
    }
}

/// Extract the skmsg ciphertext from a group stanza Node (owned, no unsafe).
/// In production the server strips <participants> before forwarding to recipients,
/// so we extract just the skmsg <enc> bytes to simulate what the receiver sees.
fn extract_skmsg_bytes(stanza: &Node) -> Vec<u8> {
    let enc = stanza
        .children()
        .unwrap()
        .iter()
        .find(|n| {
            n.tag == "enc"
                && n.attrs()
                    .optional_string("type")
                    .is_some_and(|t| t.as_ref() == "skmsg")
        })
        .expect("skmsg enc node");

    match &enc.content {
        Some(NodeContent::Bytes(b)) => b.clone(),
        _ => panic!("expected bytes"),
    }
}

fn decrypt_dm(
    ciphertext: &[u8],
    enc_type: &str,
    sender_addr: &ProtocolAddress,
    receiver: &mut User,
) -> wa::Message {
    futures::executor::block_on(async {
        let parsed = if enc_type == "pkmsg" {
            CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(ciphertext).unwrap(),
            )
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext).unwrap())
        };
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let plaintext = message_decrypt(
            &parsed,
            sender_addr,
            &mut receiver.sessions,
            &mut receiver.identity,
            &mut receiver.prekeys,
            &receiver.signed_prekeys,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .unwrap();

        let unpadded = MessageUtils::unpad_message_ref(&plaintext, 2).unwrap();
        wa::Message::decode(unpadded).unwrap()
    })
}

fn decrypt_group(
    ciphertext: &[u8],
    sender_addr: &ProtocolAddress,
    group_jid: &Jid,
    receiver: &mut User,
) -> wa::Message {
    futures::executor::block_on(async {
        let sk_name = make_sender_key_name(group_jid, sender_addr);
        let plaintext = group_decrypt(ciphertext, &mut receiver.sender_keys, &sk_name)
            .await
            .unwrap();

        let unpadded = MessageUtils::unpad_message_ref(&plaintext, 2).unwrap();
        wa::Message::decode(unpadded).unwrap()
    })
}

// ---------------------------------------------------------------------------
// DM setups
// ---------------------------------------------------------------------------

struct DmSendData {
    alice: User,
    bob_jid: Jid,
    msg: wa::Message,
}

fn setup_dm_send() -> DmSendData {
    let mut alice = User::new("5511999000001", "s.whatsapp.net");
    let mut bob = User::new("5511999000002", "s.whatsapp.net");
    establish_bidirectional(&mut alice, &mut bob);
    DmSendData {
        alice,
        bob_jid: bob.jid,
        msg: text_msg(),
    }
}

struct DmRecvData {
    bob: User,
    alice_addr: ProtocolAddress,
    ciphertext: Vec<u8>,
    enc_type: String,
}

fn setup_dm_recv() -> DmRecvData {
    let mut alice = User::new("5511999000001", "s.whatsapp.net");
    let mut bob = User::new("5511999000002", "s.whatsapp.net");
    establish_bidirectional(&mut alice, &mut bob);

    // Encrypt a message (subsequent, not PreKey — realistic steady-state)
    let (ciphertext, enc_type) = futures::executor::block_on(async {
        let ct = message_encrypt(
            &MessageUtils::pad_message_v2(text_msg().encode_to_vec()),
            &bob.address,
            &mut alice.sessions,
            &mut alice.identity,
        )
        .await
        .unwrap();

        match ct {
            CiphertextMessage::SignalMessage(msg) => (msg.serialized().to_vec(), "msg".to_string()),
            CiphertextMessage::PreKeySignalMessage(msg) => {
                (msg.serialized().to_vec(), "pkmsg".to_string())
            }
            _ => panic!("unexpected type"),
        }
    });

    DmRecvData {
        bob,
        alice_addr: alice.address,
        ciphertext,
        enc_type,
    }
}

// ---------------------------------------------------------------------------
// Group setups
// ---------------------------------------------------------------------------

struct GrpSendData {
    alice: User,
    group_jid: Jid,
    participants: Vec<Jid>,
    force_skdm: bool,
    resolver: MockResolver,
    msg: wa::Message,
}

fn setup_group_send(n: usize) -> GrpSendData {
    let mut alice = User::new("100000000000001", "lid");
    let group_jid: Jid = "120363000000000001@g.us".parse().unwrap();

    let mut participants = Vec::with_capacity(n);
    let mut devices = Vec::with_capacity(n);

    for i in 0..n {
        let member = User::new(&format!("{}", 100000000000100u64 + i as u64), "lid");
        establish_session(&mut alice, &member);
        participants.push(member.jid.clone());
        devices.push(member.jid);
    }

    let sk_name = make_sender_key_name(&group_jid, &alice.address);
    futures::executor::block_on(async {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        create_sender_key_distribution_message(&sk_name, &mut alice.sender_keys, &mut rng)
            .await
            .unwrap();
    });

    GrpSendData {
        alice,
        group_jid,
        participants,
        force_skdm: false,
        resolver: MockResolver(devices),
        msg: text_msg(),
    }
}

fn setup_group_send_10() -> GrpSendData {
    setup_group_send(10)
}
fn setup_group_send_50() -> GrpSendData {
    setup_group_send(50)
}
fn setup_group_send_256() -> GrpSendData {
    setup_group_send(256)
}

// First-message path: force_skdm=true exercises N pairwise encryptions
fn setup_group_skdm_10() -> GrpSendData {
    let mut d = setup_group_send(10);
    d.force_skdm = true;
    d
}
fn setup_group_skdm_50() -> GrpSendData {
    let mut d = setup_group_send(50);
    d.force_skdm = true;
    d
}
fn setup_group_skdm_256() -> GrpSendData {
    let mut d = setup_group_send(256);
    d.force_skdm = true;
    d
}

struct GrpRecvData {
    bob: User,
    alice_addr: ProtocolAddress,
    group_jid: Jid,
    skmsg_bytes: Vec<u8>,
}

fn setup_group_recv() -> GrpRecvData {
    let mut alice = User::new("100000000000001", "lid");
    let mut bob = User::new("100000000000002", "lid");
    let group_jid: Jid = "120363000000000001@g.us".parse().unwrap();

    establish_session(&mut alice, &bob);

    // Alice creates sender key and distributes SKDM to Bob
    let sk_name = make_sender_key_name(&group_jid, &alice.address);
    futures::executor::block_on(async {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let skdm =
            create_sender_key_distribution_message(&sk_name, &mut alice.sender_keys, &mut rng)
                .await
                .unwrap();

        process_sender_key_distribution_message(&sk_name, &skdm, &mut bob.sender_keys)
            .await
            .unwrap();
    });

    // Build a full group stanza, then extract just the skmsg bytes
    // (server strips <participants> before forwarding to recipients)
    let resolver = MockResolver(vec![bob.jid.clone()]);
    let own_jid = alice.jid.clone();
    let mut group_info =
        GroupInfo::new(vec![bob.jid.clone(), alice.jid.clone()], AddressingMode::Pn);

    let mut stores = SignalStores {
        sender_key_store: &mut alice.sender_keys,
        session_store: &mut alice.sessions,
        identity_store: &mut alice.identity,
        prekey_store: &mut alice.prekeys,
        signed_prekey_store: &alice.signed_prekeys,
    };

    let result = futures::executor::block_on(prepare_group_stanza(
        &mut stores,
        &resolver,
        &mut group_info,
        &own_jid,
        &own_jid,
        None,
        group_jid.clone(),
        &text_msg(),
        "bench-grp-recv".into(),
        false,
        None,
        None,
        &[],
    ))
    .unwrap();

    let skmsg_bytes = extract_skmsg_bytes(&result.node);

    GrpRecvData {
        bob,
        alice_addr: alice.address,
        group_jid,
        skmsg_bytes,
    }
}

// ===========================================================================
// Benchmarks
// ===========================================================================

#[library_benchmark]
#[bench::text(setup = setup_dm_send)]
fn bench_dm_send(mut d: DmSendData) {
    let node = futures::executor::block_on(prepare_peer_stanza(
        &mut d.alice.sessions,
        &mut d.alice.identity,
        d.bob_jid.clone(),
        d.bob_jid,
        &d.msg,
        "b-001".into(),
    ))
    .unwrap();
    black_box(marshal(&node).unwrap());
}

#[library_benchmark]
#[bench::text(setup = setup_dm_recv)]
fn bench_dm_recv(mut d: DmRecvData) {
    black_box(decrypt_dm(
        &d.ciphertext,
        &d.enc_type,
        &d.alice_addr,
        &mut d.bob,
    ));
}

fn run_group_send(d: &mut GrpSendData) {
    let own_jid = d.alice.jid.clone();
    let mut group_info = GroupInfo::new(std::mem::take(&mut d.participants), AddressingMode::Pn);
    let mut stores = SignalStores {
        sender_key_store: &mut d.alice.sender_keys,
        session_store: &mut d.alice.sessions,
        identity_store: &mut d.alice.identity,
        prekey_store: &mut d.alice.prekeys,
        signed_prekey_store: &d.alice.signed_prekeys,
    };

    let result = futures::executor::block_on(prepare_group_stanza(
        &mut stores,
        &d.resolver,
        &mut group_info,
        &own_jid,
        &own_jid,
        None,
        d.group_jid.clone(),
        &d.msg,
        "b-grp".into(),
        d.force_skdm,
        None,
        None,
        &[],
    ))
    .unwrap();

    black_box(marshal(&result.node).unwrap());
}

// Steady-state group send (skmsg only, no SKDM distribution)
#[library_benchmark]
#[bench::group_10(setup = setup_group_send_10)]
#[bench::group_50(setup = setup_group_send_50)]
#[bench::group_256(setup = setup_group_send_256)]
fn bench_group_send(mut d: GrpSendData) {
    run_group_send(&mut d);
}

// First-message group send: forces SKDM distribution with N pairwise encryptions
#[library_benchmark]
#[bench::skdm_10(setup = setup_group_skdm_10)]
#[bench::skdm_50(setup = setup_group_skdm_50)]
#[bench::skdm_256(setup = setup_group_skdm_256)]
fn bench_group_send_skdm(mut d: GrpSendData) {
    run_group_send(&mut d);
}

#[library_benchmark]
#[bench::text(setup = setup_group_recv)]
fn bench_group_recv(mut d: GrpRecvData) {
    black_box(decrypt_group(
        &d.skmsg_bytes,
        &d.alice_addr,
        &d.group_jid,
        &mut d.bob,
    ));
}

library_benchmark_group!(name = dm_send; benchmarks = bench_dm_send);
library_benchmark_group!(name = dm_recv; benchmarks = bench_dm_recv);
library_benchmark_group!(name = group_send; benchmarks = bench_group_send);
library_benchmark_group!(name = group_send_skdm; benchmarks = bench_group_send_skdm);
library_benchmark_group!(name = group_recv; benchmarks = bench_group_recv);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups = dm_send, dm_recv, group_send, group_send_skdm, group_recv
);
