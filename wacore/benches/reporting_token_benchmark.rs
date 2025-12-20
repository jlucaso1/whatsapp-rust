use criterion::{Criterion, black_box, criterion_group, criterion_main};
use prost::Message;
use wacore::reporting_token::{
    MESSAGE_SECRET_SIZE, REPORTING_TOKEN_KEY_SIZE, calculate_reporting_token,
    derive_reporting_token_key, generate_reporting_token, generate_reporting_token_content,
};
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

fn create_simple_message() -> wa::Message {
    wa::Message {
        conversation: Some("Hello, World!".to_string()),
        ..Default::default()
    }
}

fn create_extended_message() -> wa::Message {
    wa::Message {
        extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
            text: Some("Test message with context info".to_string()),
            context_info: Some(Box::new(wa::ContextInfo {
                is_forwarded: Some(true),
                forwarding_score: Some(5),
                ..Default::default()
            })),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn create_test_jid(user: &str) -> Jid {
    Jid {
        user: user.to_string(),
        server: "s.whatsapp.net".to_string(),
        device: 0,
        agent: 0,
        integrator: 0,
    }
}

fn bench_content_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_extraction");

    let simple_msg = create_simple_message();
    let extended_msg = create_extended_message();

    group.bench_function("simple_conversation", |b| {
        b.iter(|| generate_reporting_token_content(black_box(&simple_msg)))
    });

    group.bench_function("extended_with_context", |b| {
        b.iter(|| generate_reporting_token_content(black_box(&extended_msg)))
    });

    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");

    let secret = [0x42u8; MESSAGE_SECRET_SIZE];
    let stanza_id = "3EB0E0E5F2D4F618589C0B";
    let sender_jid = "5511999887766@s.whatsapp.net";
    let remote_jid = "5511888776655@s.whatsapp.net";

    group.bench_function("hkdf_derive", |b| {
        b.iter(|| {
            derive_reporting_token_key(
                black_box(&secret),
                black_box(stanza_id),
                black_box(sender_jid),
                black_box(remote_jid),
            )
        })
    });

    group.finish();
}

fn bench_token_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_calculation");

    let key = [0x55u8; REPORTING_TOKEN_KEY_SIZE];
    let content = b"Hello, World! This is test content for HMAC.";

    group.bench_function("hmac_sha256", |b| {
        b.iter(|| calculate_reporting_token(black_box(&key), black_box(content)))
    });

    group.finish();
}

fn bench_full_token_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_generation");

    let simple_msg = create_simple_message();
    let extended_msg = create_extended_message();
    let sender = create_test_jid("sender");
    let remote = create_test_jid("remote");
    let secret = [0xAAu8; MESSAGE_SECRET_SIZE];

    group.bench_function("simple_message", |b| {
        b.iter(|| {
            generate_reporting_token(
                black_box(&simple_msg),
                black_box("STANZA123"),
                black_box(&sender),
                black_box(&remote),
                Some(&secret),
            )
        })
    });

    group.bench_function("extended_message", |b| {
        b.iter(|| {
            generate_reporting_token(
                black_box(&extended_msg),
                black_box("STANZA123"),
                black_box(&sender),
                black_box(&remote),
                Some(&secret),
            )
        })
    });

    group.finish();
}

fn bench_message_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_encoding");

    let simple_msg = create_simple_message();
    let extended_msg = create_extended_message();

    group.bench_function("encode_simple", |b| {
        b.iter(|| black_box(&simple_msg).encode_to_vec())
    });

    group.bench_function("encode_extended", |b| {
        b.iter(|| black_box(&extended_msg).encode_to_vec())
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_content_extraction,
    bench_key_derivation,
    bench_token_calculation,
    bench_full_token_generation,
    bench_message_encoding,
);
criterion_main!(benches);
