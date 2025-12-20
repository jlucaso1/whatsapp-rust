use iai_callgrind::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use prost::Message;
use std::hint::black_box;
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

// Setup functions
fn setup_simple_message() -> wa::Message {
    create_simple_message()
}

fn setup_extended_message() -> wa::Message {
    create_extended_message()
}

// Content extraction benchmarks
#[library_benchmark]
#[bench::simple(setup = setup_simple_message)]
#[bench::extended(setup = setup_extended_message)]
fn bench_content_extraction(msg: wa::Message) {
    black_box(generate_reporting_token_content(black_box(&msg)));
}

// Key derivation benchmark
#[library_benchmark]
fn bench_key_derivation() {
    let secret = [0x42u8; MESSAGE_SECRET_SIZE];
    let stanza_id = "3EB0E0E5F2D4F618589C0B";
    let sender_jid = "5511999887766@s.whatsapp.net";
    let remote_jid = "5511888776655@s.whatsapp.net";

    let _ = black_box(derive_reporting_token_key(
        black_box(&secret),
        black_box(stanza_id),
        black_box(sender_jid),
        black_box(remote_jid),
    ));
}

// Token calculation benchmark
#[library_benchmark]
fn bench_token_calculation() {
    let key = [0x55u8; REPORTING_TOKEN_KEY_SIZE];
    let content = b"Hello, World! This is test content for HMAC.";

    let _ = black_box(calculate_reporting_token(
        black_box(&key),
        black_box(content),
    ));
}

// Full token generation - setup data
struct FullGenSetup {
    msg: wa::Message,
    sender: Jid,
    remote: Jid,
    secret: [u8; MESSAGE_SECRET_SIZE],
}

fn setup_full_gen_simple() -> FullGenSetup {
    FullGenSetup {
        msg: create_simple_message(),
        sender: create_test_jid("sender"),
        remote: create_test_jid("remote"),
        secret: [0xAAu8; MESSAGE_SECRET_SIZE],
    }
}

fn setup_full_gen_extended() -> FullGenSetup {
    FullGenSetup {
        msg: create_extended_message(),
        sender: create_test_jid("sender"),
        remote: create_test_jid("remote"),
        secret: [0xAAu8; MESSAGE_SECRET_SIZE],
    }
}

#[library_benchmark]
#[bench::simple(setup = setup_full_gen_simple)]
#[bench::extended(setup = setup_full_gen_extended)]
fn bench_full_token_generation(data: FullGenSetup) {
    black_box(generate_reporting_token(
        black_box(&data.msg),
        black_box("STANZA123"),
        black_box(&data.sender),
        black_box(&data.remote),
        Some(&data.secret),
    ));
}

// Message encoding benchmarks
#[library_benchmark]
#[bench::simple(setup = setup_simple_message)]
#[bench::extended(setup = setup_extended_message)]
fn bench_message_encoding(msg: wa::Message) -> Vec<u8> {
    black_box(black_box(&msg).encode_to_vec())
}

library_benchmark_group!(
    name = content_extraction_group;
    benchmarks = bench_content_extraction
);

library_benchmark_group!(
    name = key_derivation_group;
    benchmarks = bench_key_derivation
);

library_benchmark_group!(
    name = token_calculation_group;
    benchmarks = bench_token_calculation
);

library_benchmark_group!(
    name = full_generation_group;
    benchmarks = bench_full_token_generation
);

library_benchmark_group!(
    name = message_encoding_group;
    benchmarks = bench_message_encoding
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups =
        content_extraction_group,
        key_derivation_group,
        token_calculation_group,
        full_generation_group,
        message_encoding_group
);
