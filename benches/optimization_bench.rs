use criterion::{black_box, criterion_group, criterion_main, Criterion};
use prost::Message;
use whatsapp_rust::skdm_parser::SkdmFields;
use waproto::whatsapp as wa;

fn benchmark_skdm_parsing(c: &mut Criterion) {
    // Create test SKDM data
    let test_msg = wa::SenderKeyDistributionMessage {
        id: Some(12345),
        iteration: Some(67890),
        chain_key: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]), // 16 bytes
        signing_key: Some(vec![0; 32]), // 32 bytes
    };
    let encoded = test_msg.encode_to_vec();

    let mut group = c.benchmark_group("skdm_parsing");
    
    group.bench_function("prost_decode", |b| {
        b.iter(|| {
            let decoded = wa::SenderKeyDistributionMessage::decode(black_box(&encoded[..])).unwrap();
            black_box((decoded.id, decoded.iteration, decoded.chain_key, decoded.signing_key));
        })
    });

    group.bench_function("zero_copy_parse", |b| {
        b.iter(|| {
            let parsed = SkdmFields::parse_zero_copy(black_box(&encoded)).unwrap();
            black_box((parsed.id, parsed.iteration, parsed.chain_key, parsed.signing_key));
        })
    });

    group.finish();
}

fn benchmark_node_allocation(c: &mut Criterion) {
    use smallvec::SmallVec;
    
    let mut group = c.benchmark_group("node_allocation");
    
    // Benchmark small Vec allocation vs SmallVec
    group.bench_function("vec_4_items", |b| {
        b.iter(|| {
            let mut v: Vec<u32> = Vec::with_capacity(4);
            for i in 0..4 {
                v.push(black_box(i));
            }
            black_box(v);
        })
    });

    group.bench_function("smallvec_4_items", |b| {
        b.iter(|| {
            let mut v: SmallVec<[u32; 4]> = SmallVec::with_capacity(4);
            for i in 0..4 {
                v.push(black_box(i));
            }
            black_box(v);
        })
    });

    group.finish();
}

criterion_group!(benches, benchmark_skdm_parsing, benchmark_node_allocation);
criterion_main!(benches);