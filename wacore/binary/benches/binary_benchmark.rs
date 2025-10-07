use criterion::{Criterion, criterion_group, criterion_main};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::hint::black_box;
use std::io::Write;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::marshal::{marshal, unmarshal_ref};
use wacore_binary::node::{Node, NodeRef};
use wacore_binary::util::unpack;

fn create_small_node() -> Node {
    NodeBuilder::new("message")
        .attr("to", "user@s.whatsapp.net")
        .attr("id", "12345")
        .attr("type", "text")
        .build()
}

fn create_large_node() -> Node {
    NodeBuilder::new("iq")
        .attr("to", "server@s.whatsapp.net")
        .attr("id", "abcdef")
        .attr("type", "get")
        .attr("xmlns", "usync")
        .children(vec![
            NodeBuilder::new("usync")
                .attr("sid", "message:1")
                .attr("mode", "query")
                .attr("last", "true")
                .children(vec![
                    NodeBuilder::new("query")
                        .children(vec![NodeBuilder::new("business").build()])
                        .build(),
                ])
                .build(),
            NodeBuilder::new("list")
                .children((0..20).map(|i| {
                    NodeBuilder::new("item")
                        .attr("index", i.to_string())
                        .bytes(vec![i as u8; 32])
                        .build()
                }))
                .build(),
        ])
        .build()
}

fn benchmark_marshal(c: &mut Criterion) {
    let large_node = create_large_node();

    let mut group = c.benchmark_group("marshal_api");

    group.bench_function("marshal (allocating)", |b| {
        b.iter(|| {
            let _ = marshal(black_box(&large_node));
        })
    });

    group.bench_function("marshal_to (reusing_buffer)", |b| {
        let mut buffer = Vec::with_capacity(4096);
        b.iter(|| {
            buffer.clear();
            wacore_binary::marshal::marshal_to(black_box(&large_node), &mut buffer).unwrap();
        })
    });

    group.finish();
}

fn benchmark_unmarshal(c: &mut Criterion) {
    let small_node = create_small_node();
    let marshaled_small = marshal(&small_node).unwrap();

    let large_node = create_large_node();
    let marshaled_large = marshal(&large_node).unwrap();

    let mut group = c.benchmark_group("unmarshal_ref");

    group.bench_function("small_node", |b| {
        b.iter(|| unmarshal_ref(black_box(&marshaled_small)))
    });

    group.bench_function("large_node", |b| {
        b.iter(|| unmarshal_ref(black_box(&marshaled_large)))
    });

    group.finish();
}

fn benchmark_unpack(c: &mut Criterion) {
    let data = b"some random uncompressed data for testing";

    let mut uncompressed_payload = vec![0];
    uncompressed_payload.extend_from_slice(data);

    let mut compressed_payload = vec![2];
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    let compressed_data = encoder.finish().unwrap();
    compressed_payload.extend_from_slice(&compressed_data);

    let mut group = c.benchmark_group("unpack");

    group.bench_function("uncompressed", |b| {
        b.iter(|| unpack(black_box(&uncompressed_payload)))
    });

    group.bench_function("compressed", |b| {
        b.iter(|| unpack(black_box(&compressed_payload)))
    });

    group.finish();
}

fn benchmark_attr_parser_ref(c: &mut Criterion) {
    let attr_node = NodeBuilder::new("iq")
        .attr("xmlns", "test:ns")
        .attr("type", "result")
        .attr("id", "abc123")
        .attr("from", "server@s.whatsapp.net")
        .attr("has_flag", "true")
        .attr("timestamp", "1700000000")
        .build();

    let marshaled = marshal(&attr_node).expect("marshal attr node");
    let leaked: &'static mut [u8] = Box::leak(marshaled.into_boxed_slice());
    let attr_payload: &'static [u8] = &leaked[1..];
    let node_ref: NodeRef<'static> = unmarshal_ref(attr_payload).expect("unmarshal attr node");

    let mut group = c.benchmark_group("attr_parser_ref");

    group.bench_function("attribute_lookup", |b| {
        b.iter(|| {
            let mut parser = node_ref.attr_parser();
            black_box(parser.string("xmlns"));
            black_box(parser.optional_string("type"));
            black_box(parser.optional_jid("from"));
            black_box(parser.bool("has_flag"));
            black_box(parser.optional_u64("timestamp"));
            black_box(parser.finish().is_ok());
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_marshal,
    benchmark_unmarshal,
    benchmark_unpack,
    benchmark_attr_parser_ref
);
criterion_main!(benches);
