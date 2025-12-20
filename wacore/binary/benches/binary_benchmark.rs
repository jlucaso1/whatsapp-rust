use flate2::write::ZlibEncoder;
use flate2::Compression;
use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, FlamegraphConfig,
    LibraryBenchmarkConfig,
};
use std::hint::black_box;
use std::io::Write;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::marshal::{marshal, marshal_to, unmarshal_ref};
use wacore_binary::node::Node;
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

fn create_attr_node() -> Node {
    NodeBuilder::new("iq")
        .attr("xmlns", "test:ns")
        .attr("type", "result")
        .attr("id", "abc123")
        .attr("from", "server@s.whatsapp.net")
        .attr("has_flag", "true")
        .attr("timestamp", "1700000000")
        .build()
}

// Marshal benchmarks - self-contained, no setup needed
#[library_benchmark]
fn bench_marshal_allocating() -> Vec<u8> {
    let node = create_large_node();
    black_box(marshal(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_reusing_buffer() {
    let node = create_large_node();
    let mut buffer = Vec::with_capacity(4096);
    marshal_to(black_box(&node), &mut buffer).unwrap();
    black_box(&buffer);
}

// Unmarshal benchmarks - self-contained
// Note: marshal() adds a flag byte at position 0, unmarshal_ref expects data without it
#[library_benchmark]
fn bench_unmarshal_small() {
    let node = create_small_node();
    let marshaled = marshal(&node).unwrap();
    black_box(unmarshal_ref(black_box(&marshaled[1..])).unwrap());
}

#[library_benchmark]
fn bench_unmarshal_large() {
    let node = create_large_node();
    let marshaled = marshal(&node).unwrap();
    black_box(unmarshal_ref(black_box(&marshaled[1..])).unwrap());
}

// Unpack benchmarks - self-contained
#[library_benchmark]
fn bench_unpack_uncompressed() {
    let data = b"some random uncompressed data for testing";
    let mut payload = vec![0u8];
    payload.extend_from_slice(data);
    black_box(unpack(black_box(&payload)).unwrap());
}

#[library_benchmark]
fn bench_unpack_compressed() {
    let data = b"some random uncompressed data for testing";
    let mut payload = vec![2u8];
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    let compressed_data = encoder.finish().unwrap();
    payload.extend_from_slice(&compressed_data);
    black_box(unpack(black_box(&payload)).unwrap());
}

// Attribute parser benchmark - self-contained
#[library_benchmark]
fn bench_attr_parser() {
    let node = create_attr_node();
    let marshaled = marshal(&node).unwrap();
    // Skip the flag byte at position 0
    let node_ref = unmarshal_ref(&marshaled[1..]).unwrap();

    let mut parser = node_ref.attr_parser();
    black_box(parser.string("xmlns"));
    black_box(parser.optional_string("type"));
    black_box(parser.optional_jid("from"));
    black_box(parser.bool("has_flag"));
    black_box(parser.optional_u64("timestamp"));
    black_box(parser.finish().is_ok());
}

library_benchmark_group!(
    name = marshal_group;
    benchmarks = bench_marshal_allocating, bench_marshal_reusing_buffer
);

library_benchmark_group!(
    name = unmarshal_group;
    benchmarks = bench_unmarshal_small, bench_unmarshal_large
);

library_benchmark_group!(
    name = unpack_group;
    benchmarks = bench_unpack_uncompressed, bench_unpack_compressed
);

library_benchmark_group!(
    name = attr_parser_group;
    benchmarks = bench_attr_parser
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups =
        marshal_group,
        unmarshal_group,
        unpack_group,
        attr_parser_group
);
