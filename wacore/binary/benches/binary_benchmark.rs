use flate2::Compression;
use flate2::write::ZlibEncoder;
use iai_callgrind::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use std::hint::black_box;
use std::io::Write;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::marshal::{
    marshal, marshal_auto, marshal_exact, marshal_ref, marshal_ref_auto, marshal_ref_exact,
    marshal_to, marshal_to_vec, unmarshal_ref,
};
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

// Creates a node with long string content to test the JID parsing optimization.
// Long strings (> 48 chars) should skip JID parsing for better performance.
fn create_long_string_node() -> Node {
    // Generate a 500+ character string that contains '@' but is NOT a valid JID.
    // Without the optimization, parse_jid would scan the entire string.
    let base_pattern = "Lorem ipsum with email user@example.com in text. ";
    let long_text = base_pattern.repeat(11); // ~550 characters

    NodeBuilder::new("message")
        .attr("to", "1234567890@s.whatsapp.net")
        .attr("id", "ABC123DEF456")
        .attr("type", "text")
        .string_content(long_text)
        .build()
}

/// Creates a node structure that simulates a usync response with many children
/// for testing child iteration performance.
fn create_usync_like_node() -> Node {
    NodeBuilder::new("iq")
        .attr("type", "result")
        .children(vec![
            NodeBuilder::new("usync")
                .children(vec![
                    NodeBuilder::new("list")
                        .children((0..50).map(|i| {
                            NodeBuilder::new("user")
                                .attr("jid", format!("{}@s.whatsapp.net", i))
                                .children(vec![
                                    NodeBuilder::new("devices")
                                        .children(vec![
                                            NodeBuilder::new("device-list")
                                                .children((0..3).map(|d| {
                                                    NodeBuilder::new("device")
                                                        .attr("id", d.to_string())
                                                        .build()
                                                }))
                                                .build(),
                                        ])
                                        .build(),
                                    NodeBuilder::new("contact").attr("type", "in").build(),
                                ])
                                .build()
                        }))
                        .build(),
                ])
                .build(),
        ])
        .build()
}
// Creates a node with multiple JID attributes to benchmark JID handling.
// When marshaled, these strings are encoded as JID tokens (JID_PAIR or AD_JID).
// The optimization avoids stringify→parse roundtrip when converting NodeRef→Node.
fn create_jid_heavy_node() -> Node {
    NodeBuilder::new("message")
        .attr("from", "15551234567@s.whatsapp.net")
        .attr("to", "15559876543@s.whatsapp.net")
        .attr("participant", "15555555555@s.whatsapp.net")
        .attr("recipient", "15556666666@s.whatsapp.net")
        .attr("notify", "15557777777@s.whatsapp.net")
        .attr("id", "ABCDEF123456")
        .attr("type", "text")
        .build()
}

fn create_huge_bytes_node() -> Node {
    NodeBuilder::new("message")
        .attr("to", "server@s.whatsapp.net")
        .attr("id", "huge-binary")
        .bytes(vec![0x5A; 256 * 1024])
        .build()
}

fn create_many_children_node() -> Node {
    NodeBuilder::new("iq")
        .attr("to", "server@s.whatsapp.net")
        .attr("id", "many-children")
        .children((0..2048).map(|i| {
            NodeBuilder::new("item")
                .attr("index", i.to_string())
                .attr("type", "entry")
                .string_content("ok")
                .build()
        }))
        .build()
}

// Marshal benchmarks - self-contained, no setup needed
#[library_benchmark]
fn bench_marshal_allocating() -> Vec<u8> {
    let node = create_large_node();
    black_box(marshal(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_auto_allocating() -> Vec<u8> {
    let node = create_large_node();
    black_box(marshal_auto(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_exact_allocating() -> Vec<u8> {
    let node = create_large_node();
    black_box(marshal_exact(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_reusing_buffer() -> Vec<u8> {
    let node = create_large_node();
    let mut buffer = Vec::with_capacity(4096);
    marshal_to(black_box(&node), &mut buffer).unwrap();
    black_box(buffer)
}

#[library_benchmark]
fn bench_marshal_reusing_buffer_vec_writer() -> Vec<u8> {
    let node = create_large_node();
    let mut buffer = Vec::with_capacity(4096);
    marshal_to_vec(black_box(&node), &mut buffer).unwrap();
    black_box(buffer)
}

// Benchmark for marshaling nodes with long string content.
// This demonstrates the JID parsing optimization: long strings skip parse_jid.
#[library_benchmark]
fn bench_marshal_long_string() -> Vec<u8> {
    let node = create_long_string_node();
    black_box(marshal(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_auto_long_string() -> Vec<u8> {
    let node = create_long_string_node();
    black_box(marshal_auto(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_exact_long_string() -> Vec<u8> {
    let node = create_long_string_node();
    black_box(marshal_exact(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_huge_bytes_allocating() -> Vec<u8> {
    let node = create_huge_bytes_node();
    black_box(marshal(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_auto_huge_bytes_allocating() -> Vec<u8> {
    let node = create_huge_bytes_node();
    black_box(marshal_auto(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_exact_huge_bytes_allocating() -> Vec<u8> {
    let node = create_huge_bytes_node();
    black_box(marshal_exact(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_many_children_allocating() -> Vec<u8> {
    let node = create_many_children_node();
    black_box(marshal(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_auto_many_children_allocating() -> Vec<u8> {
    let node = create_many_children_node();
    black_box(marshal_auto(black_box(&node)).unwrap())
}

#[library_benchmark]
fn bench_marshal_exact_many_children_allocating() -> Vec<u8> {
    let node = create_many_children_node();
    black_box(marshal_exact(black_box(&node)).unwrap())
}

// Setup functions for unmarshal benchmarks - pre-compute marshaled data
// Note: marshal() adds a flag byte at position 0, unmarshal_ref expects data without it
fn setup_small_marshaled() -> Vec<u8> {
    marshal(&create_small_node()).unwrap()
}

fn setup_large_marshaled() -> Vec<u8> {
    marshal(&create_large_node()).unwrap()
}

#[library_benchmark]
#[bench::small(setup = setup_small_marshaled)]
#[bench::large(setup = setup_large_marshaled)]
fn bench_unmarshal(marshaled: Vec<u8>) {
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

// Setup function for attr_parser benchmark - pre-compute marshaled data
fn setup_attr_marshaled() -> Vec<u8> {
    marshal(&create_attr_node()).unwrap()
}

#[library_benchmark]
#[bench::attr_lookup(setup = setup_attr_marshaled)]
fn bench_attr_parser(marshaled: Vec<u8>) {
    // Skip the flag byte at position 0
    let node_ref = unmarshal_ref(&marshaled[1..]).unwrap();

    let mut parser = node_ref.attr_parser();
    black_box(parser.optional_string("xmlns"));
    black_box(parser.optional_string("type"));
    black_box(parser.optional_jid("from"));
    black_box(parser.optional_bool("has_flag"));
    black_box(parser.optional_u64("timestamp"));
    black_box(parser.finish().is_ok());
}

// Round-trip benchmark: unmarshal to NodeRef and re-marshal using the borrowed path.
// This tests the zero-copy encoding path with EncodeNode trait.
#[library_benchmark]
#[bench::small(setup = setup_small_marshaled)]
#[bench::large(setup = setup_large_marshaled)]
fn bench_roundtrip(marshaled: Vec<u8>) -> Vec<u8> {
    // Skip the flag byte at position 0
    let node_ref = unmarshal_ref(black_box(&marshaled[1..])).unwrap();
    black_box(marshal_ref(&node_ref).unwrap())
}

#[library_benchmark]
#[bench::small(setup = setup_small_marshaled)]
#[bench::large(setup = setup_large_marshaled)]
fn bench_roundtrip_auto(marshaled: Vec<u8>) -> Vec<u8> {
    // Skip the flag byte at position 0
    let node_ref = unmarshal_ref(black_box(&marshaled[1..])).unwrap();
    black_box(marshal_ref_auto(&node_ref).unwrap())
}

#[library_benchmark]
#[bench::small(setup = setup_small_marshaled)]
#[bench::large(setup = setup_large_marshaled)]
fn bench_roundtrip_exact(marshaled: Vec<u8>) -> Vec<u8> {
    // Skip the flag byte at position 0
    let node_ref = unmarshal_ref(black_box(&marshaled[1..])).unwrap();
    black_box(marshal_ref_exact(&node_ref).unwrap())
}

// Child iteration benchmark: tests get_children_by_tag performance
// Simulates the recursive traversal pattern used in usync parsing
#[library_benchmark]
fn bench_get_children_by_tag() {
    let node = create_usync_like_node();

    // Get the list node containing user children
    let usync = node.get_optional_child("usync").unwrap();
    let list = usync.get_optional_child("list").unwrap();

    // Iterate over all "user" children (simulates usync parsing)
    let mut count = 0;
    for user in black_box(list.get_children_by_tag("user")) {
        // For each user, get their device children (nested iteration)
        if let Some(devices) = user.get_optional_child("devices")
            && let Some(device_list) = devices.get_optional_child("device-list")
        {
            for _device in black_box(device_list.get_children_by_tag("device")) {
                count += 1;
            }
        }
    }
    black_box(count);
}

library_benchmark_group!(
    name = marshal_group;
    benchmarks =
        bench_marshal_allocating,
        bench_marshal_auto_allocating,
        bench_marshal_exact_allocating,
        bench_marshal_reusing_buffer,
        bench_marshal_reusing_buffer_vec_writer,
        bench_marshal_long_string,
        bench_marshal_auto_long_string,
        bench_marshal_exact_long_string,
        bench_marshal_huge_bytes_allocating,
        bench_marshal_auto_huge_bytes_allocating,
        bench_marshal_exact_huge_bytes_allocating,
        bench_marshal_many_children_allocating,
        bench_marshal_auto_many_children_allocating,
        bench_marshal_exact_many_children_allocating
);

library_benchmark_group!(
    name = unmarshal_group;
    benchmarks = bench_unmarshal
);

library_benchmark_group!(
    name = unpack_group;
    benchmarks = bench_unpack_uncompressed, bench_unpack_compressed
);

library_benchmark_group!(
    name = attr_parser_group;
    benchmarks = bench_attr_parser
);

library_benchmark_group!(
    name = roundtrip_group;
    benchmarks = bench_roundtrip, bench_roundtrip_auto, bench_roundtrip_exact
);

library_benchmark_group!(
    name = child_iteration_group;
    benchmarks = bench_get_children_by_tag
);

// Setup function for JID optimization benchmark - pre-compute marshaled JID-heavy data
fn setup_jid_heavy_marshaled() -> Vec<u8> {
    marshal(&create_jid_heavy_node()).unwrap()
}

// Benchmark that measures the JID attribute optimization.
// This tests the flow: unmarshal → to_owned() → access JIDs via AttrParser
//
// The optimization benefit:
// - Before: JID decoded → stringified in to_owned() → re-parsed in optional_jid()
// - After: JID decoded → preserved as Jid in to_owned() → cloned in optional_jid()
#[library_benchmark]
#[bench::jid_access(setup = setup_jid_heavy_marshaled)]
fn bench_jid_to_owned_access(marshaled: Vec<u8>) {
    // Skip the flag byte at position 0
    let node_ref = unmarshal_ref(&marshaled[1..]).unwrap();

    // Convert to owned Node - this is where JIDs are preserved (optimization)
    let node = node_ref.to_owned();

    // Access JID attributes via AttrParser - if JIDs are preserved, no parsing needed
    let mut parser = node.attrs();
    black_box(parser.optional_jid("from"));
    black_box(parser.optional_jid("to"));
    black_box(parser.optional_jid("participant"));
    black_box(parser.optional_jid("recipient"));
    black_box(parser.optional_jid("notify"));
    black_box(parser.optional_string("id"));
    black_box(parser.optional_string("type"));
}

library_benchmark_group!(
    name = jid_optimization_group;
    benchmarks = bench_jid_to_owned_access
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups =
        marshal_group,
        unmarshal_group,
        unpack_group,
        attr_parser_group,
        roundtrip_group,
        child_iteration_group,
        jid_optimization_group
);
