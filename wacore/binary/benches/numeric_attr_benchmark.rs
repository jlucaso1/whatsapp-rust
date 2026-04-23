use iai_callgrind::{
    Callgrind, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};
use std::hint::black_box;

use compact_str::CompactString;
use wacore_binary::node::NodeValue;

/// Baseline: what the codebase does today — `value.to_string()` then Into<NodeValue>.
/// Heap-allocates a `String`, then `CompactString::from(String)` re-uses or copies.
#[inline(never)]
fn baseline_u32(n: u32) -> NodeValue {
    NodeValue::from(n.to_string())
}

#[inline(never)]
fn baseline_u64(n: u64) -> NodeValue {
    NodeValue::from(n.to_string())
}

#[inline(never)]
fn baseline_i64(n: i64) -> NodeValue {
    NodeValue::from(n.to_string())
}

/// Proposed path: use `itoa` to format into a stack buffer, then `CompactString::from(&str)`
/// which inlines for strings <= 24 bytes on 64-bit (all integers fit).
#[inline(never)]
fn proposed_u32(n: u32) -> NodeValue {
    let mut buf = itoa::Buffer::new();
    NodeValue::String(CompactString::from(buf.format(n)))
}

#[inline(never)]
fn proposed_u64(n: u64) -> NodeValue {
    let mut buf = itoa::Buffer::new();
    NodeValue::String(CompactString::from(buf.format(n)))
}

#[inline(never)]
fn proposed_i64(n: i64) -> NodeValue {
    let mut buf = itoa::Buffer::new();
    NodeValue::String(CompactString::from(buf.format(n)))
}

#[library_benchmark]
fn bench_baseline_u32() -> NodeValue {
    black_box(baseline_u32(black_box(12345)))
}

#[library_benchmark]
fn bench_proposed_u32() -> NodeValue {
    black_box(proposed_u32(black_box(12345)))
}

#[library_benchmark]
fn bench_baseline_u64() -> NodeValue {
    black_box(baseline_u64(black_box(1234567890123u64)))
}

#[library_benchmark]
fn bench_proposed_u64() -> NodeValue {
    black_box(proposed_u64(black_box(1234567890123u64)))
}

#[library_benchmark]
fn bench_baseline_i64() -> NodeValue {
    black_box(baseline_i64(black_box(-1234567890123i64)))
}

#[library_benchmark]
fn bench_proposed_i64() -> NodeValue {
    black_box(proposed_i64(black_box(-1234567890123i64)))
}

#[library_benchmark]
fn bench_baseline_loop_100_u64() -> u64 {
    let mut acc: u64 = 0;
    for i in 0u64..100 {
        let v = baseline_u64(black_box(100_000 + i));
        acc = acc.wrapping_add(v.as_str().len() as u64);
    }
    black_box(acc)
}

#[library_benchmark]
fn bench_proposed_loop_100_u64() -> u64 {
    let mut acc: u64 = 0;
    for i in 0u64..100 {
        let v = proposed_u64(black_box(100_000 + i));
        acc = acc.wrapping_add(v.as_str().len() as u64);
    }
    black_box(acc)
}

library_benchmark_group!(
    name = bench_group;
    benchmarks =
        bench_baseline_u32,
        bench_proposed_u32,
        bench_baseline_u64,
        bench_proposed_u64,
        bench_baseline_i64,
        bench_proposed_i64,
        bench_baseline_loop_100_u64,
        bench_proposed_loop_100_u64,
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default());
    library_benchmark_groups = bench_group
);
