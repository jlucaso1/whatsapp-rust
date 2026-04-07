use iai_callgrind::{
    Callgrind, FlamegraphConfig, LibraryBenchmarkConfig, library_benchmark,
    library_benchmark_group, main,
};
use std::hint::black_box;
use wacore::types::jid::JidExt;
use wacore_binary::jid::Jid;

// --- Realistic device JID lists ---

fn make_device_jids(count: usize) -> Vec<Jid> {
    let mut jids = Vec::with_capacity(count);
    for i in 0..count {
        if i % 3 == 0 {
            jids.push(Jid {
                user: format!("5511999{:06}", i),
                server: "s.whatsapp.net".into(),
                device: (i % 4) as u16,
                agent: 0,
                integrator: 0,
            });
        } else {
            jids.push(Jid {
                user: format!("{}", 100000000000000u64 + i as u64),
                server: "lid".into(),
                device: (i % 5) as u16,
                agent: 0,
                integrator: 0,
            });
        }
    }
    jids
}

fn setup_dm() -> Vec<Jid> {
    make_device_jids(3)
}
fn setup_small_group() -> Vec<Jid> {
    make_device_jids(15)
}
fn setup_medium_group() -> Vec<Jid> {
    make_device_jids(50)
}
fn setup_large_group() -> Vec<Jid> {
    make_device_jids(256)
}
fn setup_max_group() -> Vec<Jid> {
    make_device_jids(768)
}

// ============================================================
// Approach A: Current — Vec<ProtocolAddress>, sort by Ord
// ============================================================

#[library_benchmark]
#[bench::dm(setup = setup_dm)]
#[bench::small_group(setup = setup_small_group)]
#[bench::medium_group(setup = setup_medium_group)]
#[bench::large_group(setup = setup_large_group)]
#[bench::max_group(setup = setup_max_group)]
fn current_protocol_address(jids: Vec<Jid>) {
    let mut keys: Vec<_> = jids.iter().map(|j| j.to_protocol_address()).collect();
    keys.sort_unstable();
    keys.dedup();
    for k in &keys {
        black_box(k.as_str());
    }
}

// ============================================================
// Approach B: Proposed — Vec<Jid>, sort by fields, reusable buffer
// ============================================================

use wacore::types::jid::{cmp_for_lock_order, write_protocol_address_to};

#[library_benchmark]
#[bench::dm(setup = setup_dm)]
#[bench::small_group(setup = setup_small_group)]
#[bench::medium_group(setup = setup_medium_group)]
#[bench::large_group(setup = setup_large_group)]
#[bench::max_group(setup = setup_max_group)]
fn proposed_jid_fields(jids: Vec<Jid>) {
    let mut keys: Vec<Jid> = jids;
    keys.sort_unstable_by(cmp_for_lock_order);
    keys.dedup();
    let mut buf = String::with_capacity(64);
    for k in &keys {
        write_protocol_address_to(k, &mut buf);
        black_box(buf.as_str());
    }
}

library_benchmark_group!(
    name = current_group;
    benchmarks = current_protocol_address
);

library_benchmark_group!(
    name = proposed_group;
    benchmarks = proposed_jid_fields
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().flamegraph(FlamegraphConfig::default()));
    library_benchmark_groups = current_group, proposed_group
);
