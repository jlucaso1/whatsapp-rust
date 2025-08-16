use crate::appstate::keys::ExpandedAppStateKeys;
use crate::appstate::lthash::WA_PATCH_INTEGRITY;
use crate::appstate::processor::{Mutation, ProcessorUtils};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use waproto::whatsapp as wa;

/// Decode a set of snapshot records (already parsed) into mutations using provided keys.
/// Platform agnostic: pure transformation + cryptographic verification.
pub fn decode_snapshot_records(
    keys: &ExpandedAppStateKeys,
    records: Vec<wa::SyncdRecord>,
) -> Vec<Mutation> {
    let mut mutations: Vec<Mutation> = Vec::new();
    for rec in records.into_iter() {
        let fake = wa::SyncdMutation {
            operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
            record: Some(rec),
        };
        if let Err(e) = ProcessorUtils::decode_mutation(keys, &fake, &mut mutations) {
            log::warn!(target: "AppStateSnapshot", "Failed to decode snapshot record: {e:?}");
        }
    }
    mutations
}

/// Verify snapshot MAC (HMAC-SHA256 over ordered value MACs). Returns true if valid or absent.
pub fn verify_snapshot_mac(
    keys: &ExpandedAppStateKeys,
    server_mac: Option<&[u8]>,
    mutations: &[Mutation],
) -> bool {
    if let Some(expected_server) = server_mac {
        let mut mac = Hmac::<Sha256>::new_from_slice(&keys.snapshot_mac).expect("HMAC");
        for m in mutations {
            mac.update(&m.value_mac);
        }
        let expected = mac.finalize().into_bytes();
        expected.as_slice() == expected_server
    } else {
        true
    }
}

/// Apply decoded snapshot mutations to a hash state: resets version/hash, rebuilds index map and LT hash.
pub fn apply_snapshot_mutations(
    _version: u64,
    mutations: &[Mutation],
    hash: &mut [u8; 128],
    index_value_map: &mut HashMap<String, Vec<u8>>,
) {
    *hash = [0; 128];
    index_value_map.clear();
    let add_refs: Vec<&[u8]> = mutations.iter().map(|m| m.value_mac.as_slice()).collect();
    for m in mutations {
        let idx_b64 = BASE64_STANDARD.encode(&m.index_mac);
        index_value_map.insert(idx_b64, m.value_mac.clone());
    }
    WA_PATCH_INTEGRITY.subtract_then_add_in_place(hash, &[], &add_refs);
}
