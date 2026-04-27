//! Test fixtures shared between this crate's unit tests and downstream
//! integration tests. Visible only under `#[cfg(test)]` (this crate) or
//! when the `test-util` feature is enabled.

use prost::Message;
use waproto::whatsapp::{self as wa, cert_chain::noise_certificate};

/// Builds a minimal `CertChain` blob whose leaf.key matches `server_static_pub`.
///
/// The validity windows are pinned (`not_before = 1_700_000_000` for both
/// certs, `not_after` slightly under `1_900_000_000`) so callers can exercise
/// `select_pattern`'s clock checks against deterministic boundaries.
///
/// Signatures are zero-filled — the client today does NOT verify the
/// intermediate's Ed25519 signature against `WA_CERT_PUB_KEY`, so the bytes
/// only need to round-trip through prost.
pub fn build_cert_chain_bytes(server_static_pub: &[u8; 32]) -> Vec<u8> {
    let intermediate_details = noise_certificate::Details {
        serial: Some(1),
        issuer_serial: Some(0),
        key: Some(vec![0xCC; 32]),
        not_before: Some(1_700_000_000),
        not_after: Some(1_900_000_000),
    };
    let mut intermediate_details_bytes = Vec::new();
    intermediate_details
        .encode(&mut intermediate_details_bytes)
        .expect("encode intermediate details");

    let leaf_details = noise_certificate::Details {
        serial: Some(2),
        issuer_serial: Some(1),
        key: Some(server_static_pub.to_vec()),
        not_before: Some(1_700_000_500),
        not_after: Some(1_899_999_500),
    };
    let mut leaf_details_bytes = Vec::new();
    leaf_details
        .encode(&mut leaf_details_bytes)
        .expect("encode leaf details");

    let chain = wa::CertChain {
        leaf: Some(wa::cert_chain::NoiseCertificate {
            details: Some(leaf_details_bytes),
            signature: Some(vec![0u8; 64]),
        }),
        intermediate: Some(wa::cert_chain::NoiseCertificate {
            details: Some(intermediate_details_bytes),
            signature: Some(vec![0u8; 64]),
        }),
    };
    let mut bytes = Vec::new();
    chain.encode(&mut bytes).expect("encode chain");
    bytes
}
