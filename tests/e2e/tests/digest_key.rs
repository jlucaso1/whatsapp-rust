//! E2E tests for digest key bundle validation.
//!
//! After connecting (which uploads prekeys to the server), the client
//! can query the server for a digest of its stored key material and
//! verify the SHA-1 hash matches a locally computed one. This catches
//! any divergence between local and server-side key state.

use e2e_tests::TestClient;
use log::info;
use wacore::iq::prekeys::DigestKeyBundleSpec;

/// Verify that the digest key hash from the server matches the locally
/// computed hash over identity key + signed prekey + prekey public keys.
///
/// Regression test for a bug where the digest response parser filtered
/// `<list>` children by tag "key", but the server sends them as `<id>`
/// nodes. This caused all prekey IDs to be silently dropped, producing
/// a hash over only identity + signed prekey data (no prekeys), which
/// never matched the server's hash.
#[tokio::test]
async fn test_digest_key_hash_matches_server() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let tc = TestClient::connect("e2e_digest").await?;
    let jid = tc.jid().await;
    info!("Client JID: {jid}");

    // Query the server for the current key bundle digest
    let response = tc.client.execute(DigestKeyBundleSpec::new()).await?;
    info!(
        "Server digest: reg_id={}, prekey_count={}, hash={}",
        response.reg_id,
        response.prekey_ids.len(),
        hex::encode(&response.hash),
    );

    assert!(
        !response.prekey_ids.is_empty(),
        "Server should report prekey IDs in the digest (was the parser dropping <id> nodes?)"
    );
    assert_eq!(
        response.hash.len(),
        20,
        "Server hash should be 20 bytes (SHA-1)"
    );

    // Load local key material to reproduce the hash
    let pm = tc.client.persistence_manager();
    let device = pm.get_device_snapshot().await;

    assert_eq!(
        response.reg_id, device.registration_id,
        "Registration ID should match"
    );

    let identity_pub = device.identity_key.public_key.public_key_bytes();
    let skey_pub = device.signed_pre_key.public_key.public_key_bytes();
    let skey_sig = &device.signed_pre_key_signature;

    // Load the public key for each prekey the server references
    let backend = pm.backend();
    let mut prekey_pubkeys = Vec::with_capacity(response.prekey_ids.len());
    for prekey_id in &response.prekey_ids {
        let record_bytes = backend.load_prekey(*prekey_id).await?.unwrap_or_else(|| {
            panic!(
                "Local prekey {} referenced by server digest is missing",
                prekey_id
            )
        });

        use prost::Message;
        let record = whatsapp_rust::waproto::whatsapp::PreKeyRecordStructure::decode(
            record_bytes.as_slice(),
        )?;
        let pk = record
            .public_key
            .unwrap_or_else(|| panic!("Prekey {} has no public_key field", prekey_id));
        prekey_pubkeys.push(pk);
    }

    // Compute SHA-1 digest the same way the server does
    let local_hash = wacore::prekeys::compute_key_bundle_digest(
        identity_pub,
        skey_pub,
        skey_sig,
        &prekey_pubkeys,
    );

    assert_eq!(
        local_hash,
        response.hash,
        "Local hash ({}) must match server hash ({})",
        hex::encode(&local_hash),
        hex::encode(&response.hash),
    );

    info!(
        "Digest key validation passed: {} prekeys, hash={}",
        response.prekey_ids.len(),
        hex::encode(&local_hash),
    );

    tc.disconnect().await;
    Ok(())
}
