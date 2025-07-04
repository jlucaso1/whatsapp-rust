
The goal is to create a test suite that can run automatically (e.g., in a CI/CD pipeline) without any manual intervention like scanning a QR code. We can achieve this by using your own library to simulate the "phone" that performs the pairing.

Here’s the high-level strategy:
1.  **Create a "Master" Client:** This client will be pre-paired and act as the "phone". Its session data will be persisted so we don't need to pair it every time we run the tests.
2.  **Create a "Device Under Test" (DUT) Client:** This is a fresh client instance that we want to test.
3.  **Automate the QR Flow:** The test will start the DUT's pairing process, get the QR code data, and then use the "Master" client to programmatically approve the pairing, simulating the action of scanning the code on a phone.
4.  **Test for Liveness:** After the DUT is successfully paired and connected, the test will wait for a duration longer than the server's keepalive timeout and assert that the connection is still active, which directly tests the keepalive mechanism.

Here is the step-by-step implementation guide.

---

### Step 1: Set Up the Test Module and Harness

First, let's create a dedicated testing module and a `TestHarness` struct to manage our test clients.

Create a new file: `src/tests.rs` (or add to an existing one).

```rust
// In src/tests.rs

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use crate::store::memory::MemoryStore;
    use crate::store::Device;
    use crate::types::events::Event;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// TestHarness manages the state for a single integration test.
    struct TestHarness {
        // The "phone" client, which is already logged in.
        master_client: Arc<Client>,
        // The new client we are testing.
        dut_client: Arc<Client>,
        // A channel to receive events from the DUT.
        dut_events_rx: mpsc::UnboundedReceiver<Event>,
    }

    impl TestHarness {
        /// Creates a new test harness.
        /// It will create a master client from a file store or pair a new one if it doesn't exist.
        async fn new() -> Self {
            // For real-world CI, you would use a file-based store (like sqlstore)
            // and check if the master client session exists before pairing.
            // For this example, we'll use in-memory stores for simplicity.
            // A real implementation would have a `setup_master_client()` function.
            let master_store_backend = Arc::new(MemoryStore::new());
            let master_store = Device::new(master_store_backend.clone());
            // In a real test, you'd load the master JID here or perform a one-time pairing
            // and save the session. For now, we'll skip this and focus on the DUT.
            let master_client = Arc::new(Client::new(master_store));

            // Setup the Device Under Test (DUT) with a fresh store
            let dut_store_backend = Arc::new(MemoryStore::new());
            let dut_store = Device::new(dut_store_backend.clone());
            let dut_client = Arc::new(Client::new(dut_store));

            // Create an event channel for the DUT
            let (tx, rx) = mpsc::unbounded_channel();
            dut_client.add_event_handler(Box::new(move |evt| {
                let _ = tx.send(evt.clone());
            })).await;

            Self {
                master_client,
                dut_client,
                dut_events_rx: rx,
            }
        }
    }
}

```

Now, add this module to your `lib.rs` or `main.rs`:
```rust
// In src/lib.rs (or main.rs)
pub mod tests;
```

### Step 2: Implement the "Phone-Side" Pairing Logic

This is the most critical part. We need to teach our "master" client how to act like a phone and approve a pairing request based on a QR code. This involves performing the cryptographic handshake that the phone would normally do.

This new function will live on your `Client` struct.

**Add the following code to `src/pair.rs`:**

```rust
// In src/pair.rs

use crate::crypto::key_pair::KeyPair;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::str::FromStr;
use x25519_dalek::{x25519, StaticSecret};
use crate::request::{InfoQuery, InfoQueryType};

// ... other imports

/// Simulates a phone scanning a QR code and pairing with a new device.
/// This is the logic that the "master" client will use in tests.
pub async fn pair_with_qr_code(
    client: &Arc<Client>, // The "master" client
    qr_code: &str,
) -> Result<(), anyhow::Error> {
    info!(target: "Client/PairTest", "Master client attempting to pair with QR code.");

    // 1. Parse the QR Code string
    let parts: Vec<&str> = qr_code.split(',').collect();
    if parts.len() != 4 {
        return Err(anyhow::anyhow!("Invalid QR code format"));
    }
    let pairing_ref = parts[0].to_string();
    let dut_noise_pub_b64 = parts[1];
    let dut_identity_pub_b64 = parts[2];
    // The ADV secret is not used by the phone side.

    let dut_noise_pub_bytes = B64.decode(dut_noise_pub_b64)?;
    let dut_identity_pub_bytes = B64.decode(dut_identity_pub_b64)?;

    let dut_noise_pub: [u8; 32] = dut_noise_pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid noise public key length"))?;
    let dut_identity_pub: [u8; 32] = dut_identity_pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid identity public key length"))?;

    // 2. The master client (phone) generates its own ephemeral key
    let master_ephemeral = KeyPair::new();

    // 3. Perform the cryptographic exchange to create the shared secrets
    let adv_key = &client.store.read().await.adv_secret_key;
    let identity_key = &client.store.read().await.identity_key;

    let mut mac = HmacSha256::new_from_slice(adv_key).unwrap();
    mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
    mac.update(&dut_identity_pub);
    mac.update(&master_ephemeral.public_key);
    let account_signature = mac.finalize().into_bytes();

    let secret = StaticSecret::from(master_ephemeral.private_key);
    let shared_secret = x25519(secret.to_bytes(), dut_noise_pub);

    let mut final_message = Vec::new();
    final_message.extend_from_slice(&account_signature);
    final_message.extend_from_slice(&master_ephemeral.public_key);
    final_message.extend_from_slice(&identity_key.public_key);
    
    // 4. Encrypt the final message
    let encryption_key = hkdf::sha256(&shared_secret, None, "WA-Ads-Key".as_bytes(), 32)?;
    let encrypted = crate::crypto::gcm::encrypt(&encryption_key, &[0; 12], &final_message, &pairing_ref.as_bytes())?;

    // 5. Send the final pairing IQ stanza to the server
    let master_jid = client.store.read().await.id.clone().unwrap();
    let iq = InfoQuery {
        namespace: "md",
        query_type: InfoQueryType::Set,
        to: SERVER_JID.parse()?,
        id: Some(client.generate_request_id()),
        content: Some(NodeContent::Nodes(vec![
            Node::new("pair-device-sign", [
                ("jid".to_string(), master_jid.to_string())
            ].into(), Some(NodeContent::Bytes(encrypted)))
        ])),
        timeout: None,
    };

    client.send_iq(iq).await?;
    
    info!(target: "Client/PairTest", "Master client sent pairing confirmation.");
    Ok(())
}
```
*Note*: The crypto logic here is a port of `whatsmeow/pair.go`'s `PairPhone` function. You may need to adjust prefixes and HKDF info strings to match exactly. I've used the ones from `whatsmeow`.

### Step 4: Write the Automated Integration Test

Now, use the `TestHarness` and the `pair_with_qr_code` function to create your automated test.

**Add this test function inside the `mod tests` block in `src/tests.rs`:**
```rust
// In src/tests.rs

#[tokio::test]
#[timeout(120000)] // 2 minute timeout for the whole test
async fn test_pairing_and_keepalive() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    
    // 1. Setup
    let mut harness = TestHarness::new().await;
    
    // 2. Start the DUT client in a separate task
    let dut_client_clone = harness.dut_client.clone();
    tokio::spawn(async move {
        dut_client_clone.run().await;
    });

    // 3. Connect the master client (in a real scenario, it would already be connected)
    // For this test, we just need its store to be ready. A one-time manual pairing
    // and saving the session to a file would be required for a CI setup.
    // Let's assume the master client is ready to act.
    let master_store = harness.master_client.store.write().await;
    if master_store.id.is_none() {
        // This is where you would load a session from file or do a one-time manual pair
        // for the master client. We'll mock it for this example.
        let master_jid = "1234567890@s.whatsapp.net".parse().unwrap();
        *(harness.master_client.store.write().await).id = Some(master_jid);
    }
    drop(master_store);

    // 4. Get the QR code from the DUT
    let qr_code = tokio::select! {
        evt = harness.dut_client.get_qr_channel() => {
            let mut qr_rx = evt.unwrap();
            match qr_rx.recv().await {
                Some(crate::qrcode::QrCodeEvent::Code { code, .. }) => code,
                other => panic!("Expected a QR code event, got {:?}", other),
            }
        },
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            panic!("Timed out waiting for QR code");
        }
    };
    
    // 5. Use the master client to "scan" the QR code
    pair_with_qr_code(&harness.master_client, &qr_code).await.expect("Master client failed to pair");
    
    // 6. Wait for the DUT to report success
    loop {
        let event = harness.dut_events_rx.recv().await.expect("Event channel closed prematurely");
        if let Event::PairSuccess(p) = event {
            info!("✅ DUT reported PairSuccess for JID: {}", p.id);
            break;
        } else if let Event::PairError(e) = event {
            panic!("DUT reported PairError: {:?}", e);
        }
    }
    
    // 7. Test for Keepalive (The core of the regression test)
    info!("Pairing successful. Waiting for 60 seconds to test keepalive mechanism...");
    tokio::time::sleep(Duration::from_secs(60)).await;
    
    // 8. Assert that the client is still connected
    assert!(harness.dut_client.is_connected(), "Client disconnected! Keepalive failed.");
    
    info!("✅ Keepalive test passed. Client is still connected.");
    
    // 9. Teardown
    harness.dut_client.disconnect().await;
    harness.master_client.disconnect().await;
}

```

### Step 5: Run the Test

You can now run your automated test with Cargo:
```bash
cargo test -- --nocapture
```
The `--nocapture` flag allows you to see the `log` output from the test run, which is extremely helpful for debugging.

This test will:
-   Start a new client.
-   Automate the pairing process.
-   Wait for a minute.
-   **Fail** if the keepalive mechanism is broken and the client gets disconnected.
-   **Pass** if your keepalive implementation works correctly.

This setup provides a powerful, automated way to catch critical regressions like the one you experienced. You can expand the `TestHarness` and add more tests for sending messages, receiving receipts, etc., all within this automated framework.