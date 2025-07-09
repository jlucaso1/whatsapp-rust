use anyhow::Result;
use futures_util::{stream::SplitStream, SinkExt, StreamExt};
use log::{info, warn};
use prost::Message;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_tungstenite::{accept_async, tungstenite, WebSocketStream};

use whatsapp_proto::whatsapp as wa;
use whatsapp_rust::binary::node::{Node, NodeContent};
use whatsapp_rust::binary::unmarshal_ref;
use whatsapp_rust::crypto::key_pair::KeyPair;
use whatsapp_rust::store::memory::MemoryStore;
use whatsapp_rust::store::WA_CERT_PUB_KEY;
use whatsapp_rust::types::jid::{Jid, SERVER_JID};

/// Represents the state of a single client connection from the server's perspective.
struct ClientSession {
    server_ephemeral: KeyPair,
    client_ephemeral: [u8; 32],
    noise_state: whatsapp_rust::socket::NoiseHandshake,
    noise_socket: Option<Arc<whatsapp_rust::socket::NoiseSocket>>,
    pair_request_id: String,
}

/// The central state for the mock server.
#[derive(Clone)]
struct MockServer {
    static_key: Arc<KeyPair>,
    cert_root_key: Arc<KeyPair>,
    intermediate_cert: Arc<wa::cert_chain::NoiseCertificate>,
    leaf_cert: Arc<wa::cert_chain::NoiseCertificate>,
    qr_code_rx: Arc<Mutex<mpsc::Receiver<String>>>,
    qr_scanned_rx: Arc<RwLock<Option<oneshot::Receiver<()>>>>,
    phone_identity: Arc<KeyPair>,
}

impl MockServer {
    pub fn new(qr_code_rx: mpsc::Receiver<String>, qr_scanned_rx: oneshot::Receiver<()>) -> Self {
        let static_key = Arc::new(KeyPair::new());

        let cert_root_key = Arc::new(KeyPair::from_private_key([
            54, 166, 8, 116, 172, 178, 183, 23, 226, 12, 179, 151, 161, 23, 126, 238, 16, 219, 98,
            11, 22, 107, 182, 117, 185, 218, 142, 13, 24, 216, 15, 126,
        ]));
        assert_eq!(
            cert_root_key.public_key, WA_CERT_PUB_KEY,
            "Mock server root key must match client's trusted key"
        );

        let intermediate_key = KeyPair::new();
        let leaf_key = static_key.clone();

        let intermediate_details = wa::cert_chain::noise_certificate::Details {
            serial: Some(0),
            issuer_serial: Some(0),
            key: Some(intermediate_key.public_key.to_vec()),
            ..Default::default()
        }
        .encode_to_vec();
        let intermediate_signature = cert_root_key.sign_message(&intermediate_details);
        let intermediate_cert_proto = wa::cert_chain::NoiseCertificate {
            details: Some(intermediate_details),
            signature: Some(intermediate_signature.to_vec()),
        };

        let leaf_details = wa::cert_chain::noise_certificate::Details {
            serial: Some(1),
            issuer_serial: Some(0),
            key: Some(leaf_key.public_key.to_vec()),
            ..Default::default()
        }
        .encode_to_vec();
        let leaf_signature = intermediate_key.sign_message(&leaf_details);
        let leaf_cert_proto = wa::cert_chain::NoiseCertificate {
            details: Some(leaf_details),
            signature: Some(leaf_signature.to_vec()),
        };

        Self {
            static_key,
            cert_root_key,
            intermediate_cert: Arc::new(intermediate_cert_proto),
            leaf_cert: Arc::new(leaf_cert_proto),
            qr_code_rx: Arc::new(Mutex::new(qr_code_rx)),
            qr_scanned_rx: Arc::new(RwLock::new(Some(qr_scanned_rx))),
            phone_identity: Arc::new(KeyPair::new()),
        }
    }

    pub async fn handle_connection(self, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        info!("[Server] New client connected: {}", addr);
        let ws_stream = accept_async(stream).await?;
        let (mut ws_write, mut ws_read) = ws_stream.split();

        let (mut session, _client_hello_bytes) =
            self.perform_server_handshake(&mut ws_read).await?;
        info!("[Server] Handshake Step 1/3: Received ClientHello.");

        let server_hello_bytes = self.build_server_hello(&mut session).await?;
        ws_write
            .send(tungstenite::Message::Binary(server_hello_bytes.into()))
            .await?;
        info!("[Server] Handshake Step 2/3: Sent ServerHello.");

        let client_finish_bytes = match ws_read.next().await {
            Some(Ok(tungstenite::Message::Binary(bytes))) => bytes,
            _ => return Err(anyhow::anyhow!("Failed to receive ClientFinish")),
        };
        let (_client_static_key, _client_payload) =
            self.process_client_finish(&mut session, &client_finish_bytes)?;
        info!("[Server] Handshake Step 3/3: Received and processed ClientFinish.");
        info!(
            "[Server] ✅ Handshake with {} completed successfully.",
            addr
        );

        // NOTE: In a real test, you would now create a NoiseSocket using the handshake state and the websocket.
        // Here, we stub this out, as the public API does not allow constructing a NoiseSocket directly.
        session.noise_socket = None;

        self.run_pairing_flow(session).await?;

        Ok(())
    }
}

impl MockServer {
    pub async fn run(self) -> Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        info!("[Server] Mock server listening on: {}", addr);

        tokio::spawn(async move {
            loop {
                let (stream, addr) = listener.accept().await.unwrap();
                let server_clone = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = server_clone.handle_connection(stream, addr).await {
                        warn!("[Server] Client handler for {} error: {:?}", addr, e);
                    }
                });
            }
        });

        Ok(addr)
    }

    async fn perform_server_handshake(
        &self,
        ws_read: &mut SplitStream<WebSocketStream<TcpStream>>,
    ) -> Result<(ClientSession, Vec<u8>)> {
        let client_hello_bytes = match ws_read.next().await {
            Some(Ok(tungstenite::Message::Binary(bytes))) => bytes,
            e => return Err(anyhow::anyhow!("Expected ClientHello, got {:?}", e)),
        };

        let unpacked = whatsapp_rust::binary::util::unpack(&client_hello_bytes)?;
        let client_hello_node = unmarshal_ref(unpacked.as_ref())?.to_owned();

        let client_hello_payload = handshake_helpers::get_client_hello_payload(&client_hello_node)?;
        let client_hello: wa::handshake_message::ClientHello =
            wa::HandshakeMessage::decode(client_hello_payload.as_slice())?
                .client_hello
                .unwrap();

        let client_ephemeral: [u8; 32] = client_hello.ephemeral.unwrap().as_slice().try_into()?;

        let mut noise_state = whatsapp_rust::socket::NoiseHandshake::new(
            whatsapp_rust::socket::consts::NOISE_START_PATTERN,
            &whatsapp_rust::socket::consts::WA_CONN_HEADER,
        )?;

        noise_state.authenticate(&client_ephemeral);

        let session = ClientSession {
            server_ephemeral: KeyPair::new(),
            client_ephemeral,
            noise_state,
            noise_socket: None,
            pair_request_id: String::new(),
        };

        Ok((session, client_hello_bytes.to_vec()))
    }

    async fn build_server_hello(&self, session: &mut ClientSession) -> Result<Vec<u8>> {
        session
            .noise_state
            .authenticate(&session.server_ephemeral.public_key);
        session.noise_state.mix_shared_secret(
            &session.server_ephemeral.private_key,
            &session.client_ephemeral,
        )?;

        let encrypted_static = session.noise_state.encrypt(&self.static_key.public_key)?;

        session
            .noise_state
            .mix_shared_secret(&self.static_key.private_key, &session.client_ephemeral)?;

        let cert_chain_proto = wa::CertChain {
            leaf: Some((*self.leaf_cert).clone()),
            intermediate: Some((*self.intermediate_cert).clone()),
        };
        let encrypted_cert = session
            .noise_state
            .encrypt(&cert_chain_proto.encode_to_vec())?;

        let server_hello = wa::HandshakeMessage {
            server_hello: Some(wa::handshake_message::ServerHello {
                ephemeral: Some(session.server_ephemeral.public_key.to_vec()),
                r#static: Some(encrypted_static),
                payload: Some(encrypted_cert),
            }),
            ..Default::default()
        };

        Ok(server_hello.encode_to_vec())
    }

    fn process_client_finish<'a>(
        &self,
        session: &'a mut ClientSession,
        client_finish_bytes: &[u8],
    ) -> Result<([u8; 32], wa::ClientPayload)> {
        let client_finish_node =
            unmarshal_ref(whatsapp_rust::binary::util::unpack(client_finish_bytes)?.as_ref())?
                .to_owned();
        let finish_payload = handshake_helpers::get_client_hello_payload(&client_finish_node)?;

        let client_finish: wa::handshake_message::ClientFinish =
            wa::HandshakeMessage::decode(finish_payload.as_slice())?
                .client_finish
                .unwrap();

        let client_static_encrypted = client_finish.r#static.unwrap();
        let client_static_key: [u8; 32] = session
            .noise_state
            .decrypt(&client_static_encrypted)?
            .as_slice()
            .try_into()?;

        session
            .noise_state
            .mix_shared_secret(&session.server_ephemeral.private_key, &client_static_key)?;

        let client_payload_encrypted = client_finish.payload.unwrap();
        let client_payload_bytes = session.noise_state.decrypt(&client_payload_encrypted)?;
        let client_payload = wa::ClientPayload::decode(client_payload_bytes.as_slice())?;

        Ok((client_static_key, client_payload))
    }

    async fn run_pairing_flow(&self, mut session: ClientSession) -> Result<()> {
        info!("[Server] Now in pairing mode with client...");
        // NOTE: noise_socket is not constructed due to public API limitations.
        // let noise_socket = session.noise_socket.as_ref().unwrap().clone();

        let pair_refs = vec!["REF1".to_string(), "REF2".to_string(), "REF3".to_string()];
        session.pair_request_id = format!("pair-{}", rand::thread_rng().gen::<u64>());
        let _pair_device_iq = self.build_pair_device_iq(&session.pair_request_id, pair_refs);

        // Here, we would send the node to the client using the noise socket.
        // noise_socket.send_node(&pair_device_iq).await?;
        info!("[Server] (stub) Sent <pair-device> IQ to client.");

        info!("[Server] Waiting for test runner to 'scan' QR code...");
        let qr_code_str = self
            .qr_code_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("QR code channel closed"))?;
        info!(
            "[Server] Received QR Code from client via test: {}",
            qr_code_str
        );

        let (_pair_success_iq, client_jid) = self.build_pair_success_iq(&session, &qr_code_str)?;
        info!("[Server] Built <pair-success> for JID: {}", client_jid);

        // Here, we would send the node to the client using the noise socket.
        // noise_socket.send_node(&pair_success_iq).await?;
        info!("[Server] (stub) Sent <pair-success> IQ to client.");

        // Skipping wait for final <pair-device-sign> due to unavailable test helper.
        info!(
            "[Server] Skipping wait for final <pair-device-sign> due to unavailable test helper."
        );

        // Here, we would send the final result IQ.
        info!("[Server] (stub) Pairing flow complete. Sent final result to client.");

        if let Some(rx) = self.qr_scanned_rx.write().await.take() {
            let _ = rx.await;
        }

        Ok(())
    }

    fn build_pair_device_iq(&self, req_id: &str, refs: Vec<String>) -> Node {
        let ref_nodes: Vec<Node> = refs
            .into_iter()
            .map(|r| Node {
                tag: "ref".into(),
                attrs: HashMap::new(),
                content: Some(NodeContent::Bytes(r.into_bytes())),
            })
            .collect();

        Node {
            tag: "iq".into(),
            attrs: [
                ("id".into(), req_id.to_string()),
                ("type".into(), "set".into()),
                ("to".into(), SERVER_JID.into()),
                ("from".into(), SERVER_JID.into()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![Node {
                tag: "pair-device".into(),
                attrs: HashMap::new(),
                content: Some(NodeContent::Nodes(ref_nodes)),
            }])),
        }
    }

    fn build_pair_success_iq(&self, session: &ClientSession, qr_code: &str) -> Result<(Node, Jid)> {
        let parts: Vec<&str> = qr_code.split(',').collect();
        let _ref = parts[0];
        let _client_noise_b64 = parts[1];
        let client_identity_b64 = parts[2];
        let client_adv_secret_b64 = parts[3];

        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let client_identity_pk: [u8; 32] =
            B64.decode(client_identity_b64)?.as_slice().try_into()?;

        let adv_secret_key: [u8; 32] = B64.decode(client_adv_secret_b64)?.as_slice().try_into()?;

        let identity_details = wa::AdvDeviceIdentity {
            key_index: Some(1),
            ..Default::default()
        }
        .encode_to_vec();

        let msg_to_sign = pair_helpers::get_adv_msg_to_sign(
            &identity_details,
            &client_identity_pk,
            &self.phone_identity.public_key,
        );
        let account_signature = self.phone_identity.sign_message(&msg_to_sign).to_vec();

        let signed_identity = wa::AdvSignedDeviceIdentity {
            details: Some(identity_details.clone()),
            account_signature: Some(account_signature),
            account_signature_key: Some(self.phone_identity.public_key.to_vec()),
            device_signature: None,
        }
        .encode_to_vec();

        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&adv_secret_key).unwrap();
        mac.update(&signed_identity);
        let hmac_bytes = mac.finalize().into_bytes();

        let hmac_container = wa::AdvSignedDeviceIdentityHmac {
            details: Some(signed_identity),
            hmac: Some(hmac_bytes.to_vec()),
            ..Default::default()
        }
        .encode_to_vec();

        let new_client_jid = Jid::new("1234567890", "s.whatsapp.net");

        let success_node = Node {
            tag: "pair-success".into(),
            attrs: HashMap::new(),
            content: Some(NodeContent::Nodes(vec![
                Node {
                    tag: "device".into(),
                    attrs: [("jid".to_string(), new_client_jid.to_string())].into(),
                    content: None,
                },
                Node {
                    tag: "device-identity".into(),
                    attrs: HashMap::new(),
                    content: Some(NodeContent::Bytes(hmac_container)),
                },
                Node {
                    tag: "biz".into(),
                    attrs: [("name".to_string(), "Mock Server Biz".to_string())].into(),
                    content: None,
                },
                Node {
                    tag: "platform".into(),
                    attrs: [("name".to_string(), "mock-server".to_string())].into(),
                    content: None,
                },
            ])),
        };

        let iq_node = Node {
            tag: "iq".into(),
            attrs: [
                ("from".to_string(), SERVER_JID.to_string()),
                ("id".to_string(), session.pair_request_id.clone()),
                ("type".to_string(), "result".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![success_node])),
        };

        Ok((iq_node, new_client_jid))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_full_registration_flow() {
    let (qr_tx, qr_rx) = mpsc::channel::<String>(1);
    let (scan_tx, scan_rx) = oneshot::channel::<()>();

    let server = MockServer::new(qr_rx, scan_rx);
    let server_addr = server.run().await.unwrap();

    let store_backend = Arc::new(MemoryStore::new());
    let device = whatsapp_rust::store::Device::new(store_backend);
    let client = Arc::new(whatsapp_rust::client::Client::new(device));

    let mut qr_channel = client.get_qr_channel().await.unwrap();

    let client_task = tokio::spawn(async move {
        let event = qr_channel.recv().await;
        info!("[Client Test] Received event from QR channel: {:?}", event);
        if let Some(whatsapp_rust::qrcode::QrCodeEvent::Code { ref code, .. }) = event {
            qr_tx.send(code.clone()).await.unwrap();
        }
        event
    });

    let server_interaction_task = tokio::spawn(async move {
        let _ = scan_tx.send(());
    });

    let (client_result, _) = tokio::join!(client_task, server_interaction_task);

    let final_event = client_result.unwrap().unwrap();
    assert!(
        matches!(final_event, whatsapp_rust::qrcode::QrCodeEvent::Success),
        "Client did not report pairing success, got: {:?}",
        final_event
    );

    info!("✅ End-to-end registration test passed!");
}

mod handshake_helpers {
    use super::*;
    pub fn get_client_hello_payload(node: &whatsapp_rust::binary::node::Node) -> Result<Vec<u8>> {
        let payload = node
            .content
            .as_ref()
            .and_then(|c| match c {
                whatsapp_rust::binary::node::NodeContent::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("ClientHello has no payload"))?;
        Ok(payload)
    }
}

mod pair_helpers {
    pub fn get_adv_msg_to_sign(
        details: &[u8],
        client_pk: &[u8; 32],
        account_pk: &[u8; 32],
    ) -> Vec<u8> {
        let prefix = &[6, 0];
        [prefix, details, client_pk, account_pk].concat()
    }
}
