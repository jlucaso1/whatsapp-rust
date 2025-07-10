use crate::binary::node::{Node, NodeContent};
use crate::socket::NoiseSocket;
use crate::types::jid::SERVER_JID;
use log::{debug, info, warn};
use rand::Rng;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::Duration; // Use tokio::time::Duration

// Constants
const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(20);
const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);

async fn send_ping_directly(noise_socket: &Arc<NoiseSocket>) -> Result<(), anyhow::Error> {
    let ping_id = format!("ping_{}", chrono::Utc::now().timestamp_millis());
    let ping_node = Node {
        tag: "iq".to_string(),
        attrs: vec![
            ("to".to_string(), SERVER_JID.to_string()),
            ("type".to_string(), "get".to_string()),
            ("id".to_string(), ping_id.clone()),
        ]
        .into_iter()
        .collect(),
        content: Some(NodeContent::Nodes(vec![Node {
            tag: "ping".to_string(),
            attrs: Default::default(),
            content: None,
        }])),
    };

    debug!(target: "Keepalive/Send", "Sending ping id: {}", ping_id);

    let payload = crate::binary::marshal(&ping_node)
        .map_err(|e| anyhow::anyhow!("Failed to marshal ping node: {:?}", e))?;

    noise_socket
        .send_frame(&payload)
        .await
        .map_err(|e| e.into())
}

/// Runs the keepalive loop, sending pings at random intervals.
pub async fn run_keepalive_loop(noise_socket: Arc<NoiseSocket>, shutdown_notifier: Arc<Notify>) {
    info!("Keepalive loop starting.");

    loop {
        let interval_ms = rand::thread_rng()
            .gen_range(KEEP_ALIVE_INTERVAL_MIN.as_millis()..=KEEP_ALIVE_INTERVAL_MAX.as_millis());
        let interval_duration = Duration::from_millis(interval_ms as u64);

        tokio::select! {
            biased; // Prioritize shutdown notification
            _ = shutdown_notifier.notified() => {
                info!("Keepalive loop: shutdown signaled.");
                break;
            }
            _ = tokio::time::sleep(interval_duration) => {
                debug!("Keepalive: interval elapsed, sending ping...");
                if let Err(e) = send_ping_directly(&noise_socket).await {
                    warn!("Keepalive: failed to send ping: {:?}. This might indicate a dead connection.", e);
                } else {
                    debug!("Keepalive: ping sent successfully.");
                }
            }
        }
    }
    info!("Keepalive loop stopped.");
}
