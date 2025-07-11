use crate::client::Client;
use crate::types::events::PairError;
use log::{debug, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, watch};

/// Represents an event sent over the QR channel for UI consumption.
#[derive(Debug, Clone)]
pub enum QrCodeEvent {
    /// A new QR code string has been generated.
    Code {
        /// The raw string data for the QR code. This should be rendered as a QR code image.
        code: String,
        /// The recommended time to display this code before it expires.
        timeout: Duration,
    },
    /// The pairing was successful. This is a terminal event; the channel will close after this.
    Success,
    /// The pairing process timed out (e.g., server disconnected). This is a terminal event.
    Timeout,
    /// An unexpected event occurred, suggesting the client is already paired or in a bad state. This is a terminal event.
    UnexpectedState,
    /// The client version is outdated and was rejected by the server. This is a terminal event.
    ClientOutdated,
    /// The QR code was scanned by a phone that does not have the multi-device beta enabled.
    /// The same QR code can be re-scanned after the user enables it.
    ScannedWithoutMultidevice,
    /// An error occurred during pairing. This is a terminal event.
    Error(PairError),
    /// The client was logged out from another device during pairing. This is a terminal event.
    LoggedOut,
}

/// Errors that can occur when requesting the QR channel.
#[derive(Debug, Error)]
pub enum QrError {
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client is already logged in (store contains a JID)")]
    AlreadyLoggedIn,
}
/// Asynchronously emits QR codes from a list to the output channel.
async fn emit_codes(
    output: mpsc::Sender<QrCodeEvent>,
    mut stop_rx: watch::Receiver<()>,
    codes: Vec<String>,
) {
    let mut codes_iter = codes.into_iter();
    // WhatsApp Web shows the first code for 60s and subsequent ones for 20s.
    let mut is_first = true;

    loop {
        let code = match codes_iter.next() {
            Some(c) => c,
            None => {
                debug!("Ran out of QR codes to emit, sending Timeout and stopping.");
                let _ = output.try_send(QrCodeEvent::Timeout);
                return;
            }
        };

        // FIX: Implement the 60s/20s timeout logic.
        let timeout = if is_first {
            is_first = false;
            Duration::from_secs(60)
        } else {
            Duration::from_secs(20)
        };

        debug!("Emitting QR code, timeout {}s", timeout.as_secs());
        let event = QrCodeEvent::Code { code, timeout };

        if output.send(event).await.is_err() {
            debug!("Output channel closed, exiting QR emitter");
            return;
        }

        tokio::select! {
            _ = tokio::time::sleep(timeout) => {
                // Time's up, continue to the next code
            }
            _ = stop_rx.changed() => {
                debug!("Got signal to stop QR emitter");
                return;
            }
        }
    }
}

/// The internal logic for `client.get_qr_channel`.
///
/// This function sets up the state and the master event handler that drives the QR flow.
pub(crate) async fn get_qr_channel_logic(
    client: &Client,
) -> Result<mpsc::Receiver<QrCodeEvent>, QrError> {
    if client.is_connected() {
        return Err(QrError::AlreadyConnected);
    }
    // Use persistence_manager to check login status
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    if device_snapshot.id.is_some() {
        return Err(QrError::AlreadyLoggedIn);
    }

    let (tx, rx) = mpsc::channel(8);
    let (stop_emitter_tx, stop_emitter_rx) = watch::channel(());
    let closed = Arc::new(AtomicBool::new(false));

    // Subscribe to all the events we need
    let mut qr_rx = client.subscribe_to_qr();
    let mut qr_scanned_rx = client.subscribe_to_qr_scanned_without_multidevice();
    let mut pair_success_rx = client.subscribe_to_pair_success();
    let mut pair_error_rx = client.subscribe_to_pair_error();
    let mut client_outdated_rx = client.subscribe_to_client_outdated();
    let mut disconnected_rx = client.subscribe_to_disconnected();
    let mut connected_rx = client.subscribe_to_connected();
    let mut logged_out_rx = client.subscribe_to_logged_out();

    // Spawn a task to handle all the event subscriptions
    let tx_clone = tx.clone();
    let closed_clone = closed.clone();
    let stop_emitter_tx_clone = stop_emitter_tx.clone();
    
    tokio::spawn(async move {
        loop {
            if closed_clone.load(Ordering::Relaxed) {
                break;
            }

            let mut terminal_event = None;
            let mut non_terminal_event = None;

            tokio::select! {
                Ok(qr_data) = qr_rx.recv() => {
                    debug!("Received QR event, starting emitter task");
                    tokio::spawn(emit_codes(
                        tx_clone.clone(),
                        stop_emitter_rx.clone(),
                        qr_data.codes.clone(),
                    ));
                }
                Ok(_) = qr_scanned_rx.recv() => {
                    non_terminal_event = Some(QrCodeEvent::ScannedWithoutMultidevice);
                }
                Ok(_) = pair_success_rx.recv() => {
                    terminal_event = Some(QrCodeEvent::Success);
                }
                Ok(err) = pair_error_rx.recv() => {
                    terminal_event = Some(QrCodeEvent::Error((*err).clone()));
                }
                Ok(_) = client_outdated_rx.recv() => {
                    terminal_event = Some(QrCodeEvent::ClientOutdated);
                }
                Ok(_) = disconnected_rx.recv() => {
                    terminal_event = Some(QrCodeEvent::Timeout);
                }
                Ok(_) = connected_rx.recv() => {
                    // Do nothing, benign event during pairing flow.
                }
                Ok(_) = logged_out_rx.recv() => {
                    terminal_event = Some(QrCodeEvent::LoggedOut);
                }
                else => {
                    // All channels closed, break the loop
                    break;
                }
            }

            if let Some(event) = non_terminal_event {
                if tx_clone.send(event).await.is_err() {
                    warn!("QR channel receiver was dropped before event was sent.");
                    break;
                }
            }

            if let Some(final_event) = terminal_event {
                let _ = stop_emitter_tx_clone.send(());

                if closed_clone
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    debug!("Closing QR channel with status: {final_event:?}");
                    if tx_clone.send(final_event).await.is_err() {
                        warn!("QR channel receiver was dropped before final event.");
                    }
                    break;
                }
            }
        }
    });

    Ok(rx)
}
