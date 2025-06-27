use crate::client::Client;
use crate::types::events::{Event, PairError};
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
    if client.store.id.is_some() {
        return Err(QrError::AlreadyLoggedIn);
    }

    let (tx, rx) = mpsc::channel(8);
    let (stop_emitter_tx, stop_emitter_rx) = watch::channel(());
    let closed = Arc::new(AtomicBool::new(false));

    let event_handlers_weak = Arc::downgrade(&client.event_handlers);
    let handler_id_arc = Arc::new(tokio::sync::Mutex::new(None::<usize>));

    let handler = {
        let tx = tx.clone();
        let closed = closed.clone();
        let stop_emitter_tx = stop_emitter_tx.clone();
        let handler_id_arc = handler_id_arc.clone();

        Box::new(move |event: &Event| {
            if closed.load(Ordering::Relaxed) {
                return;
            }

            let tx = tx.clone();
            let closed = closed.clone();
            let stop_emitter_tx = stop_emitter_tx.clone();
            let event_handlers_weak = event_handlers_weak.clone();
            let handler_id_arc = handler_id_arc.clone();
            let event = event.clone();
            let stop_emitter_rx = stop_emitter_rx.clone();

            tokio::spawn(async move {
                let mut terminal_event = None;
                let mut non_terminal_event = None;

                match &event {
                    Event::Qr(qr_data) => {
                        debug!("Received QR event, starting emitter task");
                        tokio::spawn(emit_codes(
                            tx.clone(),
                            stop_emitter_rx,
                            qr_data.codes.clone(),
                        ));
                    }
                    Event::QrScannedWithoutMultidevice(_) => {
                        non_terminal_event = Some(QrCodeEvent::ScannedWithoutMultidevice);
                    }
                    Event::PairSuccess(_) => {
                        terminal_event = Some(QrCodeEvent::Success);
                    }
                    Event::PairError(err) => {
                        terminal_event = Some(QrCodeEvent::Error(err.clone()));
                    }
                    Event::ClientOutdated(_) => {
                        terminal_event = Some(QrCodeEvent::ClientOutdated);
                    }
                    Event::Disconnected(_) => {
                        terminal_event = Some(QrCodeEvent::Timeout);
                    }
                    Event::Connected(_) => {
                        // Do nothing, benign event during pairing flow.
                    }
                    Event::LoggedOut(_) => {
                        terminal_event = Some(QrCodeEvent::LoggedOut);
                    }
                    _ => {}
                }

                if let Some(event) = non_terminal_event {
                    if tx.send(event).await.is_err() {
                        warn!("QR channel receiver was dropped before event was sent.");
                    }
                }

                if let Some(final_event) = terminal_event {
                    let _ = stop_emitter_tx.send(());

                    if closed
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        debug!("Closing QR channel with status: {:?}", final_event);
                        if tx.send(final_event).await.is_err() {
                            warn!("QR channel receiver was dropped before final event.");
                        }

                        if let (Some(handlers_arc), Some(id)) =
                            (event_handlers_weak.upgrade(), *handler_id_arc.lock().await)
                        {
                            tokio::spawn(async move {
                                debug!("Removing QR event handler with ID {}", id);
                                handlers_arc.write().await.retain(|h| h.id != id);
                            });
                        }
                    }
                }
            });
        })
    };

    let id = client.add_event_handler_internal(handler).await;
    *handler_id_arc.lock().await = Some(id);

    Ok(rx)
}
