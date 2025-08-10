use crate::client::Client;
use crate::types::events::PairError;
use log::{debug, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task;

#[derive(Debug, Clone)]
pub enum QrCodeEvent {
    Code { code: String, timeout: Duration },
    Success,
    Timeout,
    UnexpectedState,
    ClientOutdated,
    ScannedWithoutMultidevice,
    Error(PairError),
    LoggedOut,
}

#[derive(Debug, Error)]
pub enum QrError {
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client is already logged in (store contains a JID)")]
    AlreadyLoggedIn,
}

async fn emit_codes(
    output: mpsc::Sender<QrCodeEvent>,
    mut stop_rx: watch::Receiver<()>,
    codes: Vec<String>,
) {
    let mut codes_iter = codes.into_iter();
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
            _ = tokio::time::sleep(timeout) => {}
            _ = stop_rx.changed() => {
                debug!("Got signal to stop QR emitter");
                return;
            }
        }
    }
}

pub(crate) async fn get_qr_channel_logic(
    client: &Client,
) -> Result<mpsc::Receiver<QrCodeEvent>, QrError> {
    if client.is_connected() {
        return Err(QrError::AlreadyConnected);
    }

    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    if device_snapshot.id.is_some() {
        return Err(QrError::AlreadyLoggedIn);
    }

    let (tx, rx) = mpsc::channel(8);
    let (stop_emitter_tx, stop_emitter_rx) = watch::channel(());
    let closed = Arc::new(AtomicBool::new(false));

    let mut qr_rx = client.subscribe_to_qr();
    let mut qr_scanned_rx = client.subscribe_to_qr_scanned_without_multidevice();
    let mut pair_success_rx = client.subscribe_to_pair_success();
    let mut pair_error_rx = client.subscribe_to_pair_error();
    let mut client_outdated_rx = client.subscribe_to_client_outdated();
    let mut disconnected_rx = client.subscribe_to_disconnected();
    let mut connected_rx = client.subscribe_to_connected();
    let mut logged_out_rx = client.subscribe_to_logged_out();

    let tx_clone = tx.clone();
    let closed_clone = closed.clone();
    let stop_emitter_tx_clone = stop_emitter_tx.clone();

    task::spawn_local(async move {
        loop {
            if closed_clone.load(Ordering::Relaxed) {
                break;
            }

            let mut terminal_event = None;
            let mut non_terminal_event = None;

            tokio::select! {
                Ok(qr_data) = qr_rx.recv() => {
                    debug!("Received QR event, starting emitter task");
                    task::spawn_local(emit_codes(
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
                Ok(_) = connected_rx.recv() => {}
                Ok(_) = logged_out_rx.recv() => {
                    terminal_event = Some(QrCodeEvent::LoggedOut);
                }
                else => {
                    break;
                }
            }

            if let Some(event) = non_terminal_event
                && tx_clone.send(event).await.is_err()
            {
                warn!("QR channel receiver was dropped before event was sent.");
                break;
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
