use crate::client::Client;
use crate::types::events::PairError;
use log::{debug, warn};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task;
use wacore::types::events::{Event, EventHandler};

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

struct QrCodeEventHandler {
    output: mpsc::Sender<QrCodeEvent>,
    stop_emitter_tx: watch::Sender<()>,
    closed: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
enum QrAction {
    EmitCodes(Vec<String>),
    ProcessNonTerminal(QrCodeEvent),
    ProcessTerminal(QrCodeEvent),
}

impl EventHandler for QrCodeEventHandler {
    fn handle_event(&self, event: &Event) {
        let action = match event {
            Event::Qr(qr_data) => Some(QrAction::EmitCodes(qr_data.codes.clone())),
            Event::QrScannedWithoutMultidevice(_) => Some(QrAction::ProcessNonTerminal(
                QrCodeEvent::ScannedWithoutMultidevice,
            )),
            Event::PairSuccess(_) => Some(QrAction::ProcessTerminal(QrCodeEvent::Success)),
            Event::PairError(err) => {
                Some(QrAction::ProcessTerminal(QrCodeEvent::Error(err.clone())))
            }
            Event::ClientOutdated(_) => {
                Some(QrAction::ProcessTerminal(QrCodeEvent::ClientOutdated))
            }
            Event::Disconnected(_) => Some(QrAction::ProcessTerminal(QrCodeEvent::Timeout)),
            Event::LoggedOut(_) => Some(QrAction::ProcessTerminal(QrCodeEvent::LoggedOut)),
            _ => None,
        };

        if let Some(owned_action) = action {
            let tx = self.output.clone();
            let stop_emitter_tx = self.stop_emitter_tx.clone();
            let closed = self.closed.clone();

            tokio::task::spawn_local(async move {
                match owned_action {
                    QrAction::EmitCodes(codes) => {
                        debug!("Handler received QR event, starting emitter task");
                        let (emitter_tx, mut emitter_rx) = mpsc::channel(8);

                        task::spawn_local(emit_codes(
                            emitter_tx,
                            stop_emitter_tx.subscribe(),
                            codes,
                        ));

                        let fwd_tx = tx.clone();
                        task::spawn_local(async move {
                            while let Some(evt) = emitter_rx.recv().await {
                                if fwd_tx.send(evt).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    QrAction::ProcessNonTerminal(event) => {
                        if tx.send(event).await.is_err() {
                            warn!(
                                "QR channel receiver was dropped before non-terminal event was sent."
                            );
                        }
                    }
                    QrAction::ProcessTerminal(final_event) => {
                        let _ = stop_emitter_tx.send(());

                        if closed
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            debug!("Closing QR channel with status: {:?}", final_event);
                            if tx.send(final_event).await.is_err() {
                                warn!(
                                    "QR channel receiver was dropped before final event was sent."
                                );
                            }
                        }
                    }
                }
            });
        }
    }
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
    if device_snapshot.pn.is_some() {
        return Err(QrError::AlreadyLoggedIn);
    }

    let (tx, rx) = mpsc::channel(8);
    let (stop_emitter_tx, _) = watch::channel(());

    let handler = Arc::new(QrCodeEventHandler {
        output: tx,
        stop_emitter_tx,
        closed: Arc::new(AtomicBool::new(false)),
    });

    client.core.event_bus.add_handler(handler);

    Ok(rx)
}
