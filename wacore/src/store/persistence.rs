//! Runtime-agnostic persistence manager for device state.
//!
//! This is the core implementation that works with `wacore::store::Device` directly.
//! The `whatsapp-rust` crate has its own `PersistenceManager` in
//! `src/store/persistence_manager.rs` that wraps a `Device` with an attached
//! `Backend` reference. That version should eventually be consolidated into this
//! one once the `Device` wrapper is unified.

use crate::runtime::{AbortHandle, Runtime, wait_for_shutdown};
use crate::store::commands::{DeviceCommand, apply_command_to_device};
use crate::store::device::Device;
use crate::store::error::{StoreError, db_err};
use crate::store::traits::Backend;
use async_lock::RwLock;
use event_listener::Event;
use futures::FutureExt;
use log::{debug, error};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Manages device state persistence with lazy, batched writes.
///
/// All state changes go through `modify_device()` which marks the state dirty.
/// A background task periodically flushes dirty state to the backend.
pub struct PersistenceManager {
    device: Arc<RwLock<Device>>,
    backend: Arc<dyn Backend>,
    dirty: Arc<AtomicBool>,
    save_notify: Arc<Event>,
}

impl PersistenceManager {
    /// Create a PersistenceManager with a backend implementation.
    pub async fn new(backend: Arc<dyn Backend>) -> Result<Self, StoreError> {
        debug!("PersistenceManager: Ensuring device row exists.");
        let exists = backend.exists().await.map_err(db_err)?;
        if !exists {
            debug!("PersistenceManager: No device row found. Creating new device row.");
            let id = backend.create().await.map_err(db_err)?;
            debug!("PersistenceManager: Created device row with id={id}.");
        }

        debug!("PersistenceManager: Attempting to load device data via Backend.");
        let device_data_opt = backend.load().await.map_err(db_err)?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.",
                serializable_device.push_name
            );
            serializable_device
        } else {
            debug!("PersistenceManager: No data yet; initializing default Device in memory.");
            Device::new()
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend,
            dirty: Arc::new(AtomicBool::new(false)),
            save_notify: Arc::new(Event::new()),
        })
    }

    pub fn device_arc(&self) -> Arc<RwLock<Device>> {
        self.device.clone()
    }

    pub async fn get_device_snapshot(&self) -> Device {
        self.device.read().await.clone()
    }

    pub fn backend(&self) -> Arc<dyn Backend> {
        self.backend.clone()
    }

    /// Modify device state directly.
    ///
    /// **Warning**: This bypasses the `DeviceCommand` abstraction. Prefer
    /// `process_command()` for structured modifications. Use this only when
    /// `DeviceCommand` doesn't cover the needed mutation.
    pub async fn modify_device<F, R>(&self, modifier: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut device_guard = self.device.write().await;
        let result = modifier(&mut device_guard);

        self.dirty.store(true, Ordering::Relaxed);
        self.save_notify.notify(1);

        result
    }

    async fn save_to_disk(&self) -> Result<(), StoreError> {
        if self.dirty.swap(false, Ordering::AcqRel) {
            debug!("Device state is dirty, saving to disk.");
            let device_guard = self.device.read().await;
            let serializable_device = device_guard.clone();
            drop(device_guard);

            if let Err(e) = self.backend.save(&serializable_device).await {
                // Restore dirty flag so the next tick retries the save
                self.dirty.store(true, Ordering::Release);
                return Err(db_err(e));
            }
            debug!("Device state saved successfully.");
        }
        Ok(())
    }

    /// Triggers a snapshot of the underlying storage backend.
    pub async fn create_snapshot(
        &self,
        name: &str,
        extra_content: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        #[cfg(feature = "debug-snapshots")]
        {
            self.save_to_disk().await?;
            self.backend
                .snapshot_db(name, extra_content)
                .await
                .map_err(db_err)
        }
        #[cfg(not(feature = "debug-snapshots"))]
        {
            let _ = name;
            let _ = extra_content;
            log::warn!("Snapshot requested but 'debug-snapshots' feature is disabled");
            Ok(())
        }
    }

    /// Self-terminates on `shutdown.notify(...)` after a final flush.
    /// Caller must keep the returned `AbortHandle` — dropping it aborts the task.
    pub fn run_background_saver(
        self: Arc<Self>,
        runtime: Arc<dyn Runtime>,
        interval: Duration,
        shutdown: Weak<Event>,
    ) -> AbortHandle {
        let rt = runtime.clone();
        let weak = Arc::downgrade(&self);
        drop(self); // Release strong ref; caller's Arc keeps it alive
        debug!("Background saver task started with interval {interval:?}");
        runtime.spawn(Box::pin(async move {
            // Flush any state dirtied during construction before the first wait,
            // covering the window where save_notify fires between PM creation
            // and the first listener registration.
            if let Some(this) = weak.upgrade()
                && let Err(e) = this.save_to_disk().await
            {
                error!("Background saver: initial flush failed: {e}");
            }

            loop {
                let Some(this) = weak.upgrade() else {
                    debug!("PersistenceManager dropped, exiting background saver.");
                    return;
                };
                let save_listener = this.save_notify.listen();
                drop(this);

                let should_exit = futures::select! {
                    _ = save_listener.fuse() => false,
                    _ = rt.sleep(interval).fuse() => false,
                    _ = wait_for_shutdown(&shutdown).fuse() => true,
                };

                let Some(this) = weak.upgrade() else {
                    debug!("PersistenceManager dropped, exiting background saver.");
                    return;
                };
                if let Err(e) = this.save_to_disk().await {
                    error!("Error saving device state in background: {e}");
                }

                if should_exit {
                    debug!("Background saver received shutdown; final flush complete.");
                    return;
                }
            }
        }))
    }

    pub async fn process_command(&self, command: DeviceCommand) {
        self.modify_device(|device| {
            apply_command_to_device(device, command);
        })
        .await;
    }

    pub async fn get_sender_key_devices(
        &self,
        group_jid: &str,
    ) -> Result<Vec<(String, bool)>, StoreError> {
        self.backend
            .get_sender_key_devices(group_jid)
            .await
            .map_err(db_err)
    }

    pub async fn set_sender_key_status(
        &self,
        group_jid: &str,
        entries: &[(&str, bool)],
    ) -> Result<(), StoreError> {
        self.backend
            .set_sender_key_status(group_jid, entries)
            .await
            .map_err(db_err)
    }

    pub async fn clear_sender_key_devices(&self, group_jid: &str) -> Result<(), StoreError> {
        self.backend
            .clear_sender_key_devices(group_jid)
            .await
            .map_err(db_err)
    }
}
