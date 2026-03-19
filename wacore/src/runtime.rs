use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;

/// A runtime-agnostic abstraction over async executor capabilities.
///
/// Only truly runtime-specific operations live here: spawning tasks,
/// sleeping, and offloading blocking work. Everything else (mutexes,
/// channels, etc.) uses runtime-agnostic crates directly.
#[async_trait]
pub trait Runtime: Send + Sync + 'static {
    /// Spawn a background task. Returns a handle that can cancel the task.
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) -> AbortHandle;

    /// Sleep for the given duration.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Offload a blocking closure to a thread where blocking is acceptable.
    fn spawn_blocking(
        &self,
        f: Box<dyn FnOnce() + Send + 'static>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Handle returned by [`Runtime::spawn`]. Aborts the spawned task when dropped.
///
/// Uses `std::sync::Mutex` internally so that the handle is `Send + Sync`,
/// which is required because it may be stored inside structs shared across
/// tasks (e.g. `NoiseSocket` behind an `Arc`).
pub struct AbortHandle {
    abort_fn: std::sync::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

impl AbortHandle {
    /// Create a new abort handle with the given cancellation function.
    pub fn new(abort_fn: impl FnOnce() + Send + 'static) -> Self {
        Self {
            abort_fn: std::sync::Mutex::new(Some(Box::new(abort_fn))),
        }
    }

    /// Create a no-op handle that does nothing on drop.
    pub fn noop() -> Self {
        Self {
            abort_fn: std::sync::Mutex::new(None),
        }
    }

    /// Explicitly abort the spawned task without waiting for drop.
    pub fn abort(&self) {
        if let Some(f) = self
            .abort_fn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            f();
        }
    }

    /// Detach the handle so the task is NOT aborted on drop.
    ///
    /// The spawned task will run until completion even if the parent scope
    /// is dropped. Use this for fire-and-forget tasks where cancellation
    /// is not desired.
    pub fn detach(self) {
        *self.abort_fn.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl Drop for AbortHandle {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Error returned when an async operation times out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("operation timed out")]
pub struct Elapsed;

/// Race a future against a timeout. Returns [`Elapsed`] if the duration
/// expires before the future completes.
pub async fn timeout<F, T>(rt: &dyn Runtime, duration: Duration, future: F) -> Result<T, Elapsed>
where
    F: Future<Output = T>,
{
    use futures::future::Either;

    futures::pin_mut!(future);
    let sleep = rt.sleep(duration);
    futures::pin_mut!(sleep);

    match futures::future::select(future, sleep).await {
        Either::Left((result, _)) => Ok(result),
        Either::Right(((), _)) => Err(Elapsed),
    }
}

/// Offload a blocking closure to a thread where blocking is acceptable,
/// returning its result.
///
/// This is a convenience wrapper around [`Runtime::spawn_blocking`] that uses
/// a oneshot channel to ferry the closure's return value back to the caller.
///
/// # Panics
///
/// Panics if the runtime drops the spawned task before it completes (e.g.
/// during runtime shutdown). Callers in shutdown-sensitive paths should use
/// [`Runtime::spawn_blocking`] directly with explicit error handling.
pub async fn blocking<T: Send + 'static>(
    rt: &dyn Runtime,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = futures::channel::oneshot::channel();
    rt.spawn_blocking(Box::new(move || {
        let _ = tx.send(f());
    }))
    .await;
    rx.await.unwrap_or_else(|_| {
        panic!("spawn_blocking task was dropped before completion (runtime shutting down?)")
    })
}
