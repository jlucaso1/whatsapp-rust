use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;

/// A runtime-agnostic abstraction over async executor capabilities.
///
/// On native targets, futures must be `Send` (multi-threaded executors).
/// On wasm32, `Send` is dropped (single-threaded).
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Runtime: Send + Sync + 'static {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) -> AbortHandle;
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;
    fn spawn_blocking(
        &self,
        f: Box<dyn FnOnce() + Send + 'static>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Cooperatively yield, allowing other tasks and I/O to make progress.
    ///
    /// Use this in tight async loops that process many items to avoid
    /// starving other work. Returns `None` if yielding is unnecessary
    /// (e.g. multi-threaded runtimes where other tasks run on separate
    /// threads), or `Some(future)` that the caller must `.await` to
    /// actually yield.
    ///
    /// Returning `None` avoids any allocation or async overhead, making
    /// the call zero-cost on runtimes that don't need cooperative yielding.
    fn yield_now(&self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>>;

    /// How often to yield in tight loops (every N items). Defaults to 10.
    /// Single-threaded runtimes should return 1 to avoid starving the event loop.
    fn yield_frequency(&self) -> u32 {
        10
    }
}

/// WASM variant — `Send` bounds removed since WASM is single-threaded.
/// Concrete types use `unsafe impl Send + Sync` since there's only one thread.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Runtime: Send + Sync + 'static {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + 'static>>) -> AbortHandle;
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()>>>;
    fn spawn_blocking(&self, f: Box<dyn FnOnce() + 'static>) -> Pin<Box<dyn Future<Output = ()>>>;

    /// Cooperatively yield, allowing other tasks and I/O to make progress.
    ///
    /// Returns `None` if yielding is unnecessary, or `Some(future)` that
    /// the caller must `.await` to actually yield.
    fn yield_now(&self) -> Option<Pin<Box<dyn Future<Output = ()>>>>;

    /// How often to yield in tight loops (every N items). Defaults to 10.
    /// Single-threaded runtimes should return 1 to avoid starving the event loop.
    fn yield_frequency(&self) -> u32 {
        10
    }
}

/// Handle returned by [`Runtime::spawn`]. Aborts the spawned task when dropped.
///
/// Uses `std::sync::Mutex` internally so that the handle is `Send + Sync`,
/// which is required because it may be stored inside structs shared across
/// tasks (e.g. `NoiseSocket` behind an `Arc`).
#[must_use = "dropping an AbortHandle aborts the task; use .detach() for fire-and-forget or track it via TaskTracker"]
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

/// Tracks spawned tasks and aborts them all on demand or when dropped.
///
/// Two intended scopes:
/// - **Connection-scoped**: aborted on disconnect via `abort_all()`.
/// - **Client-scoped**: aborted when the owning struct is dropped.
pub struct TaskTracker {
    handles: std::sync::Mutex<Vec<AbortHandle>>,
}

impl TaskTracker {
    pub fn new() -> Self {
        Self {
            handles: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Store an existing `AbortHandle` so it will be aborted on `abort_all()` / drop.
    pub fn track(&self, handle: AbortHandle) {
        self.handles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(handle);
    }

    /// Abort every tracked task and clear the list.
    pub fn abort_all(&self) {
        let handles = std::mem::take(&mut *self.handles.lock().unwrap_or_else(|p| p.into_inner()));
        for handle in handles {
            handle.abort();
        }
    }

    /// Number of tracked handles (includes already-completed tasks).
    pub fn len(&self) -> usize {
        self.handles.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TaskTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TaskTracker {
    fn drop(&mut self) {
        self.abort_all();
    }
}

/// Convenience methods that depend on `Runtime`. Cfg-gated for Send bounds.
#[cfg(not(target_arch = "wasm32"))]
impl TaskTracker {
    /// Spawn a future via the given runtime and track the handle.
    pub fn spawn(
        &self,
        rt: &dyn Runtime,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        self.track(rt.spawn(future));
    }
}

#[cfg(target_arch = "wasm32")]
impl TaskTracker {
    /// Spawn a future via the given runtime and track the handle.
    pub fn spawn(&self, rt: &dyn Runtime, future: Pin<Box<dyn Future<Output = ()> + 'static>>) {
        self.track(rt.spawn(future));
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
/// Convenience wrapper around [`Runtime::spawn_blocking`] that uses
/// a oneshot channel to ferry the closure's return value back to the caller.
///
/// # Panics
///
/// Panics if the runtime drops the spawned task before it completes
/// (e.g. during runtime shutdown).
#[cfg(not(target_arch = "wasm32"))]
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
        panic!("blocking task failed to complete (closure panic or runtime shutdown)")
    })
}

/// WASM variant — runs inline (single-threaded).
#[cfg(target_arch = "wasm32")]
pub async fn blocking<T: 'static>(_rt: &dyn Runtime, f: impl FnOnce() -> T + 'static) -> T {
    f()
}
