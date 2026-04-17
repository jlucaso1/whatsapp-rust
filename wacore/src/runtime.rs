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
#[must_use = "dropping an AbortHandle aborts the task; use .detach() for fire-and-forget"]
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

/// Publish-side owner of a shutdown notifier. Exposes `notify()` which sets
/// a sticky flag before waking listeners so a late subscriber still observes
/// the shutdown (event_listener notifications are edge-triggered).
pub struct ShutdownNotifier {
    inner: std::sync::Arc<ShutdownInner>,
}

struct ShutdownInner {
    // SeqCst ensures publishers always set `fired` before `event.notify` and
    // subscribers always register `listen` before loading `fired`; combined,
    // a listener either sees the flag or is guaranteed to be woken by notify.
    fired: std::sync::atomic::AtomicBool,
    event: event_listener::Event,
}

impl ShutdownNotifier {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(ShutdownInner {
                fired: std::sync::atomic::AtomicBool::new(false),
                event: event_listener::Event::new(),
            }),
        }
    }

    pub fn notify(&self) {
        self.inner
            .fired
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.event.notify(usize::MAX);
    }

    fn is_fired(&self) -> bool {
        self.inner.fired.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sticky-aware listener: registers the event listener BEFORE reading the
    /// flag so a notify that races this call either sets the flag we observe
    /// or wakes the listener we just registered. Returned future is 'static
    /// so it can be stored in `let` bindings and composed in `select!`.
    pub fn listen(&self) -> impl Future<Output = ()> + use<> {
        let listener = self.inner.event.listen();
        let fired = self.is_fired();
        async move {
            if fired {
                return;
            }
            listener.await;
        }
    }

    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            inner: std::sync::Arc::downgrade(&self.inner),
        }
    }
}

impl Default for ShutdownNotifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Subscribe-side handle. Clone is cheap (wraps `Weak`); does not extend the
/// notifier's lifetime.
#[derive(Clone)]
pub struct ShutdownSignal {
    inner: std::sync::Weak<ShutdownInner>,
}

impl ShutdownSignal {
    /// Inert handle whose listener never fires. Useful for tests or callers
    /// that don't wire a real notifier.
    pub fn never() -> Self {
        Self {
            inner: std::sync::Weak::new(),
        }
    }

    /// Cheap synchronous probe without awaiting. Returns false if the notifier
    /// has been dropped.
    pub fn is_fired(&self) -> bool {
        self.inner
            .upgrade()
            .is_some_and(|i| i.fired.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// Wait for shutdown, resolving when `ShutdownNotifier::notify` has been
/// called. Stays `Pending` if the notifier has been dropped (or if the signal
/// was built via [`ShutdownSignal::never`]); pair with another exit condition
/// in `futures::select!`.
///
/// The listener is registered BEFORE the sticky-flag load so a notify that
/// races the subscription either sets the flag we then observe or wakes the
/// listener we just registered. Call this directly inside the select arm, not
/// earlier in the function, to keep the race window closed.
pub fn wait_for_shutdown(signal: &ShutdownSignal) -> impl Future<Output = ()> + use<> {
    let (fired, listener) = match signal.inner.upgrade() {
        Some(inner) => {
            let listener = inner.event.listen();
            // Load AFTER listen so a notify that happens between the two
            // paths is caught — either the listener wakes or we read the
            // flag set by the publisher.
            let fired = inner.fired.load(std::sync::atomic::Ordering::SeqCst);
            (fired, Some(listener))
        }
        None => (false, None),
    };
    async move {
        if fired {
            return;
        }
        match listener {
            Some(l) => l.await,
            None => std::future::pending::<()>().await,
        }
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod shutdown_tests {
    use super::{ShutdownNotifier, ShutdownSignal, wait_for_shutdown};
    use futures::FutureExt;
    use futures::executor::block_on;

    // Regression guard against CodeRabbit's critical finding on PR #560:
    // event_listener notifications are edge-triggered, so a `notify()` fired
    // before a subscriber calls `listen()` would be lost without the sticky
    // flag. Verify that notify -> subscribe -> wait_for_shutdown still
    // resolves immediately.
    #[test]
    fn wait_for_shutdown_catches_notify_fired_before_subscribe() {
        let notifier = ShutdownNotifier::new();
        notifier.notify();

        let signal = notifier.subscribe();
        block_on(wait_for_shutdown(&signal));
    }

    // Same guard for the publisher-side listen() helper.
    #[test]
    fn notifier_listen_catches_notify_fired_before_listen() {
        let notifier = ShutdownNotifier::new();
        notifier.notify();

        block_on(notifier.listen());
    }

    // Guard the ordered path: listener registered first, notify after.
    // Must resolve through the normal event-listener wakeup (not the sticky
    // flag fast-path, which only fires when the flag is set before listen).
    #[test]
    fn wait_for_shutdown_wakes_on_notify_after_subscribe() {
        let notifier = ShutdownNotifier::new();
        let signal = notifier.subscribe();
        let fut = wait_for_shutdown(&signal);

        notifier.notify();
        block_on(fut);
    }

    // never() must never resolve. Poll once manually and assert Pending.
    #[test]
    fn wait_for_shutdown_never_stays_pending() {
        let signal = ShutdownSignal::never();
        let mut fut = Box::pin(wait_for_shutdown(&signal).fuse());
        let mut ctx = futures::task::Context::from_waker(futures::task::noop_waker_ref());
        assert!(fut.as_mut().poll_unpin(&mut ctx).is_pending());
    }
}
