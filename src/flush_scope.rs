//! Tracks spawned tasks so a shutdown point can wait for them to complete.
//!
//! Used for outbound stanzas (delivery receipts, etc.) that must land before
//! the transport is torn down (issue #571). The decrement runs via a Drop
//! guard so the counter can't leak if the task future is cancelled mid-await.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use wacore::runtime::Runtime;

pub struct FlushScope {
    count: AtomicUsize,
    idle: event_listener::Event,
}

impl Default for FlushScope {
    fn default() -> Self {
        Self::new()
    }
}

impl FlushScope {
    pub fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            idle: event_listener::Event::new(),
        }
    }

    /// Spawn a tracked task. The counter decrements on completion OR if the
    /// future is dropped (e.g. aborted), so `flush` can never deadlock waiting
    /// on a cancelled task.
    pub fn spawn<F>(self: &Arc<Self>, rt: &dyn Runtime, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.count.fetch_add(1, Ordering::Relaxed);
        let scope = Arc::clone(self);
        rt.spawn(Box::pin(async move {
            let _guard = DecrementOnDrop { scope };
            fut.await;
        }))
        .detach();
    }

    /// Wait until every tracked task has finished or the timeout elapses.
    /// Emits a warn log on timeout with the number of leaked tasks.
    pub async fn flush(&self, rt: &dyn Runtime, timeout: Duration) {
        use wacore::time::Instant;

        let deadline = Instant::now() + timeout;
        loop {
            let listener = self.idle.listen();
            if self.count.load(Ordering::Relaxed) == 0 {
                return;
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero()
                || wacore::runtime::timeout(rt, remaining, listener)
                    .await
                    .is_err()
            {
                log::warn!(
                    "FlushScope timed out with {} pending task(s)",
                    self.count.load(Ordering::Relaxed)
                );
                return;
            }
        }
    }

    #[cfg(test)]
    pub fn pending(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

struct DecrementOnDrop {
    scope: Arc<FlushScope>,
}

impl Drop for DecrementOnDrop {
    fn drop(&mut self) {
        if self.scope.count.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.scope.idle.notify(usize::MAX);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    fn rt() -> Arc<dyn Runtime> {
        Arc::new(crate::runtime_impl::TokioRuntime)
    }

    #[tokio::test]
    async fn flush_returns_after_tasks_complete() {
        let scope = Arc::new(FlushScope::new());
        let runtime = rt();
        for _ in 0..5 {
            let r = Arc::clone(&runtime);
            scope.spawn(&*runtime, async move {
                r.sleep(Duration::from_millis(20)).await;
            });
        }
        assert_eq!(scope.pending(), 5);

        let start = Instant::now();
        scope.flush(&*runtime, Duration::from_secs(1)).await;
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(scope.pending(), 0);
    }

    #[tokio::test]
    async fn flush_returns_immediately_when_idle() {
        let scope = Arc::new(FlushScope::new());
        let runtime = rt();

        let start = Instant::now();
        scope.flush(&*runtime, Duration::from_secs(5)).await;
        assert!(start.elapsed() < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn flush_honors_timeout_and_logs() {
        let scope = Arc::new(FlushScope::new());
        let runtime = rt();
        let r = Arc::clone(&runtime);
        scope.spawn(&*runtime, async move {
            r.sleep(Duration::from_secs(10)).await;
        });

        let start = Instant::now();
        scope.flush(&*runtime, Duration::from_millis(50)).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_millis(500));
        assert_eq!(scope.pending(), 1);
    }

    /// Regression: if a tracked task's future is dropped after being polled
    /// (the normal abort path), the counter must still decrement via Drop.
    #[tokio::test]
    async fn decrement_runs_when_future_is_aborted_mid_flight() {
        use std::task::{Context, Poll};

        let scope = Arc::new(FlushScope::new());
        scope.count.fetch_add(1, Ordering::Relaxed);

        let scope_for_fut = Arc::clone(&scope);
        let mut fut: std::pin::Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
            let _guard = DecrementOnDrop {
                scope: scope_for_fut,
            };
            futures::future::pending::<()>().await;
        });

        // Poll once so the guard is constructed and the future suspends on the
        // inner pending().
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(scope.pending(), 1);

        // Simulate abort: drop the in-flight boxed future.
        drop(fut);
        assert_eq!(
            scope.pending(),
            0,
            "DecrementOnDrop must fire when the in-flight future is dropped"
        );
    }

    #[tokio::test]
    async fn ran_bodies_observe_completion() {
        let scope = Arc::new(FlushScope::new());
        let runtime = rt();
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        scope.spawn(&*runtime, async move {
            done_clone.store(true, Ordering::Relaxed);
        });
        scope.flush(&*runtime, Duration::from_secs(1)).await;
        assert!(done.load(Ordering::Relaxed));
    }
}
