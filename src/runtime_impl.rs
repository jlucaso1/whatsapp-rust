use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use wacore::runtime::{AbortHandle, Runtime};

/// Tokio-based implementation of [`Runtime`].
pub struct TokioRuntime;

#[async_trait]
impl Runtime for TokioRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) -> AbortHandle {
        let handle = tokio::spawn(future);
        AbortHandle::new(move || handle.abort())
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn spawn_blocking(
        &self,
        f: Box<dyn FnOnce() + Send + 'static>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {
            let _ = tokio::task::spawn_blocking(f).await;
        })
    }
}
