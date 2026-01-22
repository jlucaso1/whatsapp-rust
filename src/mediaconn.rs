//! Media connection management.
//!
//! Protocol types are defined in `wacore::iq::mediaconn`.

use crate::client::Client;
use crate::request::IqError;
use std::time::{Duration, Instant};
use wacore::iq::mediaconn::MediaConnSpec;

/// Re-export the host type from wacore.
pub use wacore::iq::mediaconn::MediaConnHost;

/// Media connection with runtime-specific fields.
#[derive(Debug, Clone)]
pub struct MediaConn {
    /// Authentication token for media operations.
    pub auth: String,
    /// Time-to-live in seconds.
    pub ttl: u64,
    /// Available media hosts.
    pub hosts: Vec<MediaConnHost>,
    /// When this connection info was fetched (runtime-specific).
    pub fetched_at: Instant,
}

impl MediaConn {
    /// Check if this connection info has expired.
    pub fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > Duration::from_secs(self.ttl)
    }
}

impl Client {
    pub(crate) async fn refresh_media_conn(&self, force: bool) -> Result<MediaConn, IqError> {
        {
            let guard = self.media_conn.read().await;
            if !force
                && let Some(conn) = &*guard
                && !conn.is_expired()
            {
                return Ok(conn.clone());
            }
        }

        let response = self.execute(MediaConnSpec::new()).await?;

        let new_conn = MediaConn {
            auth: response.auth,
            ttl: response.ttl,
            hosts: response.hosts,
            fetched_at: Instant::now(),
        };

        let mut write_guard = self.media_conn.write().await;
        *write_guard = Some(new_conn.clone());

        Ok(new_conn)
    }
}
