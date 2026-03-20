//! Media connection management.
//!
//! Protocol types are defined in `wacore::iq::mediaconn`.

use crate::client::Client;
use crate::request::IqError;
use std::time::Duration;
use wacore::iq::mediaconn::MediaConnSpec;
use wacore::time::Instant;

/// Re-export the host type from wacore.
pub use wacore::iq::mediaconn::MediaConnHost;

/// Number of retry attempts after a media auth error (401/403).
/// On auth failure, the media connection is invalidated and refreshed before retrying.
pub(crate) const MEDIA_AUTH_REFRESH_RETRY_ATTEMPTS: usize = 1;

/// Returns `true` if the HTTP status code indicates a media auth error
/// that should trigger a media connection refresh and retry.
pub(crate) fn is_media_auth_error(status_code: u16) -> bool {
    matches!(status_code, 401 | 403)
}

/// Media connection with runtime-specific fields.
#[derive(Debug, Clone)]
pub struct MediaConn {
    /// Authentication token for media operations.
    pub auth: String,
    /// Time-to-live in seconds for route info.
    pub ttl: u64,
    /// Time-to-live in seconds for auth token (may differ from route TTL).
    pub auth_ttl: Option<u64>,
    /// Available media hosts (sorted: primary first, fallback second).
    pub hosts: Vec<MediaConnHost>,
    /// When this connection info was fetched (runtime-specific).
    pub fetched_at: Instant,
}

impl MediaConn {
    /// Check if this connection info has expired.
    /// Uses the earlier of route TTL and auth TTL (auth may expire before routes).
    pub fn is_expired(&self) -> bool {
        let effective_ttl = self.auth_ttl.map_or(self.ttl, |at| self.ttl.min(at));
        self.fetched_at.elapsed() > Duration::from_secs(effective_ttl)
    }
}

impl Client {
    pub(crate) async fn invalidate_media_conn(&self) {
        *self.media_conn.write().await = None;
    }

    pub async fn refresh_media_conn(&self, force: bool) -> Result<MediaConn, IqError> {
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
            auth_ttl: response.auth_ttl,
            hosts: response.hosts,
            fetched_at: Instant::now(),
        };

        let mut write_guard = self.media_conn.write().await;
        *write_guard = Some(new_conn.clone());

        Ok(new_conn)
    }
}
