//! Pluggable time provider.
//!
//! By default, uses `chrono::Utc::now()`. Can be overridden globally via
//! [`set_time_provider`] for environments where `std::time::SystemTime` is
//! unavailable (e.g. WASM) or for deterministic testing.

use std::sync::OnceLock;

/// Trait for providing the current time.
pub trait TimeProvider: Send + Sync + 'static {
    /// Current time as milliseconds since Unix epoch.
    fn now_millis(&self) -> i64;
}

/// Default provider using `chrono`.
struct ChronoTimeProvider;

impl TimeProvider for ChronoTimeProvider {
    fn now_millis(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}

static TIME_PROVIDER: OnceLock<Box<dyn TimeProvider>> = OnceLock::new();

/// Set a custom time provider. Must be called before any time functions are used.
/// Returns `Err` if a provider has already been set.
pub fn set_time_provider(provider: impl TimeProvider) -> Result<(), &'static str> {
    TIME_PROVIDER
        .set(Box::new(provider))
        .map_err(|_| "time provider already set")
}

/// Current time in milliseconds since Unix epoch.
#[inline]
pub fn now_millis() -> i64 {
    TIME_PROVIDER
        .get_or_init(|| Box::new(ChronoTimeProvider))
        .now_millis()
}

/// Current time in seconds since Unix epoch.
#[inline]
pub fn now_secs() -> i64 {
    now_millis() / 1000
}

/// Current time as `chrono::DateTime<Utc>`.
#[inline]
pub fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(now_millis())
        .expect("time provider returned out-of-range millisecond timestamp")
}

/// Convert a Unix timestamp (seconds) to `DateTime<Utc>`.
/// Returns `None` for out-of-range values.
#[inline]
pub fn from_secs(ts: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(ts, 0)
}

/// Convert a Unix timestamp (seconds) to `DateTime<Utc>`,
/// falling back to `now_utc()` for out-of-range values.
#[inline]
pub fn from_secs_or_now(ts: i64) -> chrono::DateTime<chrono::Utc> {
    from_secs(ts).unwrap_or_else(now_utc)
}

/// Convert a Unix timestamp (milliseconds) to `DateTime<Utc>`.
/// Returns `None` for out-of-range values.
#[inline]
pub fn from_millis(ts: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_millis(ts)
}

/// Convert a Unix timestamp (milliseconds) to `DateTime<Utc>`,
/// falling back to `now_utc()` for out-of-range values.
#[inline]
pub fn from_millis_or_now(ts: i64) -> chrono::DateTime<chrono::Utc> {
    from_millis(ts).unwrap_or_else(now_utc)
}

/// Portable monotonic instant, replacing `std::time::Instant` which is
/// unavailable on `wasm32-unknown-unknown`.
///
/// Uses `now_millis()` internally — not truly monotonic but sufficient
/// for elapsed-time measurement and timeout tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(i64);

impl Instant {
    /// Capture the current instant.
    #[inline]
    pub fn now() -> Self {
        Self(now_millis())
    }

    /// Duration elapsed since this instant was captured.
    #[inline]
    pub fn elapsed(&self) -> std::time::Duration {
        let diff = now_millis().saturating_sub(self.0);
        std::time::Duration::from_millis(diff.max(0) as u64)
    }

    /// Duration from this instant until another (saturating).
    #[inline]
    pub fn saturating_duration_since(&self, earlier: Instant) -> std::time::Duration {
        let diff = self.0.saturating_sub(earlier.0);
        std::time::Duration::from_millis(diff.max(0) as u64)
    }
}

impl std::ops::Add<std::time::Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: std::time::Duration) -> Self {
        Self(self.0.saturating_add(rhs.as_millis() as i64))
    }
}

impl std::ops::Sub<Instant> for Instant {
    type Output = std::time::Duration;
    fn sub(self, rhs: Instant) -> std::time::Duration {
        self.saturating_duration_since(rhs)
    }
}
