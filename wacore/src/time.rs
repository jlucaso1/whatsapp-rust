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
