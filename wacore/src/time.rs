//! Pluggable time providers.
//!
//! Two clocks live here, kept distinct on purpose:
//!
//! - **Wall clock** ([`TimeProvider`], [`now_millis`], [`now_utc`]) — answers
//!   "what time is it?". Can jump backwards (NTP sync, manual clock changes,
//!   leap-second smearing). Resolution: milliseconds is sufficient for
//!   timestamps in stanzas, app-state mutations, and log lines.
//! - **Monotonic clock** ([`MonotonicProvider`], [`Instant`]) — answers
//!   "how much time passed?". Never moves backwards; immune to NTP
//!   adjustments. Resolution: nanoseconds where the platform supports it
//!   (`std::time::Instant` on native; sub-millisecond from `performance.now`
//!   in browsers, true ns in Node/WASI when those targets supply a custom
//!   provider).
//!
//! Conflating the two — using a wall clock to measure elapsed time — silently
//! corrupts timeouts and latency metrics whenever the system clock is adjusted
//! mid-measurement. That is why `std::time` separates `SystemTime` from
//! `Instant`, and we mirror the split here.

use std::sync::OnceLock;

/// Wall-clock provider. Returns the current Unix time. May move backwards
/// across calls when the system clock is adjusted.
pub trait TimeProvider: Send + Sync + 'static {
    /// Current time as milliseconds since Unix epoch.
    fn now_millis(&self) -> i64;
}

/// Default wall-clock provider using `chrono`.
struct ChronoTimeProvider;

impl TimeProvider for ChronoTimeProvider {
    // The single legitimate call to `chrono::Utc::now()`: this IS the default
    // provider backing `wacore::time::now_utc()`. Everywhere else must go
    // through the abstraction — see clippy.toml.
    #[allow(clippy::disallowed_methods)]
    fn now_millis(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}

static TIME_PROVIDER: OnceLock<Box<dyn TimeProvider>> = OnceLock::new();

/// Set a custom wall-clock provider. Must be called before any time function
/// is used. Returns `Err` if a provider has already been set.
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

// ---------------------------------------------------------------------------
// Monotonic clock
// ---------------------------------------------------------------------------

/// Monotonic-clock provider. Returns nanoseconds since an arbitrary fixed
/// reference; the only guarantee is that successive calls never return a
/// smaller value than a previous one.
pub trait MonotonicProvider: Send + Sync + 'static {
    /// Nanoseconds since the provider's reference point. The reference is
    /// implementation-defined (may be process start, system boot, etc.) —
    /// only differences are meaningful.
    fn now_nanos(&self) -> u64;
}

/// Native default: backed by `std::time::Instant`, which is monotonic and
/// has nanosecond resolution on every supported native platform.
#[cfg(not(target_arch = "wasm32"))]
struct StdMonotonicProvider {
    epoch: std::time::Instant,
}

#[cfg(not(target_arch = "wasm32"))]
impl StdMonotonicProvider {
    // The single legitimate call to `std::time::Instant::now()`: this IS the
    // default provider backing `wacore::time::Instant`. Everywhere else must
    // go through this abstraction — see clippy.toml.
    #[allow(clippy::disallowed_methods)]
    fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl MonotonicProvider for StdMonotonicProvider {
    fn now_nanos(&self) -> u64 {
        // Saturate at u64::MAX (584 years) — well beyond any realistic
        // process lifetime.
        self.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }
}

/// WASM fallback when no platform provider is registered. Derives nanos
/// from the wall clock and clamps to non-decreasing so the trait contract
/// holds across NTP backjumps (the value freezes until the wall clock
/// catches up). Resolution is ms × 1_000_000; embedders should register
/// a real provider via [`set_monotonic_provider`] for sub-ms precision.
#[cfg(target_arch = "wasm32")]
struct WallDerivedMonotonicProvider {
    last: std::sync::atomic::AtomicU64,
}

#[cfg(target_arch = "wasm32")]
impl WallDerivedMonotonicProvider {
    const fn new() -> Self {
        Self {
            last: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl MonotonicProvider for WallDerivedMonotonicProvider {
    fn now_nanos(&self) -> u64 {
        use std::sync::atomic::Ordering;
        let raw = (now_millis().max(0) as u64).saturating_mul(1_000_000);
        let mut last = self.last.load(Ordering::Relaxed);
        loop {
            let next = raw.max(last);
            match self
                .last
                .compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return next,
                Err(observed) => last = observed,
            }
        }
    }
}

static MONOTONIC_PROVIDER: OnceLock<Box<dyn MonotonicProvider>> = OnceLock::new();

/// Set a custom monotonic-clock provider. Must be called before any
/// [`Instant`] is captured. Returns `Err` if a provider has already been set.
pub fn set_monotonic_provider(provider: impl MonotonicProvider) -> Result<(), &'static str> {
    MONOTONIC_PROVIDER
        .set(Box::new(provider))
        .map_err(|_| "monotonic provider already set")
}

#[inline]
fn now_nanos() -> u64 {
    MONOTONIC_PROVIDER
        .get_or_init(default_monotonic_provider)
        .now_nanos()
}

#[cfg(not(target_arch = "wasm32"))]
fn default_monotonic_provider() -> Box<dyn MonotonicProvider> {
    Box::new(StdMonotonicProvider::new())
}

#[cfg(target_arch = "wasm32")]
fn default_monotonic_provider() -> Box<dyn MonotonicProvider> {
    Box::new(WallDerivedMonotonicProvider::new())
}

/// Portable monotonic instant. On native targets this wraps `std::time::Instant`
/// (via the default [`MonotonicProvider`]) and exposes nanosecond resolution.
/// On `wasm32` targets the embedder should register a sub-millisecond provider
/// via [`set_monotonic_provider`]; otherwise the fallback derives from the
/// wall clock and quantizes to milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// Capture the current monotonic instant.
    #[inline]
    pub fn now() -> Self {
        Self(now_nanos())
    }

    /// Duration elapsed since this instant was captured. Returns
    /// [`Duration::ZERO`] if the clock somehow reported a smaller value
    /// than at capture time — which a well-behaved monotonic provider
    /// must never do, but we saturate defensively.
    #[inline]
    pub fn elapsed(&self) -> std::time::Duration {
        let now = now_nanos();
        std::time::Duration::from_nanos(now.saturating_sub(self.0))
    }

    /// Duration from `earlier` to `self`. Returns [`Duration::ZERO`] if
    /// `earlier` is after `self`.
    #[inline]
    pub fn saturating_duration_since(&self, earlier: Instant) -> std::time::Duration {
        std::time::Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

impl std::ops::Add<std::time::Duration> for Instant {
    type Output = Instant;
    fn add(self, rhs: std::time::Duration) -> Self {
        let rhs_nanos: u64 = rhs.as_nanos().min(u64::MAX as u128) as u64;
        Self(self.0.saturating_add(rhs_nanos))
    }
}

impl std::ops::Sub<Instant> for Instant {
    type Output = std::time::Duration;
    fn sub(self, rhs: Instant) -> std::time::Duration {
        self.saturating_duration_since(rhs)
    }
}
