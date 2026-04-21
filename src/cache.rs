//! Unified cache type that dispatches to moka or the portable implementation
//! depending on the `moka-cache` feature flag.
//!
//! When `moka-cache` is enabled (default), [`Cache`] is `moka::future::Cache`.
//! When disabled, [`Cache`] is [`PortableCache`](crate::portable_cache::PortableCache).

#[cfg(feature = "moka-cache")]
mod inner {
    pub type Cache<K, V> = moka::future::Cache<K, V>;
}

#[cfg(not(feature = "moka-cache"))]
mod inner {
    pub type Cache<K, V> = crate::portable_cache::PortableCache<K, V>;
}

pub use inner::Cache;
