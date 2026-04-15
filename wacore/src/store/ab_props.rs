//! In-memory cache for server-side A/B experiment properties.
//!
//! Only stores props whose config_code appears in the interest set.
//! Props not in the set are discarded during parsing, avoiding heap
//! allocation for the ~1,200 props we never query.
//!
//! Not persisted — props are fetched on every connect.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use async_lock::RwLock;
use wacore_binary::CompactString;

/// In-memory cache of AB experiment properties, populated on connect.
/// Only materializes props whose config_code is registered via `watch()`.
pub struct AbPropsCache {
    props: RwLock<HashMap<u32, CompactString>>,
    /// Config codes to retain. Props not in this set are discarded.
    interest: RwLock<HashSet<u32>>,
    seeded: AtomicBool,
}

impl AbPropsCache {
    pub fn new() -> Self {
        Self {
            props: RwLock::new(HashMap::new()),
            interest: RwLock::new(HashSet::new()),
            seeded: AtomicBool::new(false),
        }
    }

    /// Register a config code to be retained when props are fetched.
    /// Call before the first `fetch_props` to ensure the value is captured.
    pub async fn watch(&self, config_code: u32) {
        self.interest.write().await.insert(config_code);
    }

    /// Register multiple config codes at once.
    pub async fn watch_many(&self, codes: &[u32]) {
        let mut interest = self.interest.write().await;
        for &code in codes {
            interest.insert(code);
        }
    }

    /// True after the first full (non-delta) update.
    pub fn is_seeded(&self) -> bool {
        self.seeded.load(Ordering::Acquire)
    }

    /// Apply a props response, retaining only watched config codes.
    pub async fn apply_props(
        &self,
        delta_update: bool,
        props: impl Iterator<Item = (u32, CompactString)>,
    ) {
        let interest = self.interest.read().await;
        let mut map = self.props.write().await;

        if !delta_update {
            map.clear();
            self.seeded.store(true, Ordering::Release);
        }

        for (code, value) in props {
            if interest.contains(&code) {
                map.insert(code, value);
            }
        }
    }

    pub async fn get(&self, config_code: u32) -> Option<CompactString> {
        self.props.read().await.get(&config_code).cloned()
    }

    /// True when the prop value is truthy (`"1"`, `"true"`, or `"enabled"`).
    pub async fn is_enabled(&self, config_code: u32) -> bool {
        self.is_enabled_or(config_code, false).await
    }

    pub async fn is_enabled_or(&self, config_code: u32, default: bool) -> bool {
        match self.props.read().await.get(&config_code) {
            Some(value) => {
                value == "1"
                    || value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("enabled")
            }
            None => default,
        }
    }

    pub async fn get_int(&self, config_code: u32, default: i64) -> i64 {
        match self.props.read().await.get(&config_code) {
            Some(value) => value.parse().unwrap_or(default),
            None => default,
        }
    }
}

impl Default for AbPropsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watched_props_are_retained() {
        let cache = AbPropsCache::new();
        cache.watch(100).await;
        cache.watch(200).await;

        let props = vec![
            (100u32, CompactString::from("1")),
            (200, CompactString::from("0")),
            (300, CompactString::from("ignored")),
        ];
        cache.apply_props(false, props.into_iter()).await;

        assert!(cache.is_seeded());
        assert_eq!(cache.get(100).await, Some(CompactString::from("1")));
        assert_eq!(cache.get(200).await, Some(CompactString::from("0")));
        assert_eq!(cache.get(300).await, None); // not watched
    }

    #[tokio::test]
    async fn is_enabled_checks_truthy_values() {
        let cache = AbPropsCache::new();
        cache.watch_many(&[1, 2, 3, 4, 5]).await;

        let props = vec![
            (1u32, CompactString::from("1")),
            (2, CompactString::from("true")),
            (3, CompactString::from("enabled")),
            (4, CompactString::from("0")),
            (5, CompactString::from("false")),
        ];
        cache.apply_props(false, props.into_iter()).await;

        assert!(cache.is_enabled(1).await);
        assert!(cache.is_enabled(2).await);
        assert!(cache.is_enabled(3).await);
        assert!(!cache.is_enabled(4).await);
        assert!(!cache.is_enabled(5).await);
        assert!(!cache.is_enabled(999).await); // absent
    }

    #[tokio::test]
    async fn delta_merges_without_clearing() {
        let cache = AbPropsCache::new();
        cache.watch_many(&[100, 200, 300]).await;

        cache
            .apply_props(
                false,
                vec![
                    (100u32, CompactString::from("old")),
                    (200, CompactString::from("keep")),
                ]
                .into_iter(),
            )
            .await;

        cache
            .apply_props(
                true,
                vec![
                    (100u32, CompactString::from("new")),
                    (300, CompactString::from("added")),
                ]
                .into_iter(),
            )
            .await;

        assert_eq!(cache.get(100).await.as_deref(), Some("new"));
        assert_eq!(cache.get(200).await.as_deref(), Some("keep"));
        assert_eq!(cache.get(300).await.as_deref(), Some("added"));
    }
}
