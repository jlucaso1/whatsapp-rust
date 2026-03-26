//! In-memory cache for server-side A/B experiment properties.
//!
//! Populated from [`PropsResponse`] after each `fetch_props()` call.
//! Features query this cache to check if an AB prop is enabled, matching
//! WhatsApp Web's `getABPropConfigValue()` pattern.
//!
//! Not persisted — props are fetched on every connect.

use std::collections::HashMap;

use async_lock::RwLock;

use crate::iq::props::{AbPropConfig, PropsResponse};

/// In-memory cache of AB experiment properties.
///
/// Thread-safe via `async_lock::RwLock`. Reads are cheap (no contention),
/// writes happen only during `fetch_props()` on connect.
pub struct AbPropsCache {
    /// config_code → config_value for experiment props.
    props: RwLock<HashMap<u32, String>>,
}

impl AbPropsCache {
    pub fn new() -> Self {
        Self {
            props: RwLock::new(HashMap::new()),
        }
    }

    /// Populate the cache from a server response.
    ///
    /// - **Full update** (`!delta_update`): clears existing values, then inserts all experiment props.
    /// - **Delta update** (`delta_update`): merges (overwrites) changed experiment props into existing map.
    /// - Sampling props are skipped (they are server-side analytics, not client feature flags).
    pub async fn apply_response(&self, response: &PropsResponse) {
        let mut map = self.props.write().await;

        if !response.delta_update {
            map.clear();
        }

        for prop in &response.props {
            if let AbPropConfig::Experiment(ab_prop) = prop {
                map.insert(ab_prop.config_code, ab_prop.config_value.clone());
            }
        }
    }

    /// Get the raw config value for a prop by its config code.
    pub async fn get(&self, config_code: u32) -> Option<String> {
        self.props.read().await.get(&config_code).cloned()
    }

    /// Check if a prop is enabled (truthy).
    ///
    /// Returns `true` if the value is `"1"`, `"true"`, or `"enabled"` (case-insensitive).
    /// Returns `false` if the prop is absent, empty, or has any other value.
    pub async fn is_enabled(&self, config_code: u32) -> bool {
        match self.props.read().await.get(&config_code) {
            Some(value) => matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "enabled"
            ),
            None => false,
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
    use crate::iq::props::{AbProp, AbPropConfig, PropsResponse, SamplingProp};

    fn make_response(delta: bool, props: Vec<AbPropConfig>) -> PropsResponse {
        PropsResponse {
            delta_update: delta,
            props,
            ..Default::default()
        }
    }

    fn experiment(code: u32, value: &str) -> AbPropConfig {
        AbPropConfig::Experiment(AbProp {
            config_code: code,
            config_value: value.to_string(),
            config_expo_key: None,
        })
    }

    fn sampling(code: u32, weight: i32) -> AbPropConfig {
        AbPropConfig::Sampling(SamplingProp {
            event_code: code,
            sampling_weight: weight,
        })
    }

    #[tokio::test]
    async fn full_update_replaces_all_props() {
        let cache = AbPropsCache::new();

        // Initial full update
        cache
            .apply_response(&make_response(
                false,
                vec![experiment(100, "1"), experiment(200, "0")],
            ))
            .await;
        assert_eq!(cache.get(100).await, Some("1".into()));
        assert_eq!(cache.get(200).await, Some("0".into()));

        // Second full update replaces everything
        cache
            .apply_response(&make_response(false, vec![experiment(300, "enabled")]))
            .await;
        assert_eq!(cache.get(100).await, None);
        assert_eq!(cache.get(200).await, None);
        assert_eq!(cache.get(300).await, Some("enabled".into()));
    }

    #[tokio::test]
    async fn delta_update_merges_props() {
        let cache = AbPropsCache::new();

        cache
            .apply_response(&make_response(
                false,
                vec![experiment(100, "1"), experiment(200, "old")],
            ))
            .await;

        // Delta update: changes 200, adds 300, leaves 100 untouched
        cache
            .apply_response(&make_response(
                true,
                vec![experiment(200, "new"), experiment(300, "1")],
            ))
            .await;

        assert_eq!(cache.get(100).await, Some("1".into()));
        assert_eq!(cache.get(200).await, Some("new".into()));
        assert_eq!(cache.get(300).await, Some("1".into()));
    }

    #[tokio::test]
    async fn sampling_props_are_skipped() {
        let cache = AbPropsCache::new();
        cache
            .apply_response(&make_response(
                false,
                vec![experiment(100, "1"), sampling(5138, -1)],
            ))
            .await;
        assert_eq!(cache.get(100).await, Some("1".into()));
        assert_eq!(cache.get(5138).await, None);
    }

    #[tokio::test]
    async fn is_enabled_checks_truthy_values() {
        let cache = AbPropsCache::new();
        cache
            .apply_response(&make_response(
                false,
                vec![
                    experiment(1, "1"),
                    experiment(2, "true"),
                    experiment(3, "True"),
                    experiment(4, "enabled"),
                    experiment(5, "ENABLED"),
                    experiment(6, "0"),
                    experiment(7, "false"),
                    experiment(8, ""),
                    experiment(9, "other"),
                ],
            ))
            .await;

        assert!(cache.is_enabled(1).await);
        assert!(cache.is_enabled(2).await);
        assert!(cache.is_enabled(3).await);
        assert!(cache.is_enabled(4).await);
        assert!(cache.is_enabled(5).await);
        assert!(!cache.is_enabled(6).await);
        assert!(!cache.is_enabled(7).await);
        assert!(!cache.is_enabled(8).await);
        assert!(!cache.is_enabled(9).await);
        assert!(!cache.is_enabled(999).await); // absent
    }
}
