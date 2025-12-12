use crate::client::Client;
use crate::jid_utils::server_jid;
use log::debug;
use std::collections::{HashMap, HashSet};
use wacore_binary::jid::Jid;
use wacore_binary::node::NodeContent;

impl Client {
    pub(crate) async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        debug!("get_user_devices: Using normal mode for {jids:?}");

        let mut jids_to_fetch: HashSet<Jid> = HashSet::new();
        let mut all_devices = Vec::new();

        // 1. Check the cache first
        for jid in jids.iter().map(|j| j.to_non_ad()) {
            if let Some(cached_devices) = self.get_device_cache().await.get(&jid).await {
                all_devices.extend(cached_devices);
                continue; // Found fresh entry, skip network fetch
            }
            // Not in cache or stale, add to the fetch set (de-duplicated)
            jids_to_fetch.insert(jid);
        }

        // 2. Fetch missing JIDs from the network
        if !jids_to_fetch.is_empty() {
            debug!(
                "get_user_devices: Cache miss, fetching from network for {} unique users",
                jids_to_fetch.len()
            );

            let sid = self.generate_request_id();
            let jids_vec: Vec<Jid> = jids_to_fetch.into_iter().collect();
            let usync_node = wacore::usync::build_get_user_devices_query(&jids_vec, sid.as_str());

            let iq = crate::request::InfoQuery {
                namespace: "usync",
                query_type: crate::request::InfoQueryType::Get,
                to: server_jid(),
                content: Some(NodeContent::Nodes(vec![usync_node])),
                id: None,
                target: None,
                timeout: None,
            };
            let resp_node = self.send_iq(iq).await?;
            let fetched_devices = wacore::usync::parse_get_user_devices_response(&resp_node)?;

            // Extract and persist LID mappings from the response
            let lid_mappings = wacore::usync::parse_lid_mappings_from_response(&resp_node);
            for mapping in lid_mappings {
                self.add_lid_pn_mapping(
                    &mapping.lid,
                    &mapping.phone_number,
                    crate::lid_pn_cache::LearningSource::Usync,
                )
                .await;
                debug!(
                    "Learned LID mapping from usync: {} -> {}",
                    mapping.phone_number, mapping.lid
                );
            }

            // 3. Update the cache with the newly fetched data
            let mut devices_by_user = HashMap::new();
            for device in fetched_devices.iter() {
                let user_jid = device.to_non_ad();
                devices_by_user
                    .entry(user_jid)
                    .or_insert_with(Vec::new)
                    .push(device.clone());
            }

            for (user_jid, devices) in devices_by_user {
                self.get_device_cache()
                    .await
                    .insert(user_jid, devices)
                    .await;
            }
            all_devices.extend(fetched_devices);
        }

        Ok(all_devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_device_cache_hit() {
        // Create a mock client
        let backend = Arc::new(crate::store::SqliteStore::new(":memory:").await.unwrap())
            as Arc<dyn crate::store::traits::Backend>;
        let pm = Arc::new(
            crate::store::persistence_manager::PersistenceManager::new(backend)
                .await
                .unwrap(),
        );

        let (client, _sync_rx) = crate::client::Client::new(
            pm.clone(),
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let test_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let device_jid: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();

        // Manually insert into cache
        client
            .get_device_cache()
            .await
            .insert(test_jid.clone(), vec![device_jid.clone()])
            .await;

        // Verify cache hit
        let cached = client.get_device_cache().await.get(&test_jid).await;
        assert!(cached.is_some());
        let cached_devices = cached.unwrap();
        assert_eq!(cached_devices.len(), 1);
        assert_eq!(cached_devices[0], device_jid);
    }

    #[tokio::test]
    async fn test_cache_size_eviction() {
        use moka::future::Cache;

        // Create a small cache
        let cache: Cache<i32, String> = Cache::builder().max_capacity(2).build();

        // Insert 3 items
        cache.insert(1, "one".to_string()).await;
        cache.insert(2, "two".to_string()).await;
        cache.insert(3, "three".to_string()).await;

        // Give time for eviction to occur
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // The cache should have at most 2 items
        let count = cache.entry_count();
        assert!(
            count <= 2,
            "Cache should have at most 2 items, has {}",
            count
        );
    }

    // Mock HTTP client for tests
    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl crate::http::HttpClient for MockHttpClient {
        async fn execute(
            &self,
            _request: crate::http::HttpRequest,
        ) -> Result<crate::http::HttpResponse, anyhow::Error> {
            Err(anyhow::anyhow!("Not implemented"))
        }
    }
}
