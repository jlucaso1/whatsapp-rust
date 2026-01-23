//! User device list synchronization.
//!
//! Device list IQ specification is defined in `wacore::iq::usync`.

use crate::client::Client;
use log::{debug, warn};
use std::collections::HashSet;
use wacore::iq::usync::DeviceListSpec;
use wacore_binary::jid::Jid;

impl Client {
    pub(crate) async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        debug!("get_user_devices: Using normal mode for {jids:?}");

        let mut jids_to_fetch: HashSet<Jid> = HashSet::new();
        let mut all_devices = Vec::new();

        for jid in jids.iter().map(|j| j.to_non_ad()) {
            if let Some(cached_devices) = self.get_device_cache().await.get(&jid).await {
                all_devices.extend(cached_devices);
                continue;
            }
            jids_to_fetch.insert(jid);
        }

        if !jids_to_fetch.is_empty() {
            debug!(
                "get_user_devices: Cache miss, fetching from network for {} unique users",
                jids_to_fetch.len()
            );

            let sid = self.generate_request_id();
            let jids_vec: Vec<Jid> = jids_to_fetch.into_iter().collect();
            let spec = DeviceListSpec::new(jids_vec, sid);

            let response = self.execute(spec).await?;

            // Extract and persist LID mappings from the response
            for mapping in &response.lid_mappings {
                if let Err(err) = self
                    .add_lid_pn_mapping(
                        &mapping.lid,
                        &mapping.phone_number,
                        crate::lid_pn_cache::LearningSource::Usync,
                    )
                    .await
                {
                    warn!(
                        "Failed to persist LID {} -> {} from usync: {err}",
                        mapping.lid, mapping.phone_number,
                    );
                    continue;
                }
                debug!(
                    "Learned LID mapping from usync: {} -> {}",
                    mapping.lid, mapping.phone_number
                );
            }

            for user_list in &response.device_lists {
                self.get_device_cache()
                    .await
                    .insert(user_list.user.clone(), user_list.devices.clone())
                    .await;

                // Also update device registry for hasDevice checks (matches WhatsApp Web)
                // Preserve key_index values from existing records (set via account_sync)
                let existing_key_indices: std::collections::HashMap<u32, Option<u32>> = self
                    .persistence_manager
                    .backend()
                    .get_devices(&user_list.user.user)
                    .await
                    .ok()
                    .flatten()
                    .map(|r| {
                        r.devices
                            .into_iter()
                            .map(|d| (d.device_id, d.key_index))
                            .collect()
                    })
                    .unwrap_or_default();

                let device_list = wacore::store::traits::DeviceListRecord {
                    user: user_list.user.user.clone(),
                    devices: user_list
                        .devices
                        .iter()
                        .map(|d| wacore::store::traits::DeviceInfo {
                            device_id: d.device as u32,
                            // Preserve existing key_index if we have it
                            key_index: existing_key_indices
                                .get(&(d.device as u32))
                                .copied()
                                .flatten(),
                        })
                        .collect(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                    phash: user_list.phash.clone(),
                };
                if let Err(e) = self.update_device_list(device_list).await {
                    warn!(
                        "Failed to update device registry for {}: {}",
                        user_list.user.user, e
                    );
                }
            }

            // Collect all devices for return
            let fetched_devices: Vec<Jid> = response
                .device_lists
                .into_iter()
                .flat_map(|u| u.devices)
                .collect();
            all_devices.extend(fetched_devices);
        }

        Ok(all_devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_client;

    #[tokio::test]
    async fn test_device_cache_hit() {
        let client = create_test_client().await;

        let test_jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let device_jid: Jid = "1234567890:1@s.whatsapp.net"
            .parse()
            .expect("test device JID should be valid");

        // Manually insert into cache
        client
            .get_device_cache()
            .await
            .insert(test_jid.clone(), vec![device_jid.clone()])
            .await;

        // Verify cache hit
        let cached = client.get_device_cache().await.get(&test_jid).await;
        assert!(cached.is_some());
        let cached_devices = cached.expect("cache should have entry");
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
}
