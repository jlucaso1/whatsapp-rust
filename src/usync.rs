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
        let mut jids_to_fetch: HashSet<Jid> = HashSet::with_capacity(jids.len());
        let mut all_devices = Vec::with_capacity(jids.len() * 2);

        for jid in jids.iter().map(|j| j.to_non_ad()) {
            // Device registry (in-memory cache + DB) is the single source of truth
            if let Some(devices) = self.get_devices_from_registry(&jid).await {
                all_devices.extend(devices);
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
                // Update device registry (single source of truth for device lists).
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
                    timestamp: wacore::time::now_secs(),
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
    use wacore::store::traits::{DeviceInfo, DeviceListRecord};

    #[tokio::test]
    async fn test_device_registry_hit_resolves_devices() {
        let client = create_test_client().await;

        let user_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();

        // Insert a device record into the registry (simulates prior usync/notification)
        let record = DeviceListRecord {
            user: "1234567890".into(),
            devices: vec![
                DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                DeviceInfo {
                    device_id: 3,
                    key_index: Some(10),
                },
            ],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client.update_device_list(record).await.unwrap();

        // get_user_devices should resolve from registry without network
        let devices = client.get_user_devices(&[user_jid]).await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|d| d.device == 0));
        assert!(devices.iter().any(|d| d.device == 3));
        assert!(devices.iter().all(|d| d.is_pn()));
    }

    #[tokio::test]
    async fn test_device_registry_hit_for_lid_jid() {
        let client = create_test_client().await;

        let lid_jid: Jid = "100000012345678@lid".parse().unwrap();

        let record = DeviceListRecord {
            user: "100000012345678".into(),
            devices: vec![
                DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                DeviceInfo {
                    device_id: 39,
                    key_index: Some(25),
                },
            ],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client.update_device_list(record).await.unwrap();

        let devices = client.get_user_devices(&[lid_jid]).await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|d| d.device == 0));
        assert!(devices.iter().any(|d| d.device == 39));
        assert!(devices.iter().all(|d| d.is_lid()));
    }

    #[tokio::test]
    async fn test_device_registry_db_fallback() {
        let client = create_test_client().await;

        let user_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        // Insert into backend DB via update_device_list
        let record = DeviceListRecord {
            user: "9876543210".into(),
            devices: vec![DeviceInfo {
                device_id: 5,
                key_index: None,
            }],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client.update_device_list(record).await.unwrap();

        // Evict from registry cache to force DB path
        client.device_registry_cache.invalidate("9876543210").await;
        client.device_registry_cache.run_pending_tasks().await;

        // Should still resolve from DB
        let devices = client.get_user_devices(&[user_jid]).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device, 5);
    }

    #[tokio::test]
    async fn test_cache_size_eviction() {
        use crate::cache::Cache;

        let cache: Cache<i32, String> = Cache::builder().max_capacity(2).build();

        cache.insert(1, "one".to_string()).await;
        cache.insert(2, "two".to_string()).await;
        cache.insert(3, "three".to_string()).await;

        cache.run_pending_tasks().await;

        let count = cache.entry_count();
        assert!(
            count <= 2,
            "Cache should have at most 2 items, has {}",
            count
        );
    }
}
