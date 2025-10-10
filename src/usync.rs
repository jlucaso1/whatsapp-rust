use crate::client::Client;
use log::debug;
use std::collections::{HashMap, HashSet};
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::NodeContent;

impl Client {
    pub(crate) async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        debug!("get_user_devices: Using normal mode for {jids:?}");

        let mut jids_to_fetch: HashSet<Jid> = HashSet::new();
        let mut all_devices = Vec::new();

        // 1. Check the cache first
        for jid in jids.iter().map(|j| j.to_non_ad()) {
            if let Some(cached_devices) = self.device_cache.get(&jid).await {
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
                to: SERVER_JID.parse().unwrap(),
                content: Some(NodeContent::Nodes(vec![usync_node])),
                id: None,
                target: None,
                timeout: None,
            };
            let resp_node = self.send_iq(iq).await?;
            let fetched_devices = wacore::usync::parse_get_user_devices_response(&resp_node)?;

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
                self.device_cache.insert(user_jid, devices).await;
            }
            all_devices.extend(fetched_devices);
        }

        Ok(all_devices)
    }
}
