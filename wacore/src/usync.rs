use anyhow::{Result, anyhow};
use wacore_binary::Jid;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Node, NodeRef};

/// A LID mapping learned from usync response
#[derive(Debug, Clone)]
pub struct UsyncLidMapping {
    /// The phone number user part (e.g., "559980000001")
    pub phone_number: wacore_binary::CompactString,
    /// The LID user part (e.g., "100000012345678")
    pub lid: wacore_binary::CompactString,
}

#[derive(Debug, Clone)]
pub struct UsyncDevice {
    pub device: u16,
    pub key_index: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct UserDeviceList {
    pub user: Jid,
    pub devices: Vec<UsyncDevice>,
    pub phash: Option<String>,
    pub key_index_bytes: Option<Vec<u8>>,
}

pub fn build_get_user_devices_query(jids: &[Jid], sid: &str) -> Node {
    let user_nodes = jids
        .iter()
        .map(|jid| {
            NodeBuilder::new("user")
                .attr("jid", jid.to_non_ad())
                .build()
        })
        .collect::<Vec<_>>();

    let query_node = NodeBuilder::new("query")
        .children([NodeBuilder::new("devices").attr("version", "2").build()])
        .build();

    let list_node = NodeBuilder::new("list").children(user_nodes).build();

    NodeBuilder::new("usync")
        .attrs([
            ("context", "message"),
            ("index", "0"),
            ("last", "true"),
            ("mode", "query"),
            ("sid", sid),
        ])
        .children([query_node, list_node])
        .build()
}

/// Parse usync response returning devices grouped by user with phash.
/// This is the full-featured version that includes the participant hash.
pub fn parse_get_user_devices_response_with_phash(resp_node: &Node) -> Result<Vec<UserDeviceList>> {
    let list_node = resp_node
        .get_optional_child_by_tag(&["usync", "list"])
        .ok_or_else(|| anyhow!("<usync> or <list> not found in usync response"))?;

    let mut result = Vec::new();

    for user_node in list_node.get_children_by_tag("user") {
        let user_jid = user_node.attrs().jid("jid");
        let device_list_node = user_node
            .get_optional_child_by_tag(&["devices", "device-list"])
            .ok_or_else(|| anyhow!("<device-list> not found for user {user_jid}"))?;

        // Extract phash from device-list node attributes
        let phash = device_list_node
            .attrs()
            .optional_string("hash")
            .map(|s| s.to_string());

        // Parse key-index-list from <devices> node (sibling of <device-list>)
        // WA Web: WAWebUsyncDevice.deviceParser() extracts both deviceList and keyIndex
        let devices_parent = user_node.get_optional_child("devices");
        let key_index_bytes = devices_parent
            .and_then(|dp| dp.get_optional_child("key-index-list"))
            .and_then(|ki| match &ki.content {
                Some(wacore_binary::NodeContent::Bytes(b)) if !b.is_empty() => Some(b.clone()),
                _ => None,
            });

        let mut devices = Vec::new();
        for device_node in device_list_node.get_children_by_tag("device") {
            let device_id_str = match device_node.attrs().optional_string("id") {
                Some(id) => id,
                None => {
                    log::warn!(target: "usync", "device node missing 'id' attribute, skipping");
                    continue;
                }
            };
            let device_id: u16 = match device_id_str.parse() {
                Ok(id) => id,
                Err(_) => {
                    log::warn!(target: "usync", "invalid device id '{device_id_str}' for user {user_jid}, skipping");
                    continue;
                }
            };

            let key_index = device_node
                .attrs()
                .optional_string("key-index")
                .and_then(|s| s.parse::<u32>().ok());
            devices.push(UsyncDevice {
                device: device_id,
                key_index,
            });
        }

        // WA Web: WAWebHandleAdvForUsyncApi.handleADVSyncResult() rejects usync results
        // that have companion devices but no signedKeyIndexBytes.
        let has_companion = devices.iter().any(|d| d.device != 0);
        if has_companion && key_index_bytes.is_none() {
            log::warn!(
                target: "usync",
                "User {user_jid} has companion devices but no signedKeyIndexBytes, skipping"
            );
            continue;
        }

        result.push(UserDeviceList {
            user: user_jid.to_non_ad(),
            devices,
            phash,
            key_index_bytes,
        });
    }

    Ok(result)
}

/// Parse usync response returning a flat list of device JIDs.
/// This is a convenience wrapper around `parse_get_user_devices_response_with_phash`.
pub fn parse_get_user_devices_response(resp_node: &Node) -> Result<Vec<Jid>> {
    Ok(parse_get_user_devices_response_with_phash(resp_node)?
        .into_iter()
        .flat_map(|u| {
            let user_jid = u.user;
            u.devices.into_iter().map(move |d| {
                let mut jid = user_jid.clone();
                jid.device = d.device;
                jid
            })
        })
        .collect())
}

/// Parse LID mappings from a usync `NodeRef` response (zero-copy path).
pub fn parse_lid_mappings_from_response(resp_node: &NodeRef<'_>) -> Vec<UsyncLidMapping> {
    let mut mappings = Vec::new();

    let list_node = match resp_node.get_optional_child_by_tag(&["usync", "list"]) {
        Some(node) => node,
        None => return mappings,
    };

    for user_node in list_node.get_children_by_tag("user") {
        let user_jid_str = match user_node.attrs().optional_string("jid") {
            Some(jid) => jid,
            None => continue,
        };
        let user_jid: Jid = match user_jid_str.parse() {
            Ok(j) => j,
            Err(_) => continue,
        };

        if user_jid.server != wacore_binary::Server::Pn {
            continue;
        }

        if let Some(lid_node) = user_node.get_optional_child("lid") {
            let lid_val = match lid_node.attrs().optional_string("val") {
                Some(v) => v,
                None => continue,
            };
            if !lid_val.is_empty()
                && let Ok(lid_jid) = lid_val.parse::<Jid>()
                && lid_jid.server == wacore_binary::Server::Lid
            {
                mappings.push(UsyncLidMapping {
                    phone_number: user_jid.user.clone(),
                    lid: lid_jid.user.clone(),
                });
            }
        }
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    /// Helper to build a usync response node for testing.
    /// The structure matches actual server responses:
    /// <iq> (wrapper - this is resp_node)
    ///   <usync>
    ///     <list>
    ///       <user jid="...">
    ///         <devices>
    ///           <device-list hash="...">
    ///             <device id="0" />
    ///           </device-list>
    ///         </devices>
    ///       </user>
    ///     </list>
    ///   </usync>
    /// </iq>
    /// Build dummy ADV signed key index bytes for tests.
    fn build_test_key_index_bytes(device_ids: &[u16]) -> Vec<u8> {
        use prost::Message;
        let valid_indexes: Vec<u32> = device_ids.iter().map(|&id| id as u32).collect();
        let key_index = waproto::whatsapp::AdvKeyIndexList {
            raw_id: Some(1),
            timestamp: Some(1000),
            current_index: Some(valid_indexes.iter().copied().max().unwrap_or(0)),
            valid_indexes,
            account_type: None,
        };
        let signed = waproto::whatsapp::AdvSignedKeyIndexList {
            details: Some(key_index.encode_to_vec()),
            account_signature: None,
            account_signature_key: None,
        };
        signed.encode_to_vec()
    }

    fn build_usync_response(users: Vec<(&str, Vec<u16>, Option<&str>)>) -> Node {
        let user_nodes: Vec<Node> = users
            .into_iter()
            .map(|(jid, device_ids, phash)| {
                let device_nodes: Vec<Node> = device_ids
                    .iter()
                    .map(|id| {
                        NodeBuilder::new("device")
                            .attr("id", id.to_string())
                            .build()
                    })
                    .collect();

                let mut device_list_builder = NodeBuilder::new("device-list");
                if let Some(hash) = phash {
                    device_list_builder = device_list_builder.attr("hash", hash);
                }
                let device_list = device_list_builder.children(device_nodes).build();

                // Add key-index-list if there are companion devices
                let has_companion = device_ids.iter().any(|&id| id != 0);
                let mut devices_children = vec![device_list];
                if has_companion {
                    let ki_bytes = build_test_key_index_bytes(&device_ids);
                    devices_children.push(
                        NodeBuilder::new("key-index-list")
                            .attr("ts", "1000")
                            .bytes(ki_bytes)
                            .build(),
                    );
                }

                let devices_node = NodeBuilder::new("devices")
                    .children(devices_children)
                    .build();

                NodeBuilder::new("user")
                    .attr("jid", jid)
                    .children([devices_node])
                    .build()
            })
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();
        let usync_node = NodeBuilder::new("usync").children([list_node]).build();
        // Wrap in an outer node (like IQ response) since the parser looks for usync as a child
        NodeBuilder::new("iq").children([usync_node]).build()
    }

    #[test]
    fn test_parse_with_phash_single_user() {
        let response = build_usync_response(vec![(
            "1234567890@s.whatsapp.net",
            vec![0, 1, 2],
            Some("2:abcdef123456"),
        )]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user.user, "1234567890");
        assert_eq!(result[0].devices.len(), 3);
        assert_eq!(result[0].phash, Some("2:abcdef123456".to_string()));
    }

    #[test]
    fn test_parse_with_phash_multiple_users() {
        let response = build_usync_response(vec![
            ("1111111111@s.whatsapp.net", vec![0, 1], Some("2:hash1")),
            ("2222222222@s.whatsapp.net", vec![0], Some("2:hash2")),
            (
                "3333333333@s.whatsapp.net",
                vec![0, 1, 2, 3],
                Some("2:hash3"),
            ),
        ]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        assert_eq!(result.len(), 3);

        assert_eq!(result[0].user.user, "1111111111");
        assert_eq!(result[0].devices.len(), 2);
        assert_eq!(result[0].phash, Some("2:hash1".to_string()));

        assert_eq!(result[1].user.user, "2222222222");
        assert_eq!(result[1].devices.len(), 1);
        assert_eq!(result[1].phash, Some("2:hash2".to_string()));

        assert_eq!(result[2].user.user, "3333333333");
        assert_eq!(result[2].devices.len(), 4);
        assert_eq!(result[2].phash, Some("2:hash3".to_string()));
    }

    #[test]
    fn test_parse_without_phash() {
        let response = build_usync_response(vec![(
            "1234567890@s.whatsapp.net",
            vec![0, 1],
            None, // No phash
        )]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user.user, "1234567890");
        assert_eq!(result[0].devices.len(), 2);
        assert_eq!(result[0].phash, None);
    }

    #[test]
    fn test_parse_mixed_phash_presence() {
        let response = build_usync_response(vec![
            ("1111111111@s.whatsapp.net", vec![0], Some("2:hasphash")),
            ("2222222222@s.whatsapp.net", vec![0, 1], None), // No phash
        ]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].phash, Some("2:hasphash".to_string()));
        assert_eq!(result[1].phash, None);
    }

    #[test]
    fn test_parse_device_ids_correct() {
        let response = build_usync_response(vec![(
            "1234567890@s.whatsapp.net",
            vec![0, 5, 10],
            Some("2:test"),
        )]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        assert_eq!(result[0].devices.len(), 3);
        assert_eq!(result[0].devices[0].device, 0);
        assert_eq!(result[0].devices[1].device, 5);
        assert_eq!(result[0].devices[2].device, 10);
    }

    #[test]
    fn test_backward_compat_flat_list() {
        let response = build_usync_response(vec![
            ("1111111111@s.whatsapp.net", vec![0, 1], Some("2:hash1")),
            ("2222222222@s.whatsapp.net", vec![0], None),
        ]);

        // The backward-compatible function should return a flat list
        let result = parse_get_user_devices_response(&response).unwrap();

        assert_eq!(result.len(), 3); // 2 + 1 devices total
        assert_eq!(result[0].user, "1111111111");
        assert_eq!(result[0].device, 0);
        assert_eq!(result[1].user, "1111111111");
        assert_eq!(result[1].device, 1);
        assert_eq!(result[2].user, "2222222222");
        assert_eq!(result[2].device, 0);
    }

    #[test]
    fn test_user_jid_normalized_to_non_ad() {
        // Test with a JID that has a device suffix - should be normalized
        let response = build_usync_response(vec![(
            "1234567890:5@s.whatsapp.net", // With device suffix
            vec![0, 1],
            Some("2:test"),
        )]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        // The user JID should be normalized (no device suffix)
        assert_eq!(result[0].user.device, 0);
        assert_eq!(result[0].user.user, "1234567890");
    }

    #[test]
    fn test_empty_device_list() {
        let response = build_usync_response(vec![(
            "1234567890@s.whatsapp.net",
            vec![], // No devices
            Some("2:empty"),
        )]);

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].devices.len(), 0);
        assert_eq!(result[0].phash, Some("2:empty".to_string()));
    }

    #[test]
    fn test_server_returned_key_index_is_parsed() {
        // Build a response where devices have key-index attributes
        // (matches real server: <device id="4" key-index="93"/>)
        let device_nodes: Vec<Node> = vec![
            NodeBuilder::new("device").attr("id", "0").build(),
            NodeBuilder::new("device")
                .attr("id", "4")
                .attr("key-index", "93")
                .build(),
            NodeBuilder::new("device")
                .attr("id", "24")
                .attr("key-index", "113")
                .build(),
        ];

        let ki_bytes = build_test_key_index_bytes(&[0, 4, 24]);
        let device_list = NodeBuilder::new("device-list")
            .children(device_nodes)
            .build();
        let devices_node = NodeBuilder::new("devices")
            .children(vec![
                device_list,
                NodeBuilder::new("key-index-list")
                    .attr("ts", "1000")
                    .bytes(ki_bytes)
                    .build(),
            ])
            .build();

        let user_node = NodeBuilder::new("user")
            .attr("jid", "559900001111@s.whatsapp.net")
            .children(vec![devices_node])
            .build();

        let response = NodeBuilder::new("iq")
            .children(vec![
                NodeBuilder::new("usync")
                    .children(vec![
                        NodeBuilder::new("list").children(vec![user_node]).build(),
                    ])
                    .build(),
            ])
            .build();

        let result = parse_get_user_devices_response_with_phash(&response).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].devices.len(), 3);

        // Device 0: no key-index attribute → None
        assert_eq!(result[0].devices[0].device, 0);
        assert_eq!(result[0].devices[0].key_index, None);

        // Device 4: key-index="93"
        assert_eq!(result[0].devices[1].device, 4);
        assert_eq!(result[0].devices[1].key_index, Some(93));

        // Device 24: key-index="113"
        assert_eq!(result[0].devices[2].device, 24);
        assert_eq!(result[0].devices[2].key_index, Some(113));
    }
}
