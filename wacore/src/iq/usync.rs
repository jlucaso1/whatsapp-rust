//! Usync IQ specifications.
//!
//! The usync protocol is used for user synchronization operations including:
//! - Checking if phone numbers or LIDs are registered on WhatsApp
//! - Fetching user information by JID
//! - Fetching device lists
//!
//! ## Wire Format
//! ```xml
//! <!-- Request (phone number query) -->
//! <iq xmlns="usync" type="get" to="s.whatsapp.net" id="...">
//!   <usync sid="..." mode="query" last="true" index="0" context="interactive">
//!     <query>
//!       <contact/>
//!       <lid/>
//!       <business><verified_name/></business>
//!     </query>
//!     <list>
//!       <user>
//!         <contact>+1234567890</contact>
//!       </user>
//!     </list>
//!   </usync>
//! </iq>
//!
//! <!-- Request (LID query) -->
//! <iq xmlns="usync" type="get" to="s.whatsapp.net" id="...">
//!   <usync sid="..." mode="query" last="true" index="0" context="interactive">
//!     <query>
//!       <lid/>
//!       <business><verified_name/></business>
//!     </query>
//!     <list>
//!       <user jid="100000001@lid"/>
//!     </list>
//!   </usync>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <usync>
//!     <list>
//!       <user jid="1234567890@s.whatsapp.net" pn_jid="1234567890@s.whatsapp.net">
//!         <contact type="in"/>
//!         <lid val="100000001@lid"/>
//!         <business/>
//!       </user>
//!     </list>
//!   </usync>
//! </iq>
//! ```

use crate::WireEnum;
use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use anyhow::anyhow;
use log::warn;
use std::collections::HashMap;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Server};
use wacore_binary::{Node, NodeContent, NodeContentRef, NodeRef};

/// Usync mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, WireEnum)]
pub enum UsyncMode {
    /// Query mode - used for contact lookups.
    #[wire_default]
    #[wire = "query"]
    Query,
    /// Full mode - used for user info with more details.
    #[wire = "full"]
    Full,
}

/// Usync context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, WireEnum)]
pub enum UsyncContext {
    /// Interactive context - for user-initiated operations.
    #[wire_default]
    #[wire = "interactive"]
    Interactive,
    /// Background context - for background sync operations.
    #[wire = "background"]
    Background,
    /// Message context - for message-related operations.
    #[wire = "message"]
    Message,
}

#[derive(Debug, Clone)]
pub struct IsOnWhatsAppUser {
    pub jid: Jid,
    /// Helps server optimize the lookup (WA Web pre-populates this from its LID cache).
    pub known_lid: Option<String>,
}

fn build_user_nodes(users: &[IsOnWhatsAppUser]) -> Vec<Node> {
    users
        .iter()
        .map(|user| {
            if user.jid.is_pn() {
                let phone = if user.jid.user.starts_with('+') {
                    user.jid.user.to_string()
                } else {
                    format!("+{}", user.jid.user)
                };
                let mut children = vec![NodeBuilder::new("contact").string_content(phone).build()];
                if let Some(lid) = &user.known_lid {
                    children.push(NodeBuilder::new("lid").attr("jid", Jid::lid(lid)).build());
                }
                NodeBuilder::new("user").children(children).build()
            } else {
                NodeBuilder::new("user")
                    .attr("jid", user.jid.to_non_ad())
                    .build()
            }
        })
        .collect()
}

/// Parse LID JID from a `<lid val="..."/>` child node.
fn parse_lid_jid(user_node: &NodeRef<'_>) -> Option<Jid> {
    user_node.get_optional_child("lid").and_then(|lid_node| {
        lid_node
            .attrs()
            .optional_string("val")
            .and_then(|val| val.parse::<Jid>().ok())
    })
}

/// Common fields parsed from a usync `<user>` node.
struct ParsedUserFields {
    jid: Jid,
    lid: Option<Jid>,
    is_business: bool,
    status: Option<String>,
}

/// Parse common fields from a usync `<user>` node.
fn parse_user_common_fields(user_node: &NodeRef<'_>) -> Option<ParsedUserFields> {
    let jid = user_node
        .attrs()
        .optional_string("jid")?
        .parse::<Jid>()
        .ok()?;

    let lid = parse_lid_jid(user_node);

    let status = user_node
        .get_optional_child("status")
        .and_then(|status_node| {
            if status_node.get_optional_child("error").is_some() {
                return None;
            }
            match status_node.content.as_deref() {
                Some(NodeContentRef::String(s)) if !s.is_empty() => Some(s.to_string()),
                _ => None,
            }
        });

    let is_business = user_node.get_optional_child("business").is_some();

    Some(ParsedUserFields {
        jid,
        lid,
        is_business,
        status,
    })
}

/// Parse picture ID as String (used in UserInfo).
fn parse_picture_id_string(user_node: &NodeRef<'_>) -> Option<String> {
    user_node
        .get_optional_child("picture")
        .and_then(|pic_node| {
            if pic_node.get_optional_child("error").is_some() {
                return None;
            }
            pic_node
                .attrs()
                .optional_string("id")
                .map(|s| s.to_string())
        })
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IsOnWhatsAppResult {
    pub jid: Jid,
    pub lid: Option<Jid>,
    /// From `pn_jid` response attribute; present when server returns LID as primary JID.
    pub pn_jid: Option<Jid>,
    pub is_registered: bool,
    pub is_business: bool,
}

/// User information from usync.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub jid: Jid,
    pub lid: Option<Jid>,
    pub status: Option<String>,
    pub picture_id: Option<String>,
    pub is_business: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsOnWhatsAppQueryType {
    /// PN query: `<contact/>` + `<lid/>` + `<business><verified_name/></business>`.
    Pn,
    /// LID query: `<lid/>` + `<business><verified_name/></business>` (no contact).
    Lid,
}

/// Check if JIDs are registered on WhatsApp.
///
/// Query protocols differ by type:
/// - PN: `<contact/>`, `<lid/>`, `<business><verified_name/></business>`
/// - LID: `<lid/>`, `<business><verified_name/></business>`
#[derive(Debug, Clone)]
pub struct IsOnWhatsAppSpec {
    pub users: Vec<IsOnWhatsAppUser>,
    pub sid: String,
    pub query_type: IsOnWhatsAppQueryType,
}

impl IsOnWhatsAppSpec {
    pub fn new(
        users: Vec<IsOnWhatsAppUser>,
        sid: impl Into<String>,
        query_type: IsOnWhatsAppQueryType,
    ) -> Self {
        Self {
            users,
            sid: sid.into(),
            query_type,
        }
    }
}

fn build_business_query_node() -> Node {
    NodeBuilder::new("business")
        .children(vec![NodeBuilder::new("verified_name").build()])
        .build()
}

/// Check `<usync><result>` for per-protocol errors.
fn check_usync_result_errors(usync: &NodeRef<'_>) -> Result<(), anyhow::Error> {
    let Some(result_node) = usync.get_optional_child("result") else {
        return Ok(());
    };
    for tag in ["contact", "lid", "business"] {
        if let Some(protocol_node) = result_node.get_optional_child(tag)
            && let Some(error_node) = protocol_node.get_optional_child("error")
        {
            let code = error_node
                .attrs()
                .optional_string("code")
                .unwrap_or_default();
            let text = error_node
                .attrs()
                .optional_string("text")
                .unwrap_or_default();
            return Err(anyhow!("usync {tag} error {code}: {text}"));
        }
    }
    Ok(())
}

impl IqSpec for IsOnWhatsAppSpec {
    type Response = Vec<IsOnWhatsAppResult>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let mut query_children = Vec::new();
        if self.query_type == IsOnWhatsAppQueryType::Pn {
            query_children.push(NodeBuilder::new("contact").build());
        }
        query_children.push(NodeBuilder::new("lid").build());
        query_children.push(build_business_query_node());

        let query_node = NodeBuilder::new("query").children(query_children).build();

        let user_nodes = build_user_nodes(&self.users);
        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", self.sid.as_str())
            .attr("mode", UsyncMode::Query.as_str())
            .attr("last", "true")
            .attr("index", "0")
            .attr("context", UsyncContext::Interactive.as_str())
            .children(vec![query_node, list_node])
            .build();

        InfoQuery::get(
            "usync",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        let usync = response
            .get_optional_child("usync")
            .ok_or_else(|| anyhow!("Response missing <usync> node"))?;

        check_usync_result_errors(usync)?;

        let list = usync
            .get_optional_child("list")
            .ok_or_else(|| anyhow!("Response missing <list> node"))?;

        let mut results = Vec::new();

        for user_node in list.get_children_by_tag("user") {
            let Some(jid_str) = user_node.attrs().optional_string("jid") else {
                continue;
            };
            let Ok(jid) = jid_str.parse::<Jid>() else {
                continue;
            };

            let pn_jid = user_node
                .attrs()
                .optional_string("pn_jid")
                .and_then(|s| s.parse::<Jid>().ok());

            let lid = parse_lid_jid(user_node);

            let contact_node = user_node.get_optional_child("contact");
            // LID queries omit contact protocol; presence in response implies registered
            let is_registered = if jid.is_lid() && contact_node.is_none() {
                true
            } else {
                contact_node
                    .map(|c| c.get_attr("type").is_some_and(|v| v.as_str() == "in"))
                    .unwrap_or(false)
            };

            let is_business = user_node.get_optional_child("business").is_some();

            results.push(IsOnWhatsAppResult {
                jid,
                lid,
                pn_jid,
                is_registered,
                is_business,
            });
        }

        Ok(results)
    }
}

/// Get user information by JID.
#[derive(Debug, Clone)]
pub struct UserInfoSpec {
    pub jids: Vec<Jid>,
    pub sid: String,
}

impl UserInfoSpec {
    pub fn new(jids: Vec<Jid>, sid: impl Into<String>) -> Self {
        Self {
            jids,
            sid: sid.into(),
        }
    }
}

impl IqSpec for UserInfoSpec {
    type Response = HashMap<Jid, UserInfo>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let query_node = NodeBuilder::new("query")
            .children(vec![
                NodeBuilder::new("business")
                    .children(vec![NodeBuilder::new("verified_name").build()])
                    .build(),
                NodeBuilder::new("status").build(),
                NodeBuilder::new("picture").build(),
                NodeBuilder::new("devices").attr("version", "2").build(),
                NodeBuilder::new("lid").build(),
            ])
            .build();

        let user_nodes: Vec<Node> = self
            .jids
            .iter()
            .map(|jid| {
                NodeBuilder::new("user")
                    .attr("jid", jid.to_non_ad())
                    .build()
            })
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", self.sid.as_str())
            .attr("mode", UsyncMode::Full.as_str())
            .attr("last", "true")
            .attr("index", "0")
            .attr("context", UsyncContext::Background.as_str())
            .children(vec![query_node, list_node])
            .build();

        InfoQuery::get(
            "usync",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        let usync = response
            .get_optional_child("usync")
            .ok_or_else(|| anyhow!("Response missing <usync> node"))?;

        let list = usync
            .get_optional_child("list")
            .ok_or_else(|| anyhow!("Response missing <list> node"))?;

        let mut results = HashMap::new();

        for user_node in list.get_children_by_tag("user") {
            if let Some(fields) = parse_user_common_fields(user_node) {
                results.insert(
                    fields.jid.clone(),
                    UserInfo {
                        jid: fields.jid,
                        lid: fields.lid,
                        status: fields.status,
                        picture_id: parse_picture_id_string(user_node),
                        is_business: fields.is_business,
                    },
                );
            }
        }

        Ok(results)
    }
}

// Re-export types from wacore::usync for convenience
pub use crate::usync::{UserDeviceList, UsyncLidMapping};

/// Response from device list query containing device lists and any LID mappings.
#[derive(Debug, Clone)]
pub struct DeviceListResponse {
    pub device_lists: Vec<UserDeviceList>,
    pub lid_mappings: Vec<UsyncLidMapping>,
}

/// Get device list for JIDs.
///
/// ## Wire Format
/// ```xml
/// <!-- Request -->
/// <iq xmlns="usync" type="get" to="s.whatsapp.net" id="...">
///   <usync sid="..." mode="query" last="true" index="0" context="message">
///     <query>
///       <devices version="2"/>
///     </query>
///     <list>
///       <user jid="1234567890@s.whatsapp.net"/>
///     </list>
///   </usync>
/// </iq>
///
/// <!-- Response -->
/// <iq from="s.whatsapp.net" id="..." type="result">
///   <usync>
///     <list>
///       <user jid="1234567890@s.whatsapp.net">
///         <devices>
///           <device-list hash="2:abcdef123456">
///             <device id="0"/>
///             <device id="1"/>
///           </device-list>
///         </devices>
///       </user>
///     </list>
///   </usync>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct DeviceListSpec {
    pub jids: Vec<Jid>,
    pub sid: String,
}

impl DeviceListSpec {
    pub fn new(jids: Vec<Jid>, sid: impl Into<String>) -> Self {
        Self {
            jids,
            sid: sid.into(),
        }
    }
}

impl IqSpec for DeviceListSpec {
    type Response = DeviceListResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let query_node = NodeBuilder::new("query")
            .children(vec![
                NodeBuilder::new("devices").attr("version", "2").build(),
            ])
            .build();

        let user_nodes: Vec<Node> = self
            .jids
            .iter()
            .map(|jid| {
                NodeBuilder::new("user")
                    .attr("jid", jid.to_non_ad())
                    .build()
            })
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", self.sid.as_str())
            .attr("mode", UsyncMode::Query.as_str())
            .attr("last", "true")
            .attr("index", "0")
            .attr("context", UsyncContext::Message.as_str())
            .children(vec![query_node, list_node])
            .build();

        InfoQuery::get(
            "usync",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        let list_node = response
            .get_optional_child_by_tag(&["usync", "list"])
            .ok_or_else(|| anyhow!("<usync> or <list> not found in usync response"))?;

        let mut device_lists = Vec::new();
        let mut lid_mappings = Vec::new();

        for user_node in list_node.get_children_by_tag("user") {
            let user_jid = user_node
                .attrs()
                .optional_jid("jid")
                .ok_or_else(|| anyhow!("user node missing required 'jid' attribute"))?;

            // Extract LID mapping if present
            if user_jid.server == wacore_binary::Server::Pn
                && let Some(lid_node) = user_node.get_optional_child("lid")
            {
                let lid_val = lid_node.attrs().optional_string("val").unwrap_or_default();
                if !lid_val.is_empty()
                    && let Ok(lid_jid) = lid_val.parse::<Jid>()
                    && lid_jid.server == wacore_binary::Server::Lid
                {
                    lid_mappings.push(UsyncLidMapping {
                        phone_number: user_jid.user.clone(),
                        lid: lid_jid.user.clone(),
                    });
                }
            }

            // Extract device list - skip user if not present
            let device_list_node = match user_node
                .get_optional_child_by_tag(&["devices", "device-list"])
            {
                Some(node) => node,
                None => {
                    warn!(target: "usync", "<device-list> not found for user {user_jid}, skipping");
                    continue;
                }
            };

            // Extract phash from device-list node attributes
            let phash = device_list_node
                .attrs()
                .optional_string("hash")
                .map(|s| s.to_string());

            // Parse key-index-list from <devices> node
            let devices_parent = user_node.get_optional_child("devices");
            let key_index_bytes = devices_parent
                .and_then(|dp| dp.get_optional_child("key-index-list"))
                .and_then(|ki| match ki.content.as_deref() {
                    Some(NodeContentRef::Bytes(b)) if !b.is_empty() => Some(b.to_vec()),
                    _ => None,
                });

            let mut devices = Vec::new();
            for device_node in device_list_node.get_children_by_tag("device") {
                let Some(device_id_str) = device_node.attrs().optional_string("id") else {
                    warn!(target: "usync", "device node missing 'id' attribute for user {user_jid}, skipping device");
                    continue;
                };
                let Ok(device_id) = device_id_str.parse::<u16>() else {
                    warn!(target: "usync", "invalid device id '{}' for user {user_jid}, skipping device", device_id_str);
                    continue;
                };

                let key_index = device_node
                    .attrs()
                    .optional_string("key-index")
                    .and_then(|s| s.parse::<u32>().ok());
                devices.push(crate::usync::UsyncDevice {
                    device: device_id,
                    key_index,
                });
            }

            let has_companion = devices.iter().any(|d| d.device != 0);
            if has_companion && key_index_bytes.is_none() {
                warn!(
                    target: "usync",
                    "User {user_jid} has companion devices but no signedKeyIndexBytes, skipping"
                );
                continue;
            }

            device_lists.push(UserDeviceList {
                user: user_jid.to_non_ad(),
                devices,
                phash,
                key_index_bytes,
            });
        }

        Ok(DeviceListResponse {
            device_lists,
            lid_mappings,
        })
    }
}

/// Resolve PN→LID mappings for JIDs without a known LID.
/// Matches WA Web's `ensurePhoneNumberToLidMapping` (PhoneNumberMappingJob.js).
/// Uses a separate usync with only `<lid/>` in the query to avoid side effects
/// on device registries or sender key state.
#[derive(Debug, Clone)]
pub struct LidQuerySpec {
    pub jids: Vec<Jid>,
    pub sid: String,
}

impl LidQuerySpec {
    pub fn new(jids: Vec<Jid>, sid: impl Into<String>) -> Self {
        Self {
            jids,
            sid: sid.into(),
        }
    }
}

/// Response: just the LID mappings learned.
#[derive(Debug, Clone)]
pub struct LidQueryResponse {
    pub lid_mappings: Vec<UsyncLidMapping>,
}

impl IqSpec for LidQuerySpec {
    type Response = LidQueryResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let query_node = NodeBuilder::new("query")
            .children(vec![NodeBuilder::new("lid").build()])
            .build();

        let user_nodes: Vec<Node> = self
            .jids
            .iter()
            .map(|jid| {
                NodeBuilder::new("user")
                    .attr("jid", jid.to_non_ad())
                    .build()
            })
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", self.sid.as_str())
            .attr("mode", UsyncMode::Query.as_str())
            .attr("last", "true")
            .attr("index", "0")
            // WA Web ContactSyncApi uses "background" for LID resolution
            .attr("context", UsyncContext::Background.as_str())
            .children(vec![query_node, list_node])
            .build();

        InfoQuery::get(
            "usync",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        let usync = response
            .get_optional_child("usync")
            .ok_or_else(|| anyhow!("LID query response missing <usync> node"))?;
        check_usync_result_errors(usync)?;
        usync
            .get_optional_child("list")
            .ok_or_else(|| anyhow!("LID query response missing <list> node"))?;

        let lid_mappings = crate::usync::parse_lid_mappings_from_response(response);
        Ok(LidQueryResponse { lid_mappings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a dummy key-index-list node for device IDs (used in test fixtures)
    fn build_test_key_index_list_node(device_ids: &[u16]) -> Node {
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
        NodeBuilder::new("key-index-list")
            .attr("ts", "1000")
            .bytes(signed.encode_to_vec())
            .build()
    }

    #[test]
    fn test_usync_mode() {
        assert_eq!(UsyncMode::Query.as_str(), "query");
        assert_eq!(UsyncMode::Full.as_str(), "full");
    }

    #[test]
    fn test_usync_context() {
        assert_eq!(UsyncContext::Interactive.as_str(), "interactive");
        assert_eq!(UsyncContext::Background.as_str(), "background");
        assert_eq!(UsyncContext::Message.as_str(), "message");
    }

    fn pn_user(phone: &str) -> IsOnWhatsAppUser {
        IsOnWhatsAppUser {
            jid: Jid::pn(phone),
            known_lid: None,
        }
    }

    #[test]
    fn test_is_on_whatsapp_spec_build_iq() {
        let spec = IsOnWhatsAppSpec::new(
            vec![pn_user("1234567890")],
            "test-sid",
            IsOnWhatsAppQueryType::Pn,
        );
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "usync");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            let usync = &nodes[0];
            assert_eq!(usync.tag, "usync");
            assert!(usync.attrs.get("sid").is_some_and(|s| s == "test-sid"));
            assert!(usync.attrs.get("mode").is_some_and(|s| s == "query"));
            assert!(
                usync
                    .attrs
                    .get("context")
                    .is_some_and(|s| s == "interactive")
            );

            let query = usync.get_optional_child("query").unwrap();
            assert!(query.get_optional_child("contact").is_some());
            assert!(query.get_optional_child("lid").is_some());
            assert!(query.get_optional_child("business").is_some());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_is_on_whatsapp_spec_build_iq_lid() {
        let spec = IsOnWhatsAppSpec::new(
            vec![IsOnWhatsAppUser {
                jid: Jid::lid("100000001"),
                known_lid: None,
            }],
            "test-sid",
            IsOnWhatsAppQueryType::Lid,
        );
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let usync = &nodes[0];
            let query = usync.get_optional_child("query").unwrap();
            assert!(query.get_optional_child("contact").is_none());
            assert!(query.get_optional_child("lid").is_some());
            assert!(query.get_optional_child("business").is_some());

            let list = usync.get_optional_child("list").unwrap();
            let user = list.get_children_by_tag("user").next().unwrap();
            assert!(user.attrs.get("jid").is_some_and(|s| s == "100000001@lid"));
            assert!(user.get_optional_child("contact").is_none());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_is_on_whatsapp_spec_build_iq_with_known_lid() {
        let spec = IsOnWhatsAppSpec::new(
            vec![IsOnWhatsAppUser {
                jid: Jid::pn("1234567890"),
                known_lid: Some("100000001".to_string()),
            }],
            "sid",
            IsOnWhatsAppQueryType::Pn,
        );
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let list = nodes[0].get_optional_child("list").unwrap();
            let user = list.get_children_by_tag("user").next().unwrap();
            let lid_child = user.get_optional_child("lid").unwrap();
            assert!(
                lid_child
                    .attrs
                    .get("jid")
                    .is_some_and(|s| s == "100000001@lid")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_is_on_whatsapp_spec_parse_response() {
        let spec = IsOnWhatsAppSpec::new(
            vec![pn_user("1234567890")],
            "test-sid",
            IsOnWhatsAppQueryType::Pn,
        );

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([
                            NodeBuilder::new("contact").attr("type", "in").build(),
                            NodeBuilder::new("lid").attr("val", "100000001@lid").build(),
                            NodeBuilder::new("business").build(),
                        ])
                        .build()])
                    .build()])
                .build()])
            .build();

        let results = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].jid.user, "1234567890");
        assert!(results[0].is_registered);
        assert!(results[0].is_business);
        assert!(results[0].lid.is_some());
        assert_eq!(results[0].lid.as_ref().unwrap().user, "100000001");
    }

    #[test]
    fn test_is_on_whatsapp_spec_parse_not_registered() {
        let spec = IsOnWhatsAppSpec::new(
            vec![pn_user("1234567890")],
            "test-sid",
            IsOnWhatsAppQueryType::Pn,
        );

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([NodeBuilder::new("contact").attr("type", "out").build()])
                        .build()])
                    .build()])
                .build()])
            .build();

        let results = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_registered);
        assert!(!results[0].is_business);
        assert!(results[0].lid.is_none());
    }

    #[test]
    fn test_is_on_whatsapp_spec_parse_pn_jid() {
        let spec = IsOnWhatsAppSpec::new(
            vec![IsOnWhatsAppUser {
                jid: Jid::lid("100000001"),
                known_lid: None,
            }],
            "test-sid",
            IsOnWhatsAppQueryType::Lid,
        );

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "100000001@lid")
                        .attr("pn_jid", "1234567890@s.whatsapp.net")
                        .build()])
                    .build()])
                .build()])
            .build();

        let results = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].jid.user, "100000001");
        assert!(results[0].jid.is_lid());
        // LID query with no contact node: presence implies registration
        assert!(results[0].is_registered);
        assert_eq!(results[0].pn_jid.as_ref().unwrap().user, "1234567890");
    }

    #[test]
    fn test_user_info_spec_build_iq() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = UserInfoSpec::new(vec![jid], "test-sid");
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "usync");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let usync = &nodes[0];
            assert!(usync.attrs.get("mode").is_some_and(|s| s == "full"));
            assert!(
                usync
                    .attrs
                    .get("context")
                    .is_some_and(|s| s == "background")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_user_info_spec_parse_response() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = UserInfoSpec::new(vec![jid.clone()], "test-sid");

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([
                            NodeBuilder::new("lid").attr("val", "100000001@lid").build(),
                            NodeBuilder::new("status")
                                .string_content("Hello World")
                                .build(),
                            NodeBuilder::new("picture").attr("id", "123456789").build(),
                            NodeBuilder::new("business").build(),
                        ])
                        .build()])
                    .build()])
                .build()])
            .build();

        let results = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(results.len(), 1);
        let info = results.get(&jid).unwrap();
        assert_eq!(info.jid.user, "1234567890");
        assert!(info.is_business);
        assert_eq!(info.status, Some("Hello World".to_string()));
        assert_eq!(info.picture_id, Some("123456789".to_string()));
        assert!(info.lid.is_some());
    }

    #[test]
    fn test_pn_user_phone_formatting() {
        // PN JIDs always have the user part without +, build_user_nodes adds +
        let spec = IsOnWhatsAppSpec::new(
            vec![pn_user("1234567890")],
            "sid",
            IsOnWhatsAppQueryType::Pn,
        );
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let list = nodes[0].get_optional_child("list").unwrap();
            let user = list.get_children_by_tag("user").next().unwrap();
            let contact = user.get_optional_child("contact").unwrap();

            match &contact.content {
                Some(NodeContent::String(s)) => assert_eq!(s, "+1234567890"),
                _ => panic!("Expected string content"),
            }
            // PN user nodes should NOT have a jid attribute
            assert!(user.attrs.get("jid").is_none());
        }
    }

    #[test]
    fn test_device_list_spec_build_iq() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = DeviceListSpec::new(vec![jid], "test-sid");
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "usync");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let usync = &nodes[0];
            assert!(usync.attrs.get("sid").is_some_and(|s| s == "test-sid"));
            assert!(usync.attrs.get("mode").is_some_and(|s| s == "query"));
            assert!(usync.attrs.get("context").is_some_and(|s| s == "message"));

            let query = usync.get_optional_child("query").unwrap();
            let devices = query.get_optional_child("devices").unwrap();
            assert!(devices.attrs.get("version").is_some_and(|s| s == "2"));
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_device_list_spec_parse_response() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = DeviceListSpec::new(vec![jid], "test-sid");

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([NodeBuilder::new("devices")
                            .children([
                                NodeBuilder::new("device-list")
                                    .attr("hash", "2:abcdef123456")
                                    .children([
                                        NodeBuilder::new("device").attr("id", "0").build(),
                                        NodeBuilder::new("device").attr("id", "1").build(),
                                        NodeBuilder::new("device").attr("id", "5").build(),
                                    ])
                                    .build(),
                                build_test_key_index_list_node(&[0, 1, 5]),
                            ])
                            .build()])
                        .build()])
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result.device_lists.len(), 1);
        assert_eq!(result.device_lists[0].user.user, "1234567890");
        assert_eq!(result.device_lists[0].devices.len(), 3);
        assert_eq!(result.device_lists[0].devices[0].device, 0);
        assert_eq!(result.device_lists[0].devices[1].device, 1);
        assert_eq!(result.device_lists[0].devices[2].device, 5);
        assert_eq!(
            result.device_lists[0].phash,
            Some("2:abcdef123456".to_string())
        );
        assert!(result.lid_mappings.is_empty());
    }

    #[test]
    fn test_device_list_spec_parse_response_multiple_users() {
        let jid1: Jid = "1111111111@s.whatsapp.net".parse().unwrap();
        let jid2: Jid = "2222222222@s.whatsapp.net".parse().unwrap();
        let spec = DeviceListSpec::new(vec![jid1, jid2], "test-sid");

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([
                        NodeBuilder::new("user")
                            .attr("jid", "1111111111@s.whatsapp.net")
                            .children([NodeBuilder::new("devices")
                                .children([NodeBuilder::new("device-list")
                                    .attr("hash", "2:hash1")
                                    .children([NodeBuilder::new("device").attr("id", "0").build()])
                                    .build()])
                                .build()])
                            .build(),
                        NodeBuilder::new("user")
                            .attr("jid", "2222222222@s.whatsapp.net")
                            .children([NodeBuilder::new("devices")
                                .children([
                                    NodeBuilder::new("device-list")
                                        .attr("hash", "2:hash2")
                                        .children([
                                            NodeBuilder::new("device").attr("id", "0").build(),
                                            NodeBuilder::new("device").attr("id", "1").build(),
                                        ])
                                        .build(),
                                    build_test_key_index_list_node(&[0, 1]),
                                ])
                                .build()])
                            .build(),
                    ])
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result.device_lists.len(), 2);
        assert_eq!(result.device_lists[0].user.user, "1111111111");
        assert_eq!(result.device_lists[0].devices.len(), 1);
        assert_eq!(result.device_lists[0].phash, Some("2:hash1".to_string()));
        assert_eq!(result.device_lists[1].user.user, "2222222222");
        assert_eq!(result.device_lists[1].devices.len(), 2);
        assert_eq!(result.device_lists[1].phash, Some("2:hash2".to_string()));
    }

    #[test]
    fn test_device_list_spec_parse_response_with_lid() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = DeviceListSpec::new(vec![jid], "test-sid");

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([
                            NodeBuilder::new("lid")
                                .attr("val", "100000012345678@lid")
                                .build(),
                            NodeBuilder::new("devices")
                                .children([NodeBuilder::new("device-list")
                                    .attr("hash", "2:abcdef")
                                    .children([NodeBuilder::new("device").attr("id", "0").build()])
                                    .build()])
                                .build(),
                        ])
                        .build()])
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result.device_lists.len(), 1);
        assert_eq!(result.lid_mappings.len(), 1);
        assert_eq!(result.lid_mappings[0].phone_number, "1234567890");
        assert_eq!(result.lid_mappings[0].lid, "100000012345678");
    }
}
