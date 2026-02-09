//! Usync IQ specifications.
//!
//! The usync protocol is used for user synchronization operations including:
//! - Checking if phone numbers are registered on WhatsApp
//! - Fetching contact information (LID, status, picture, business status)
//! - Fetching user information by JID
//! - Fetching device lists
//!
//! ## Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="usync" type="get" to="s.whatsapp.net" id="...">
//!   <usync sid="..." mode="query" last="true" index="0" context="interactive">
//!     <query>
//!       <contact/>
//!       <lid/>
//!       <status/>
//!       <picture/>
//!       <business/>
//!     </query>
//!     <list>
//!       <user>
//!         <contact>+1234567890</contact>
//!       </user>
//!     </list>
//!   </usync>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <usync>
//!     <list>
//!       <user jid="1234567890@s.whatsapp.net">
//!         <contact type="in"/>
//!         <lid val="123456@lid"/>
//!         <status>Hello World</status>
//!         <picture id="123456789"/>
//!         <business/>
//!       </user>
//!     </list>
//!   </usync>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use anyhow::anyhow;
use log::warn;
use std::collections::HashMap;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// Usync mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsyncMode {
    /// Query mode - used for contact lookups.
    #[default]
    Query,
    /// Full mode - used for user info with more details.
    Full,
}

impl UsyncMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Full => "full",
        }
    }
}

/// Usync context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsyncContext {
    /// Interactive context - for user-initiated operations.
    #[default]
    Interactive,
    /// Background context - for background sync operations.
    Background,
    /// Message context - for message-related operations.
    Message,
}

impl UsyncContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Background => "background",
            Self::Message => "message",
        }
    }
}

/// Build user nodes with phone number contact children.
fn build_phone_user_nodes(phones: &[String]) -> Vec<Node> {
    phones
        .iter()
        .map(|phone| {
            let phone_content = if phone.starts_with('+') {
                phone.clone()
            } else {
                format!("+{}", phone)
            };
            NodeBuilder::new("user")
                .children(vec![
                    NodeBuilder::new("contact")
                        .string_content(phone_content)
                        .build(),
                ])
                .build()
        })
        .collect()
}

/// Common fields parsed from a usync user node.
struct ParsedUserFields {
    jid: Jid,
    lid: Option<Jid>,
    is_registered: bool,
    is_business: bool,
    status: Option<String>,
}

/// Parse common fields from a usync `<user>` node.
fn parse_user_common_fields(user_node: &Node) -> Option<ParsedUserFields> {
    let jid = user_node
        .attrs()
        .optional_string("jid")?
        .parse::<Jid>()
        .ok()?;

    let contact_node = user_node.get_optional_child("contact");
    let is_registered = contact_node
        .map(|c| c.attrs().optional_string("type") == Some("in"))
        .unwrap_or(false);

    let lid = user_node.get_optional_child("lid").and_then(|lid_node| {
        lid_node
            .attrs()
            .optional_string("val")
            .and_then(|val| val.parse::<Jid>().ok())
    });

    let status = user_node
        .get_optional_child("status")
        .and_then(|status_node| {
            if status_node.get_optional_child("error").is_some() {
                return None;
            }
            match &status_node.content {
                Some(NodeContent::String(s)) if !s.is_empty() => Some(s.clone()),
                _ => None,
            }
        });

    let is_business = user_node.get_optional_child("business").is_some();

    Some(ParsedUserFields {
        jid,
        lid,
        is_registered,
        is_business,
        status,
    })
}

/// Parse picture ID as u64 (used in ContactInfo).
fn parse_picture_id_u64(user_node: &Node) -> Option<u64> {
    user_node
        .get_optional_child("picture")
        .and_then(|pic_node| {
            if pic_node.get_optional_child("error").is_some() {
                return None;
            }
            pic_node.attrs().optional_u64("id")
        })
}

/// Parse picture ID as String (used in UserInfo).
fn parse_picture_id_string(user_node: &Node) -> Option<String> {
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

/// Result of checking if a phone number is on WhatsApp.
#[derive(Debug, Clone)]
pub struct IsOnWhatsAppResult {
    pub jid: Jid,
    pub is_registered: bool,
}

/// Contact information from usync.
#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub jid: Jid,
    pub lid: Option<Jid>,
    pub is_registered: bool,
    pub is_business: bool,
    pub status: Option<String>,
    pub picture_id: Option<u64>,
}

/// User information from usync.
///
/// Note: `picture_id` is `Option<String>` here vs `Option<u64>` in `ContactInfo`.
/// The server returns picture IDs in different formats depending on the usync mode:
/// - Query mode (ContactInfo): numeric ID that fits in u64
/// - Full mode (UserInfo): may include non-numeric prefixes, kept as String for safety
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub jid: Jid,
    pub lid: Option<Jid>,
    pub status: Option<String>,
    pub picture_id: Option<String>,
    pub is_business: bool,
}

/// Check if phone numbers are registered on WhatsApp.
#[derive(Debug, Clone)]
pub struct IsOnWhatsAppSpec {
    pub phones: Vec<String>,
    pub sid: String,
}

impl IsOnWhatsAppSpec {
    pub fn new(phones: Vec<String>, sid: impl Into<String>) -> Self {
        Self {
            phones,
            sid: sid.into(),
        }
    }
}

impl IqSpec for IsOnWhatsAppSpec {
    type Response = Vec<IsOnWhatsAppResult>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let query_node = NodeBuilder::new("query")
            .children(vec![NodeBuilder::new("contact").build()])
            .build();

        let user_nodes = build_phone_user_nodes(&self.phones);
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
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let usync = response
            .get_optional_child("usync")
            .ok_or_else(|| anyhow!("Response missing <usync> node"))?;

        let list = usync
            .get_optional_child("list")
            .ok_or_else(|| anyhow!("Response missing <list> node"))?;

        let mut results = Vec::new();

        for user_node in list.get_children_by_tag("user") {
            let jid_str = user_node.attrs().optional_string("jid");

            if let Some(jid_str) = jid_str
                && let Ok(jid) = jid_str.parse::<Jid>()
            {
                let contact_node = user_node.get_optional_child("contact");
                let is_registered = contact_node
                    .map(|c| c.attrs().optional_string("type") == Some("in"))
                    .unwrap_or(false);

                results.push(IsOnWhatsAppResult { jid, is_registered });
            }
        }

        Ok(results)
    }
}

/// Get contact information for phone numbers.
#[derive(Debug, Clone)]
pub struct ContactInfoSpec {
    pub phones: Vec<String>,
    pub sid: String,
}

impl ContactInfoSpec {
    pub fn new(phones: Vec<String>, sid: impl Into<String>) -> Self {
        Self {
            phones,
            sid: sid.into(),
        }
    }
}

impl IqSpec for ContactInfoSpec {
    type Response = Vec<ContactInfo>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let query_node = NodeBuilder::new("query")
            .children(vec![
                NodeBuilder::new("contact").build(),
                NodeBuilder::new("lid").build(),
                NodeBuilder::new("status").build(),
                NodeBuilder::new("picture").build(),
                NodeBuilder::new("business").build(),
            ])
            .build();

        let user_nodes = build_phone_user_nodes(&self.phones);
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
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let usync = response
            .get_optional_child("usync")
            .ok_or_else(|| anyhow!("Response missing <usync> node"))?;

        let list = usync
            .get_optional_child("list")
            .ok_or_else(|| anyhow!("Response missing <list> node"))?;

        let mut results = Vec::new();

        for user_node in list.get_children_by_tag("user") {
            if let Some(fields) = parse_user_common_fields(user_node) {
                results.push(ContactInfo {
                    jid: fields.jid,
                    lid: fields.lid,
                    is_registered: fields.is_registered,
                    is_business: fields.is_business,
                    status: fields.status,
                    picture_id: parse_picture_id_u64(user_node),
                });
            }
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
                    .attr("jid", jid.to_non_ad().to_string())
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
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
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
                    .attr("jid", jid.to_non_ad().to_string())
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
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![usync_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
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
            if user_jid.server == wacore_binary::jid::DEFAULT_USER_SERVER
                && let Some(lid_node) = user_node.get_optional_child("lid")
            {
                let lid_val = lid_node.attrs().optional_string("val").unwrap_or_default();
                if !lid_val.is_empty()
                    && let Ok(lid_jid) = lid_val.parse::<Jid>()
                    && lid_jid.server == wacore_binary::jid::HIDDEN_USER_SERVER
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

                let mut device_jid = user_jid.clone();
                device_jid.device = device_id;
                devices.push(device_jid);
            }

            device_lists.push(UserDeviceList {
                user: user_jid.to_non_ad(),
                devices,
                phash,
            });
        }

        Ok(DeviceListResponse {
            device_lists,
            lid_mappings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_is_on_whatsapp_spec_build_iq() {
        let spec = IsOnWhatsAppSpec::new(vec!["1234567890".to_string()], "test-sid");
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "usync");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            let usync = &nodes[0];
            assert_eq!(usync.tag, "usync");
            assert_eq!(
                usync.attrs.get("sid").and_then(|s| s.as_str()),
                Some("test-sid")
            );
            assert_eq!(
                usync.attrs.get("mode").and_then(|s| s.as_str()),
                Some("query")
            );
            assert_eq!(
                usync.attrs.get("context").and_then(|s| s.as_str()),
                Some("interactive")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_is_on_whatsapp_spec_parse_response() {
        let spec = IsOnWhatsAppSpec::new(vec!["1234567890".to_string()], "test-sid");

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([NodeBuilder::new("contact").attr("type", "in").build()])
                        .build()])
                    .build()])
                .build()])
            .build();

        let results = spec.parse_response(&response).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].jid.user, "1234567890");
        assert!(results[0].is_registered);
    }

    #[test]
    fn test_is_on_whatsapp_spec_parse_not_registered() {
        let spec = IsOnWhatsAppSpec::new(vec!["1234567890".to_string()], "test-sid");

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

        let results = spec.parse_response(&response).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_registered);
    }

    #[test]
    fn test_contact_info_spec_build_iq() {
        let spec = ContactInfoSpec::new(vec!["1234567890".to_string()], "test-sid");
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "usync");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let usync = &nodes[0];
            let query = usync.get_optional_child("query").unwrap();
            // Should have contact, lid, status, picture, business query fields
            assert!(query.get_optional_child("contact").is_some());
            assert!(query.get_optional_child("lid").is_some());
            assert!(query.get_optional_child("status").is_some());
            assert!(query.get_optional_child("picture").is_some());
            assert!(query.get_optional_child("business").is_some());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_contact_info_spec_parse_response() {
        let spec = ContactInfoSpec::new(vec!["1234567890".to_string()], "test-sid");

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("usync")
                .children([NodeBuilder::new("list")
                    .children([NodeBuilder::new("user")
                        .attr("jid", "1234567890@s.whatsapp.net")
                        .children([
                            NodeBuilder::new("contact").attr("type", "in").build(),
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

        let results = spec.parse_response(&response).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].jid.user, "1234567890");
        assert!(results[0].is_registered);
        assert!(results[0].is_business);
        assert_eq!(results[0].status, Some("Hello World".to_string()));
        assert_eq!(results[0].picture_id, Some(123456789));
        assert!(results[0].lid.is_some());
    }

    #[test]
    fn test_user_info_spec_build_iq() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = UserInfoSpec::new(vec![jid], "test-sid");
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "usync");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let usync = &nodes[0];
            assert_eq!(
                usync.attrs.get("mode").and_then(|s| s.as_str()),
                Some("full")
            );
            assert_eq!(
                usync.attrs.get("context").and_then(|s| s.as_str()),
                Some("background")
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

        let results = spec.parse_response(&response).unwrap();
        assert_eq!(results.len(), 1);
        let info = results.get(&jid).unwrap();
        assert_eq!(info.jid.user, "1234567890");
        assert!(info.is_business);
        assert_eq!(info.status, Some("Hello World".to_string()));
        assert_eq!(info.picture_id, Some("123456789".to_string()));
        assert!(info.lid.is_some());
    }

    #[test]
    fn test_phone_number_formatting() {
        // Without plus
        let spec1 = IsOnWhatsAppSpec::new(vec!["1234567890".to_string()], "sid");
        let iq1 = spec1.build_iq();

        // With plus
        let spec2 = IsOnWhatsAppSpec::new(vec!["+1234567890".to_string()], "sid");
        let iq2 = spec2.build_iq();

        // Both should produce the same formatted phone number with +
        if let (Some(NodeContent::Nodes(n1)), Some(NodeContent::Nodes(n2))) =
            (&iq1.content, &iq2.content)
        {
            let list1 = n1[0].get_optional_child("list").unwrap();
            let list2 = n2[0].get_optional_child("list").unwrap();
            let user1 = list1.get_children_by_tag("user").next().unwrap();
            let user2 = list2.get_children_by_tag("user").next().unwrap();
            let contact1 = user1.get_optional_child("contact").unwrap();
            let contact2 = user2.get_optional_child("contact").unwrap();

            match (&contact1.content, &contact2.content) {
                (Some(NodeContent::String(s1)), Some(NodeContent::String(s2))) => {
                    assert_eq!(s1, "+1234567890");
                    assert_eq!(s2, "+1234567890");
                }
                _ => panic!("Expected string content"),
            }
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
            assert_eq!(
                usync.attrs.get("sid").and_then(|s| s.as_str()),
                Some("test-sid")
            );
            assert_eq!(
                usync.attrs.get("mode").and_then(|s| s.as_str()),
                Some("query")
            );
            assert_eq!(
                usync.attrs.get("context").and_then(|s| s.as_str()),
                Some("message")
            );

            let query = usync.get_optional_child("query").unwrap();
            let devices = query.get_optional_child("devices").unwrap();
            assert_eq!(
                devices.attrs.get("version").and_then(|s| s.as_str()),
                Some("2")
            );
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
                            .children([NodeBuilder::new("device-list")
                                .attr("hash", "2:abcdef123456")
                                .children([
                                    NodeBuilder::new("device").attr("id", "0").build(),
                                    NodeBuilder::new("device").attr("id", "1").build(),
                                    NodeBuilder::new("device").attr("id", "5").build(),
                                ])
                                .build()])
                            .build()])
                        .build()])
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
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
                                .children([NodeBuilder::new("device-list")
                                    .attr("hash", "2:hash2")
                                    .children([
                                        NodeBuilder::new("device").attr("id", "0").build(),
                                        NodeBuilder::new("device").attr("id", "1").build(),
                                    ])
                                    .build()])
                                .build()])
                            .build(),
                    ])
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
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

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.device_lists.len(), 1);
        assert_eq!(result.lid_mappings.len(), 1);
        assert_eq!(result.lid_mappings[0].phone_number, "1234567890");
        assert_eq!(result.lid_mappings[0].lid, "100000012345678");
    }
}
