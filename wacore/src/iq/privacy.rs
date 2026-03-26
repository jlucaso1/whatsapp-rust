//! Privacy settings IQ specification.
//!
//! Fetches and sets the user's privacy settings.
//!
//! ## Wire Format
//! ```xml
//! <!-- GET request -->
//! <iq xmlns="privacy" type="get" to="s.whatsapp.net" id="...">
//!   <privacy/>
//! </iq>
//!
//! <!-- GET response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <privacy>
//!     <category name="last" value="all"/>
//!     <category name="online" value="all"/>
//!     <category name="profile" value="contacts"/>
//!     <category name="status" value="contacts"/>
//!     <category name="groupadd" value="contacts"/>
//!     <category name="readreceipts" value="all"/>
//!     <category name="calladd" value="all"/>
//!     <category name="messages" value="all"/>
//!     <category name="defense" value="off"/>
//!     ...
//!   </privacy>
//! </iq>
//!
//! <!-- SET request (simple) -->
//! <iq xmlns="privacy" type="set" to="s.whatsapp.net" id="...">
//!   <privacy>
//!     <category name="{category}" value="{value}"/>
//!   </privacy>
//! </iq>
//!
//! <!-- SET request (with disallowed list, LID addressing) -->
//! <iq xmlns="privacy" type="set" to="s.whatsapp.net" id="...">
//!   <privacy addressing_mode="lid">
//!     <category name="{category}" value="contact_blacklist" dhash="{hash}">
//!       <user action="add" jid="{lid}" pn_jid="{pn}"/>
//!       <user action="remove" jid="{lid}" pn_jid="{pn}"/>
//!     </category>
//!   </privacy>
//! </iq>
//! ```
//!
//! Verified against WhatsApp Web JS:
//! - `WAWebQueryPrivacySettingsJob` (GET parsing)
//! - `WAWebSetPrivacyJob` (SET building)
//! - `WAWebPrivacySettings` (value enums)
//! - `WAWebSchemaPrivacyDisallowedList` (disallowed list types)

use crate::StringEnum;
use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for privacy settings.
pub const PRIVACY_NAMESPACE: &str = "privacy";

#[derive(Debug, Clone, PartialEq, Eq, StringEnum)]
pub enum PrivacyCategory {
    /// Last seen visibility (`all | contacts | contact_blacklist | none`)
    #[str = "last"]
    Last,
    /// Online status visibility (`all | match_last_seen`)
    #[str = "online"]
    Online,
    /// Profile photo visibility (`all | contacts | contact_blacklist | none`)
    #[str = "profile"]
    Profile,
    /// About/status text visibility (`all | contacts | contact_blacklist | none`)
    #[str = "status"]
    Status,
    /// Group add permissions (`all | contacts | contact_blacklist | none`)
    #[str = "groupadd"]
    GroupAdd,
    /// Read receipts (`all | none`)
    #[str = "readreceipts"]
    ReadReceipts,
    /// Call add permissions (`all | known | contacts`)
    #[str = "calladd"]
    CallAdd,
    /// Message permissions / anti-brigading (`all | contacts`)
    #[str = "messages"]
    Messages,
    /// Defense mode (`off | on_standard`)
    #[str = "defense"]
    DefenseMode,
    #[string_fallback]
    Other(String),
}

impl PrivacyCategory {
    /// Check whether a value is valid for this category per `WAWebPrivacySettings`.
    pub fn is_valid_value(&self, value: &PrivacyValue) -> bool {
        match self {
            Self::Last | Self::Profile | Self::Status | Self::GroupAdd => matches!(
                value,
                PrivacyValue::All
                    | PrivacyValue::Contacts
                    | PrivacyValue::ContactBlacklist
                    | PrivacyValue::None
            ),
            Self::ReadReceipts => matches!(value, PrivacyValue::All | PrivacyValue::None),
            Self::Online => matches!(value, PrivacyValue::All | PrivacyValue::MatchLastSeen),
            Self::CallAdd => matches!(
                value,
                PrivacyValue::All | PrivacyValue::Known | PrivacyValue::Contacts
            ),
            Self::Messages => matches!(value, PrivacyValue::All | PrivacyValue::Contacts),
            Self::DefenseMode => matches!(value, PrivacyValue::Off | PrivacyValue::OnStandard),
            // Unknown categories: allow anything
            Self::Other(_) => true,
        }
    }

    /// Whether this category supports disallowed lists (`contact_blacklist` with user list).
    pub fn supports_disallowed_list(&self) -> bool {
        matches!(
            self,
            Self::Last | Self::Profile | Self::Status | Self::GroupAdd
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, StringEnum)]
pub enum PrivacyValue {
    #[str = "all"]
    All,
    #[str = "contacts"]
    Contacts,
    #[str = "none"]
    None,
    #[str = "contact_blacklist"]
    ContactBlacklist,
    #[str = "match_last_seen"]
    MatchLastSeen,
    /// `calladd` only
    #[str = "known"]
    Known,
    /// `defense` only
    #[str = "off"]
    Off,
    /// `defense` only
    #[str = "on_standard"]
    OnStandard,
    #[string_fallback]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct PrivacySetting {
    pub category: PrivacyCategory,
    pub value: PrivacyValue,
}

#[derive(Debug, Clone, Default)]
pub struct PrivacySettingsResponse {
    pub settings: Vec<PrivacySetting>,
}

impl PrivacySettingsResponse {
    /// Get a privacy setting by category.
    pub fn get(&self, category: &PrivacyCategory) -> Option<&PrivacySetting> {
        self.settings.iter().find(|s| &s.category == category)
    }

    /// Get the value for a category.
    pub fn get_value(&self, category: &PrivacyCategory) -> Option<&PrivacyValue> {
        self.get(category).map(|s| &s.value)
    }
}

/// Fetches privacy settings from the server.
#[derive(Debug, Clone, Default)]
pub struct PrivacySettingsSpec;

impl PrivacySettingsSpec {
    /// Create a new privacy settings spec.
    pub fn new() -> Self {
        Self
    }
}

impl IqSpec for PrivacySettingsSpec {
    type Response = PrivacySettingsResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get(
            PRIVACY_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("privacy").build(),
            ])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        use crate::iq::node::{optional_attr, required_child};

        let privacy_node = required_child(response, "privacy")?;

        let mut settings = Vec::new();
        for child in privacy_node.get_children_by_tag("category") {
            let name = optional_attr(child, "name")
                .ok_or_else(|| anyhow::anyhow!("missing name in category"))?;
            let value = optional_attr(child, "value")
                .ok_or_else(|| anyhow::anyhow!("missing value in category"))?;

            settings.push(PrivacySetting {
                category: PrivacyCategory::from(name.as_ref()),
                value: PrivacyValue::from(value.as_ref()),
            });
        }

        Ok(PrivacySettingsResponse { settings })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum DisallowedListAction {
    #[string_default]
    #[str = "add"]
    Add,
    #[str = "remove"]
    Remove,
}

#[derive(Debug, Clone)]
pub struct DisallowedListUserEntry {
    pub action: DisallowedListAction,
    pub jid: Jid,
    pub pn_jid: Option<Jid>,
}

/// Update for the `contact_blacklist` disallowed list (user exclusions).
#[derive(Debug, Clone)]
pub struct DisallowedListUpdate {
    /// Hash of the current disallowed list for conflict detection (409 handling).
    /// Server returns updated dhash in the response.
    pub dhash: String,
    /// User additions/removals.
    pub users: Vec<DisallowedListUserEntry>,
}

#[derive(Debug, Clone)]
pub struct SetPrivacySettingSpec {
    pub category: PrivacyCategory,
    pub value: PrivacyValue,
    pub disallowed_list: Option<DisallowedListUpdate>,
}

impl SetPrivacySettingSpec {
    pub fn new(category: PrivacyCategory, value: PrivacyValue) -> Self {
        debug_assert!(
            category.is_valid_value(&value),
            "{:?} does not accept {:?}",
            category,
            value
        );
        Self {
            category,
            value,
            disallowed_list: None,
        }
    }

    /// Automatically sets the value to `ContactBlacklist`.
    pub fn with_disallowed_list(category: PrivacyCategory, update: DisallowedListUpdate) -> Self {
        debug_assert!(
            category.supports_disallowed_list(),
            "{:?} does not support disallowed lists",
            category
        );
        Self {
            category,
            value: PrivacyValue::ContactBlacklist,
            disallowed_list: Some(update),
        }
    }
}

impl IqSpec for SetPrivacySettingSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let mut category_node = NodeBuilder::new("category")
            .attr("name", self.category.as_str())
            .attr("value", self.value.as_str());

        let mut privacy_node = NodeBuilder::new("privacy");

        if let Some(ref update) = self.disallowed_list {
            category_node = category_node.attr("dhash", &*update.dhash);

            let user_nodes: Vec<Node> = update
                .users
                .iter()
                .map(|entry| {
                    let mut user = NodeBuilder::new("user")
                        .attr("action", entry.action.as_str())
                        .attr("jid", entry.jid.clone());
                    if let Some(ref pn) = entry.pn_jid {
                        user = user.attr("pn_jid", pn.clone());
                    }
                    user.build()
                })
                .collect();

            category_node = category_node.children(user_nodes);
            // LID addressing mode per WAWebSetPrivacyJob function `f`
            privacy_node = privacy_node.attr("addressing_mode", "lid");
        }

        InfoQuery::set(
            PRIVACY_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![
                privacy_node.children([category_node.build()]).build(),
            ])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        Ok(())
    }
}

/// Set the default disappearing messages duration.
///
/// ```xml
/// <iq xmlns="disappearing_mode" type="set" to="s.whatsapp.net">
///   <disappearing_mode duration="{seconds}"/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetDefaultDisappearingModeSpec {
    pub duration: u32,
}

impl SetDefaultDisappearingModeSpec {
    pub fn new(duration: u32) -> Self {
        Self { duration }
    }
}

impl IqSpec for SetDefaultDisappearingModeSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set(
            "disappearing_mode",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("disappearing_mode")
                    .attr("duration", self.duration.to_string())
                    .build(),
            ])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[test]
    fn test_privacy_settings_spec_build_iq() {
        let spec = PrivacySettingsSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, PRIVACY_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "privacy");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_privacy_settings_spec_parse_response() {
        let spec = PrivacySettingsSpec::new();
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("privacy")
                .children([
                    NodeBuilder::new("category")
                        .attr("name", "last")
                        .attr("value", "all")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "profile")
                        .attr("value", "contacts")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "status")
                        .attr("value", "none")
                        .build(),
                ])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.settings.len(), 3);

        assert_eq!(result.settings[0].category, PrivacyCategory::Last);
        assert_eq!(result.settings[0].value, PrivacyValue::All);

        assert_eq!(result.settings[1].category, PrivacyCategory::Profile);
        assert_eq!(result.settings[1].value, PrivacyValue::Contacts);

        assert_eq!(result.settings[2].category, PrivacyCategory::Status);
        assert_eq!(result.settings[2].value, PrivacyValue::None);
    }

    #[test]
    fn test_parse_all_categories_from_server() {
        let spec = PrivacySettingsSpec::new();
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("privacy")
                .children([
                    NodeBuilder::new("category")
                        .attr("name", "last")
                        .attr("value", "all")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "online")
                        .attr("value", "match_last_seen")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "profile")
                        .attr("value", "contact_blacklist")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "status")
                        .attr("value", "contacts")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "groupadd")
                        .attr("value", "contacts")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "readreceipts")
                        .attr("value", "none")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "calladd")
                        .attr("value", "known")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "messages")
                        .attr("value", "contacts")
                        .build(),
                    NodeBuilder::new("category")
                        .attr("name", "defense")
                        .attr("value", "off")
                        .build(),
                ])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.settings.len(), 9);

        assert_eq!(result.settings[0].category, PrivacyCategory::Last);
        assert_eq!(result.settings[0].value, PrivacyValue::All);

        assert_eq!(result.settings[1].category, PrivacyCategory::Online);
        assert_eq!(result.settings[1].value, PrivacyValue::MatchLastSeen);

        assert_eq!(result.settings[2].category, PrivacyCategory::Profile);
        assert_eq!(result.settings[2].value, PrivacyValue::ContactBlacklist);

        assert_eq!(result.settings[3].category, PrivacyCategory::Status);
        assert_eq!(result.settings[3].value, PrivacyValue::Contacts);

        assert_eq!(result.settings[4].category, PrivacyCategory::GroupAdd);
        assert_eq!(result.settings[4].value, PrivacyValue::Contacts);

        assert_eq!(result.settings[5].category, PrivacyCategory::ReadReceipts);
        assert_eq!(result.settings[5].value, PrivacyValue::None);

        assert_eq!(result.settings[6].category, PrivacyCategory::CallAdd);
        assert_eq!(result.settings[6].value, PrivacyValue::Known);

        assert_eq!(result.settings[7].category, PrivacyCategory::Messages);
        assert_eq!(result.settings[7].value, PrivacyValue::Contacts);

        assert_eq!(result.settings[8].category, PrivacyCategory::DefenseMode);
        assert_eq!(result.settings[8].value, PrivacyValue::Off);
    }

    #[test]
    fn test_privacy_settings_response_get() {
        let response = PrivacySettingsResponse {
            settings: vec![
                PrivacySetting {
                    category: PrivacyCategory::Last,
                    value: PrivacyValue::All,
                },
                PrivacySetting {
                    category: PrivacyCategory::Profile,
                    value: PrivacyValue::Contacts,
                },
            ],
        };

        assert_eq!(
            response.get_value(&PrivacyCategory::Last),
            Some(&PrivacyValue::All)
        );
        assert_eq!(
            response.get_value(&PrivacyCategory::Profile),
            Some(&PrivacyValue::Contacts)
        );
        assert_eq!(response.get_value(&PrivacyCategory::Online), None);
    }

    // --- StringEnum conversion tests ---

    #[test]
    fn test_privacy_category_from_str() {
        assert_eq!(PrivacyCategory::from("last"), PrivacyCategory::Last);
        assert_eq!(PrivacyCategory::from("online"), PrivacyCategory::Online);
        assert_eq!(PrivacyCategory::from("profile"), PrivacyCategory::Profile);
        assert_eq!(PrivacyCategory::from("status"), PrivacyCategory::Status);
        assert_eq!(PrivacyCategory::from("groupadd"), PrivacyCategory::GroupAdd);
        assert_eq!(
            PrivacyCategory::from("readreceipts"),
            PrivacyCategory::ReadReceipts
        );
        assert_eq!(PrivacyCategory::from("calladd"), PrivacyCategory::CallAdd);
        assert_eq!(PrivacyCategory::from("messages"), PrivacyCategory::Messages);
        assert_eq!(
            PrivacyCategory::from("defense"),
            PrivacyCategory::DefenseMode
        );
        assert_eq!(
            PrivacyCategory::from("unknown"),
            PrivacyCategory::Other("unknown".to_string())
        );
    }

    #[test]
    fn test_privacy_value_from_str() {
        assert_eq!(PrivacyValue::from("all"), PrivacyValue::All);
        assert_eq!(PrivacyValue::from("contacts"), PrivacyValue::Contacts);
        assert_eq!(PrivacyValue::from("none"), PrivacyValue::None);
        assert_eq!(
            PrivacyValue::from("contact_blacklist"),
            PrivacyValue::ContactBlacklist
        );
        assert_eq!(
            PrivacyValue::from("match_last_seen"),
            PrivacyValue::MatchLastSeen
        );
        assert_eq!(PrivacyValue::from("known"), PrivacyValue::Known);
        assert_eq!(PrivacyValue::from("off"), PrivacyValue::Off);
        assert_eq!(PrivacyValue::from("on_standard"), PrivacyValue::OnStandard);
        assert_eq!(
            PrivacyValue::from("unknown"),
            PrivacyValue::Other("unknown".to_string())
        );
    }

    // --- SET spec tests ---

    fn attr_str<'a>(node: &'a Node, key: &str) -> Option<Cow<'a, str>> {
        crate::iq::node::optional_attr(node, key)
    }

    #[test]
    fn test_set_privacy_simple_build_iq() {
        let spec = SetPrivacySettingSpec::new(PrivacyCategory::Last, PrivacyValue::Contacts);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, PRIVACY_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        let nodes = match &iq.content {
            Some(NodeContent::Nodes(n)) => n,
            _ => panic!("Expected NodeContent::Nodes"),
        };
        let privacy_node = &nodes[0];
        assert_eq!(privacy_node.tag, "privacy");
        assert!(attr_str(privacy_node, "addressing_mode").is_none());

        let categories: Vec<&Node> = privacy_node.get_children_by_tag("category").collect();
        assert_eq!(categories.len(), 1);
        assert_eq!(attr_str(categories[0], "name").as_deref(), Some("last"));
        assert_eq!(
            attr_str(categories[0], "value").as_deref(),
            Some("contacts")
        );
        assert!(attr_str(categories[0], "dhash").is_none());
    }

    #[test]
    fn test_set_privacy_with_disallowed_list_build_iq() {
        let spec = SetPrivacySettingSpec::with_disallowed_list(
            PrivacyCategory::Profile,
            DisallowedListUpdate {
                dhash: "abc123".to_string(),
                users: vec![
                    DisallowedListUserEntry {
                        action: DisallowedListAction::Add,
                        jid: Jid::new("100000000000001", "lid"),
                        pn_jid: Some(Jid::new("5511999999999", "s.whatsapp.net")),
                    },
                    DisallowedListUserEntry {
                        action: DisallowedListAction::Remove,
                        jid: Jid::new("100000000000002", "lid"),
                        pn_jid: None,
                    },
                ],
            },
        );
        let iq = spec.build_iq();

        let nodes = match &iq.content {
            Some(NodeContent::Nodes(n)) => n,
            _ => panic!("Expected NodeContent::Nodes"),
        };
        let privacy_node = &nodes[0];
        assert_eq!(privacy_node.tag, "privacy");
        assert_eq!(
            attr_str(privacy_node, "addressing_mode").as_deref(),
            Some("lid")
        );

        let categories: Vec<&Node> = privacy_node.get_children_by_tag("category").collect();
        assert_eq!(categories.len(), 1);
        assert_eq!(attr_str(categories[0], "name").as_deref(), Some("profile"));
        assert_eq!(
            attr_str(categories[0], "value").as_deref(),
            Some("contact_blacklist")
        );
        assert_eq!(attr_str(categories[0], "dhash").as_deref(), Some("abc123"));

        let users: Vec<&Node> = categories[0].get_children_by_tag("user").collect();
        assert_eq!(users.len(), 2);
        assert_eq!(attr_str(users[0], "action").as_deref(), Some("add"));
        assert_eq!(attr_str(users[1], "action").as_deref(), Some("remove"));
    }

    // --- Validation tests ---

    #[test]
    fn test_category_value_validation() {
        // ReadReceipts: only all | none
        assert!(PrivacyCategory::ReadReceipts.is_valid_value(&PrivacyValue::All));
        assert!(PrivacyCategory::ReadReceipts.is_valid_value(&PrivacyValue::None));
        assert!(!PrivacyCategory::ReadReceipts.is_valid_value(&PrivacyValue::Contacts));
        assert!(!PrivacyCategory::ReadReceipts.is_valid_value(&PrivacyValue::MatchLastSeen));

        // Online: only all | match_last_seen
        assert!(PrivacyCategory::Online.is_valid_value(&PrivacyValue::All));
        assert!(PrivacyCategory::Online.is_valid_value(&PrivacyValue::MatchLastSeen));
        assert!(!PrivacyCategory::Online.is_valid_value(&PrivacyValue::None));
        assert!(!PrivacyCategory::Online.is_valid_value(&PrivacyValue::Contacts));

        // Last/Profile/Status/GroupAdd: all | contacts | contact_blacklist | none
        for cat in [
            PrivacyCategory::Last,
            PrivacyCategory::Profile,
            PrivacyCategory::Status,
            PrivacyCategory::GroupAdd,
        ] {
            assert!(cat.is_valid_value(&PrivacyValue::All));
            assert!(cat.is_valid_value(&PrivacyValue::Contacts));
            assert!(cat.is_valid_value(&PrivacyValue::ContactBlacklist));
            assert!(cat.is_valid_value(&PrivacyValue::None));
            assert!(!cat.is_valid_value(&PrivacyValue::MatchLastSeen));
            assert!(!cat.is_valid_value(&PrivacyValue::Known));
            assert!(!cat.is_valid_value(&PrivacyValue::Off));
        }

        // CallAdd: all | known | contacts
        assert!(PrivacyCategory::CallAdd.is_valid_value(&PrivacyValue::All));
        assert!(PrivacyCategory::CallAdd.is_valid_value(&PrivacyValue::Known));
        assert!(PrivacyCategory::CallAdd.is_valid_value(&PrivacyValue::Contacts));
        assert!(!PrivacyCategory::CallAdd.is_valid_value(&PrivacyValue::None));

        // Messages: all | contacts
        assert!(PrivacyCategory::Messages.is_valid_value(&PrivacyValue::All));
        assert!(PrivacyCategory::Messages.is_valid_value(&PrivacyValue::Contacts));
        assert!(!PrivacyCategory::Messages.is_valid_value(&PrivacyValue::None));

        // DefenseMode: off | on_standard
        assert!(PrivacyCategory::DefenseMode.is_valid_value(&PrivacyValue::Off));
        assert!(PrivacyCategory::DefenseMode.is_valid_value(&PrivacyValue::OnStandard));
        assert!(!PrivacyCategory::DefenseMode.is_valid_value(&PrivacyValue::All));

        // Other: allows anything
        assert!(
            PrivacyCategory::Other("future".to_string())
                .is_valid_value(&PrivacyValue::Other("future_val".to_string()))
        );
    }

    #[test]
    fn test_supports_disallowed_list() {
        assert!(PrivacyCategory::Last.supports_disallowed_list());
        assert!(PrivacyCategory::Profile.supports_disallowed_list());
        assert!(PrivacyCategory::Status.supports_disallowed_list());
        assert!(PrivacyCategory::GroupAdd.supports_disallowed_list());
        assert!(!PrivacyCategory::ReadReceipts.supports_disallowed_list());
        assert!(!PrivacyCategory::Online.supports_disallowed_list());
        assert!(!PrivacyCategory::CallAdd.supports_disallowed_list());
        assert!(!PrivacyCategory::Messages.supports_disallowed_list());
        assert!(!PrivacyCategory::DefenseMode.supports_disallowed_list());
    }
}
