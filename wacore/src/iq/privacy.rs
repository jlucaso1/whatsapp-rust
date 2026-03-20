//! Privacy settings IQ specification.
//!
//! Fetches the user's privacy settings from the server.
//!
//! ## Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="privacy" type="get" to="s.whatsapp.net" id="...">
//!   <privacy/>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <privacy>
//!     <category name="last" value="all"/>
//!     <category name="online" value="all"/>
//!     <category name="profile" value="contacts"/>
//!     <category name="status" value="contacts"/>
//!     <category name="groupadd" value="contacts"/>
//!     ...
//!   </privacy>
//! </iq>
//! ```
//!
//! Verified against WhatsApp Web JS (WAWebQueryPrivacy).

use crate::StringEnum;
use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for privacy settings.
pub const PRIVACY_NAMESPACE: &str = "privacy";

/// Privacy setting category name.
#[derive(Debug, Clone, PartialEq, Eq, StringEnum)]
pub enum PrivacyCategory {
    /// Last seen visibility
    #[str = "last"]
    Last,
    /// Online status visibility
    #[str = "online"]
    Online,
    /// Profile photo visibility
    #[str = "profile"]
    Profile,
    /// Status visibility
    #[str = "status"]
    Status,
    /// Group add permissions
    #[str = "groupadd"]
    GroupAdd,
    /// Read receipts
    #[str = "readreceipts"]
    ReadReceipts,
    /// Other/unknown category
    #[string_fallback]
    Other(String),
}

/// Privacy setting value.
#[derive(Debug, Clone, PartialEq, Eq, StringEnum)]
pub enum PrivacyValue {
    /// Visible to everyone
    #[str = "all"]
    All,
    /// Visible only to contacts
    #[str = "contacts"]
    Contacts,
    /// Not visible to anyone
    #[str = "none"]
    None,
    /// Visible to contacts except specific list
    #[str = "contact_blacklist"]
    ContactBlacklist,
    /// Match their settings (for online/last)
    #[str = "match_last_seen"]
    MatchLastSeen,
    /// Other/unknown value
    #[string_fallback]
    Other(String),
}

/// A single privacy setting.
#[derive(Debug, Clone)]
pub struct PrivacySetting {
    /// The category name (e.g., "last", "profile", etc.)
    pub category: PrivacyCategory,
    /// The privacy value (e.g., "all", "contacts", "none")
    pub value: PrivacyValue,
}

/// Response from privacy settings query.
#[derive(Debug, Clone, Default)]
pub struct PrivacySettingsResponse {
    /// The list of privacy settings.
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

/// Set a single privacy setting.
///
/// ```xml
/// <iq xmlns="privacy" type="set" to="s.whatsapp.net">
///   <privacy>
///     <category name="{category}" value="{value}"/>
///   </privacy>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetPrivacySettingSpec {
    pub category: String,
    pub value: String,
}

impl SetPrivacySettingSpec {
    pub fn new(category: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            value: value.into(),
        }
    }
}

impl IqSpec for SetPrivacySettingSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set(
            PRIVACY_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("privacy")
                    .children([NodeBuilder::new("category")
                        .attr("name", &*self.category)
                        .attr("value", &*self.value)
                        .build()])
                    .build(),
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

    #[test]
    fn test_privacy_category_from_str() {
        assert_eq!(PrivacyCategory::from("last"), PrivacyCategory::Last);
        assert_eq!(PrivacyCategory::from("online"), PrivacyCategory::Online);
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
            PrivacyValue::from("unknown"),
            PrivacyValue::Other("unknown".to_string())
        );
    }
}
