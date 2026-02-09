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

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for privacy settings.
pub const PRIVACY_NAMESPACE: &str = "privacy";

/// Privacy setting category name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyCategory {
    /// Last seen visibility
    Last,
    /// Online status visibility
    Online,
    /// Profile photo visibility
    Profile,
    /// Status visibility
    Status,
    /// Group add permissions
    GroupAdd,
    /// Read receipts
    ReadReceipts,
    /// Other/unknown category
    Other(String),
}

impl PrivacyCategory {
    pub fn as_str(&self) -> &str {
        match self {
            PrivacyCategory::Last => "last",
            PrivacyCategory::Online => "online",
            PrivacyCategory::Profile => "profile",
            PrivacyCategory::Status => "status",
            PrivacyCategory::GroupAdd => "groupadd",
            PrivacyCategory::ReadReceipts => "readreceipts",
            PrivacyCategory::Other(s) => s.as_str(),
        }
    }
}

impl From<&str> for PrivacyCategory {
    fn from(s: &str) -> Self {
        match s {
            "last" => PrivacyCategory::Last,
            "online" => PrivacyCategory::Online,
            "profile" => PrivacyCategory::Profile,
            "status" => PrivacyCategory::Status,
            "groupadd" => PrivacyCategory::GroupAdd,
            "readreceipts" => PrivacyCategory::ReadReceipts,
            other => PrivacyCategory::Other(other.to_string()),
        }
    }
}

/// Privacy setting value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyValue {
    /// Visible to everyone
    All,
    /// Visible only to contacts
    Contacts,
    /// Not visible to anyone
    None,
    /// Visible to contacts except specific list
    ContactBlacklist,
    /// Match their settings (for online/last)
    MatchLastSeen,
    /// Other/unknown value
    Other(String),
}

impl PrivacyValue {
    pub fn as_str(&self) -> &str {
        match self {
            PrivacyValue::All => "all",
            PrivacyValue::Contacts => "contacts",
            PrivacyValue::None => "none",
            PrivacyValue::ContactBlacklist => "contact_blacklist",
            PrivacyValue::MatchLastSeen => "match_last_seen",
            PrivacyValue::Other(s) => s.as_str(),
        }
    }
}

impl From<&str> for PrivacyValue {
    fn from(s: &str) -> Self {
        match s {
            "all" => PrivacyValue::All,
            "contacts" => PrivacyValue::Contacts,
            "none" => PrivacyValue::None,
            "contact_blacklist" => PrivacyValue::ContactBlacklist,
            "match_last_seen" => PrivacyValue::MatchLastSeen,
            other => PrivacyValue::Other(other.to_string()),
        }
    }
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
                category: PrivacyCategory::from(name),
                value: PrivacyValue::from(value),
            });
        }

        Ok(PrivacySettingsResponse { settings })
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
