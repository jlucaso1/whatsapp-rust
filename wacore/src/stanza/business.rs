//! Business notification stanza types.
//!
//! Reference: WhatsApp Web `WAWebHandleBusinessNotification`

use anyhow::{Result, anyhow};
use serde::Serialize;
use wacore_binary::Jid;
use wacore_binary::NodeRef;

/// Business notification type based on child element.
#[derive(Debug, Clone, PartialEq, Eq, crate::WireEnum)]
pub enum BusinessNotificationType {
    #[wire = "remove_jid"]
    RemoveJid,
    #[wire = "remove_hash"]
    RemoveHash,
    #[wire = "verified_name_jid"]
    VerifiedNameJid,
    #[wire = "verified_name_hash"]
    VerifiedNameHash,
    #[wire = "profile"]
    Profile,
    #[wire = "profile_hash"]
    ProfileHash,
    #[wire = "product"]
    Product,
    #[wire = "collection"]
    Collection,
    #[wire = "subscriptions"]
    Subscriptions,
    #[wire_default]
    #[wire = "unknown"]
    Unknown,
}

/// Verified name certificate information.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedName {
    pub name: Option<String>,
    pub serial: Option<String>,
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Vec<u8>>,
}

impl VerifiedName {
    pub fn try_from_node(node: &NodeRef<'_>) -> Result<Self> {
        use wacore_binary::NodeContentRef;
        let name = node
            .attrs()
            .optional_string("name")
            .map(|s| s.into_owned())
            .or_else(|| {
                node.get_optional_child_by_tag(&["name"])
                    .and_then(|n| match n.content.as_deref() {
                        Some(NodeContentRef::String(s)) => Some(s.to_string()),
                        _ => None,
                    })
            });

        let serial = node
            .attrs()
            .optional_string("serial")
            .map(|s| s.into_owned());
        let issuer = node
            .attrs()
            .optional_string("issuer")
            .map(|s| s.into_owned());
        let certificate = match node.content.as_deref() {
            Some(NodeContentRef::Bytes(b)) => Some(b.to_vec()),
            _ => None,
        };

        Ok(Self {
            name,
            serial,
            issuer,
            certificate,
        })
    }
}

/// Business subscription information (SMB features).
#[derive(Debug, Clone, Serialize)]
pub struct BusinessSubscription {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<i64>,
}

/// Parsed `<notification type="business">` stanza.
#[derive(Debug, Clone, Serialize)]
pub struct BusinessNotification {
    pub from: Jid,
    pub stanza_id: String,
    pub timestamp: i64,
    pub notification_type: BusinessNotificationType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jid: Option<Jid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_name: Option<VerifiedName>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub product_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub collection_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subscriptions: Vec<BusinessSubscription>,
}

impl BusinessNotification {
    pub fn try_parse(node: &NodeRef<'_>) -> Result<Self> {
        if node.tag != "notification" {
            return Err(anyhow!("expected <notification>, got <{}>", node.tag));
        }
        if node
            .get_attr("type")
            .map(|v| v.as_str())
            .is_none_or(|s| s != "business")
        {
            return Err(anyhow!("expected type='business'"));
        }

        let mut attrs = node.attrs();
        let from = attrs
            .optional_jid("from")
            .ok_or_else(|| anyhow!("notification missing required 'from' attribute"))?;
        let stanza_id = node
            .get_attr("id")
            .map(|v| v.as_str())
            .unwrap_or_default()
            .into_owned();
        let timestamp = match attrs.optional_u64("t") {
            Some(t) => i64::try_from(t)
                .map_err(|_| anyhow!("notification timestamp {} exceeds i64::MAX", t))?,
            None => 0,
        };

        let (
            notification_type,
            jid,
            hash,
            verified_name,
            product_ids,
            collection_ids,
            subscriptions,
        ) = Self::parse_content(node)?;

        Ok(Self {
            from,
            stanza_id,
            timestamp,
            notification_type,
            jid,
            hash,
            verified_name,
            product_ids,
            collection_ids,
            subscriptions,
        })
    }

    #[allow(clippy::type_complexity)]
    fn parse_content(
        node: &NodeRef<'_>,
    ) -> Result<(
        BusinessNotificationType,
        Option<Jid>,
        Option<String>,
        Option<VerifiedName>,
        Vec<String>,
        Vec<String>,
        Vec<BusinessSubscription>,
    )> {
        use wacore_binary::NodeContentRef;

        if let Some(remove_node) = node.get_optional_child("remove") {
            if let Some(jid) = remove_node.attrs().optional_jid("jid") {
                return Ok((
                    BusinessNotificationType::RemoveJid,
                    Some(jid),
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ));
            } else if let Some(hash) = remove_node.attrs().optional_string("hash") {
                return Ok((
                    BusinessNotificationType::RemoveHash,
                    None,
                    Some(hash.to_string()),
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ));
            }
        }

        if let Some(vn_node) = node.get_optional_child("verified_name") {
            let verified_name = VerifiedName::try_from_node(vn_node)?;
            if let Some(jid) = vn_node.attrs().optional_jid("jid") {
                return Ok((
                    BusinessNotificationType::VerifiedNameJid,
                    Some(jid),
                    None,
                    Some(verified_name),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ));
            } else if let Some(hash) = vn_node.attrs().optional_string("hash") {
                return Ok((
                    BusinessNotificationType::VerifiedNameHash,
                    None,
                    Some(hash.to_string()),
                    Some(verified_name),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ));
            }
        }

        if let Some(profile_node) = node.get_optional_child("profile") {
            if let Some(hash) = profile_node.attrs().optional_string("hash") {
                return Ok((
                    BusinessNotificationType::ProfileHash,
                    None,
                    Some(hash.to_string()),
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ));
            }
            return Ok((
                BusinessNotificationType::Profile,
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ));
        }

        if let Some(catalog_node) = node.get_optional_child("product_catalog")
            && let Some(children) = catalog_node.children()
        {
            let mut product_ids = Vec::new();
            let mut collection_ids = Vec::new();

            for child in children {
                if child.tag == "product"
                    && let Some(id_node) = child.get_optional_child_by_tag(&["id"])
                    && let Some(NodeContentRef::String(id)) = id_node.content.as_deref()
                {
                    product_ids.push(id.to_string());
                } else if child.tag == "collection"
                    && let Some(id) = child.attrs().optional_string("id")
                {
                    collection_ids.push(id.to_string());
                }
            }

            if !product_ids.is_empty() {
                return Ok((
                    BusinessNotificationType::Product,
                    None,
                    None,
                    None,
                    product_ids,
                    Vec::new(),
                    Vec::new(),
                ));
            }
            if !collection_ids.is_empty() {
                return Ok((
                    BusinessNotificationType::Collection,
                    None,
                    None,
                    None,
                    Vec::new(),
                    collection_ids,
                    Vec::new(),
                ));
            }
        }

        if let Some(subs_node) = node.get_optional_child("subscriptions") {
            let mut subscriptions = Vec::new();
            if let Some(children) = subs_node.children() {
                for child in children.iter().filter(|c| c.tag == "subscription") {
                    if let (Some(id), Some(status)) = (
                        child.attrs().optional_string("id"),
                        child.attrs().optional_string("status"),
                    ) {
                        subscriptions.push(BusinessSubscription {
                            id: id.to_string(),
                            status: status.to_string(),
                            expiration_date: child
                                .attrs()
                                .optional_u64("subscription_end_time")
                                .and_then(|v| i64::try_from(v).ok()),
                            creation_time: child
                                .attrs()
                                .optional_u64("subscription_creation_time")
                                .and_then(|v| i64::try_from(v).ok()),
                        });
                    }
                }
            }
            if !subscriptions.is_empty() {
                return Ok((
                    BusinessNotificationType::Subscriptions,
                    None,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    subscriptions,
                ));
            }
        }

        Ok((
            BusinessNotificationType::Unknown,
            None,
            None,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ))
    }

    #[inline]
    pub fn is_business_removed(&self) -> bool {
        matches!(
            self.notification_type,
            BusinessNotificationType::RemoveJid | BusinessNotificationType::RemoveHash
        )
    }

    #[inline]
    pub fn is_verified_name_update(&self) -> bool {
        matches!(
            self.notification_type,
            BusinessNotificationType::VerifiedNameJid | BusinessNotificationType::VerifiedNameHash
        )
    }

    #[inline]
    pub fn is_profile_update(&self) -> bool {
        matches!(
            self.notification_type,
            BusinessNotificationType::Profile | BusinessNotificationType::ProfileHash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_parse_remove_jid_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("remove")
                .attr("jid", "15551234567@s.whatsapp.net")
                .build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(
            parsed.notification_type,
            BusinessNotificationType::RemoveJid
        );
        assert_eq!(parsed.from.user, "15551234567");
        assert_eq!(parsed.stanza_id, "123456");
        assert!(parsed.jid.is_some());
        assert!(parsed.is_business_removed());
    }

    #[test]
    fn test_parse_remove_hash_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("remove")
                .attr("hash", "abc123hash")
                .build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(
            parsed.notification_type,
            BusinessNotificationType::RemoveHash
        );
        assert_eq!(parsed.hash, Some("abc123hash".to_string()));
        assert!(parsed.is_business_removed());
    }

    #[test]
    fn test_parse_verified_name_jid_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("verified_name")
                .attr("jid", "15551234567@s.whatsapp.net")
                .attr("name", "Test Business")
                .attr("serial", "12345")
                .build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(
            parsed.notification_type,
            BusinessNotificationType::VerifiedNameJid
        );
        assert!(parsed.is_verified_name_update());
        assert!(parsed.verified_name.is_some());
        assert_eq!(
            parsed.verified_name.as_ref().unwrap().name,
            Some("Test Business".to_string())
        );
    }

    #[test]
    fn test_parse_profile_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("profile").build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(parsed.notification_type, BusinessNotificationType::Profile);
        assert!(parsed.is_profile_update());
    }

    #[test]
    fn test_parse_profile_hash_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("profile")
                .attr("hash", "profile_hash_123")
                .build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(
            parsed.notification_type,
            BusinessNotificationType::ProfileHash
        );
        assert_eq!(parsed.hash, Some("profile_hash_123".to_string()));
    }

    #[test]
    fn test_parse_product_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("product_catalog")
                .children([
                    NodeBuilder::new("product")
                        .children([NodeBuilder::new("id").string_content("product_1").build()])
                        .build(),
                    NodeBuilder::new("product")
                        .children([NodeBuilder::new("id").string_content("product_2").build()])
                        .build(),
                ])
                .build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(parsed.notification_type, BusinessNotificationType::Product);
        assert_eq!(parsed.product_ids, vec!["product_1", "product_2"]);
    }

    #[test]
    fn test_parse_subscriptions_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("subscriptions")
                .children([NodeBuilder::new("subscription")
                    .attr("id", "premium_123")
                    .attr("status", "active")
                    .attr("subscription_end_time", "1800000000")
                    .build()])
                .build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(
            parsed.notification_type,
            BusinessNotificationType::Subscriptions
        );
        assert_eq!(parsed.subscriptions.len(), 1);
        assert_eq!(parsed.subscriptions[0].id, "premium_123");
        assert_eq!(parsed.subscriptions[0].status, "active");
        assert_eq!(parsed.subscriptions[0].expiration_date, Some(1800000000));
    }

    #[test]
    fn test_parse_unknown_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "business")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123456")
            .attr("t", "1700000000")
            .children([NodeBuilder::new("ctwa_suggestion").build()])
            .build();

        let parsed = BusinessNotification::try_parse(&node.as_node_ref()).unwrap();
        assert_eq!(parsed.notification_type, BusinessNotificationType::Unknown);
    }

    #[test]
    fn test_wrong_notification_type_fails() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .build();

        let result = BusinessNotification::try_parse(&node.as_node_ref());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("type='business'"));
    }
}
