//! Business profile IQ specification (namespace `w:biz`).

use crate::iq::node::optional_attr;
use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

fn node_text(node: &Node) -> Option<String> {
    match &node.content {
        Some(NodeContent::String(s)) => Some(s.clone()),
        Some(NodeContent::Bytes(b)) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BusinessProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wid: Option<Jid>,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub website: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<BusinessCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub business_hours: BusinessHours,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BusinessHours {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_config: Option<Vec<BusinessHoursConfig>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BusinessHoursConfig {
    pub day_of_week: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_time: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BusinessCategory {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BusinessProfileSpec {
    pub jid: Jid,
}

impl BusinessProfileSpec {
    pub fn new(jid: &Jid) -> Self {
        Self { jid: jid.clone() }
    }
}

impl IqSpec for BusinessProfileSpec {
    type Response = Option<BusinessProfile>;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get(
            "w:biz",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("business_profile")
                    .attr("v", "244")
                    .children([NodeBuilder::new("profile")
                        .attr("jid", self.jid.clone())
                        .build()])
                    .build(),
            ])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let biz_node = match response.get_optional_child("business_profile") {
            Some(n) => n,
            None => return Ok(None),
        };

        let profile_node = match biz_node.get_optional_child("profile") {
            Some(n) => n,
            None => return Ok(None),
        };

        let wid = optional_attr(profile_node, "jid").and_then(|s| s.parse::<Jid>().ok());

        let description = profile_node
            .get_optional_child("description")
            .and_then(node_text)
            .unwrap_or_default();

        let address = profile_node
            .get_optional_child("address")
            .and_then(node_text);

        let email = profile_node.get_optional_child("email").and_then(node_text);

        let website: Vec<String> = profile_node
            .get_children_by_tag("website")
            .filter_map(node_text)
            .collect();

        let categories: Vec<BusinessCategory> = profile_node
            .get_optional_child("categories")
            .map(|cats| {
                cats.get_children_by_tag("category")
                    .filter_map(|c| {
                        let id = optional_attr(c, "id")?.into_owned();
                        let name = node_text(c).unwrap_or_default();
                        Some(BusinessCategory { id, name })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let business_hours =
            if let Some(bh_node) = profile_node.get_optional_child("business_hours") {
                let timezone = optional_attr(bh_node, "timezone").map(|s| s.into_owned());
                let configs: Vec<BusinessHoursConfig> = bh_node
                    .get_children_by_tag("business_hours_config")
                    .filter_map(|c| {
                        let day = optional_attr(c, "day_of_week")?.into_owned();
                        let mode = optional_attr(c, "mode")?.into_owned();
                        Some(BusinessHoursConfig {
                            day_of_week: day,
                            mode,
                            open_time: optional_attr(c, "open_time").map(|s| s.into_owned()),
                            close_time: optional_attr(c, "close_time").map(|s| s.into_owned()),
                        })
                    })
                    .collect();

                BusinessHours {
                    timezone,
                    business_config: if configs.is_empty() {
                        None
                    } else {
                        Some(configs)
                    },
                }
            } else {
                BusinessHours::default()
            };

        Ok(Some(BusinessProfile {
            wid,
            description,
            email,
            website,
            categories,
            address,
            business_hours,
        }))
    }
}
