use crate::client::Client;
use crate::jid_utils::server_jid;
use crate::request::InfoQuery;
use anyhow::{Result, anyhow};
use log::debug;
use std::collections::HashMap;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};

#[derive(Debug, Clone)]
pub struct IsOnWhatsAppResult {
    pub jid: Jid,
    pub is_registered: bool,
}

#[derive(Debug, Clone)]
pub struct ContactInfo {
    pub jid: Jid,

    pub lid: Option<Jid>,

    pub is_registered: bool,

    pub is_business: bool,

    pub status: Option<String>,

    pub picture_id: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ProfilePicture {
    pub id: String,

    pub url: String,

    pub direct_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub jid: Jid,

    pub lid: Option<Jid>,

    pub status: Option<String>,

    pub picture_id: Option<String>,

    pub is_business: bool,
}

pub struct Contacts<'a> {
    client: &'a Client,
}

impl<'a> Contacts<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn is_on_whatsapp(&self, phones: &[&str]) -> Result<Vec<IsOnWhatsAppResult>> {
        if phones.is_empty() {
            return Ok(Vec::new());
        }

        let request_id = self.client.generate_request_id();
        debug!("is_on_whatsapp: checking {} numbers", phones.len());

        let query_node = NodeBuilder::new("query")
            .children(vec![NodeBuilder::new("contact").build()])
            .build();

        let user_nodes: Vec<Node> = phones
            .iter()
            .map(|phone| {
                let phone_content = if phone.starts_with('+') {
                    phone.to_string()
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
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", request_id.as_str())
            .attr("mode", "query")
            .attr("last", "true")
            .attr("index", "0")
            .attr("context", "interactive")
            .children(vec![query_node, list_node])
            .build();

        let iq = InfoQuery::get(
            "usync",
            server_jid(),
            Some(NodeContent::Nodes(vec![usync_node])),
        );

        let response_node = self.client.send_iq(iq).await?;
        Self::parse_is_on_whatsapp_response(&response_node)
    }

    pub async fn get_info(&self, phones: &[&str]) -> Result<Vec<ContactInfo>> {
        if phones.is_empty() {
            return Ok(Vec::new());
        }

        let request_id = self.client.generate_request_id();
        debug!("get_info: fetching info for {} numbers", phones.len());

        let query_node = NodeBuilder::new("query")
            .children(vec![
                NodeBuilder::new("contact").build(),
                NodeBuilder::new("lid").build(),
                NodeBuilder::new("status").build(),
                NodeBuilder::new("picture").build(),
                NodeBuilder::new("business").build(),
            ])
            .build();

        let user_nodes: Vec<Node> = phones
            .iter()
            .map(|phone| {
                let phone_content = if phone.starts_with('+') {
                    phone.to_string()
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
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", request_id.as_str())
            .attr("mode", "query")
            .attr("last", "true")
            .attr("index", "0")
            .attr("context", "interactive")
            .children(vec![query_node, list_node])
            .build();

        let iq = InfoQuery::get(
            "usync",
            server_jid(),
            Some(NodeContent::Nodes(vec![usync_node])),
        );

        let response_node = self.client.send_iq(iq).await?;
        Self::parse_contact_info_response(&response_node)
    }

    pub async fn get_profile_picture(
        &self,
        jid: &Jid,
        preview: bool,
    ) -> Result<Option<ProfilePicture>> {
        debug!(
            "get_profile_picture: fetching {} picture for {}",
            if preview { "preview" } else { "full" },
            jid
        );

        let picture_type = if preview { "preview" } else { "image" };
        let picture_node = NodeBuilder::new("picture")
            .attr("type", picture_type)
            .attr("query", "url")
            .build();

        let iq = InfoQuery::get(
            "w:profile:picture",
            server_jid(),
            Some(NodeContent::Nodes(vec![picture_node])),
        )
        .with_target(jid.clone());

        let response_node = self.client.send_iq(iq).await?;
        Self::parse_profile_picture_response(&response_node)
    }

    pub async fn get_user_info(&self, jids: &[Jid]) -> Result<HashMap<Jid, UserInfo>> {
        if jids.is_empty() {
            return Ok(HashMap::new());
        }

        let request_id = self.client.generate_request_id();
        debug!("get_user_info: fetching info for {} JIDs", jids.len());

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

        let user_nodes: Vec<Node> = jids
            .iter()
            .map(|jid| {
                NodeBuilder::new("user")
                    .attr("jid", jid.to_non_ad().to_string())
                    .build()
            })
            .collect();

        let list_node = NodeBuilder::new("list").children(user_nodes).build();

        let usync_node = NodeBuilder::new("usync")
            .attr("sid", request_id.as_str())
            .attr("mode", "full")
            .attr("last", "true")
            .attr("index", "0")
            .attr("context", "background")
            .children(vec![query_node, list_node])
            .build();

        let iq = InfoQuery::get(
            "usync",
            server_jid(),
            Some(NodeContent::Nodes(vec![usync_node])),
        );

        let response_node = self.client.send_iq(iq).await?;
        Self::parse_user_info_response(&response_node)
    }

    fn parse_is_on_whatsapp_response(node: &Node) -> Result<Vec<IsOnWhatsAppResult>> {
        let usync = node
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

    fn parse_contact_info_response(node: &Node) -> Result<Vec<ContactInfo>> {
        let usync = node
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

                let picture_id = user_node
                    .get_optional_child("picture")
                    .and_then(|pic_node| {
                        if pic_node.get_optional_child("error").is_some() {
                            return None;
                        }
                        pic_node.attrs().optional_u64("id")
                    });

                let is_business = user_node.get_optional_child("business").is_some();

                results.push(ContactInfo {
                    jid,
                    lid,
                    is_registered,
                    is_business,
                    status,
                    picture_id,
                });
            }
        }

        Ok(results)
    }

    fn parse_profile_picture_response(node: &Node) -> Result<Option<ProfilePicture>> {
        let picture_node = match node.get_optional_child("picture") {
            Some(p) => p,
            None => return Ok(None),
        };

        if let Some(error_node) = picture_node.get_optional_child("error") {
            let code = error_node.attrs().optional_string("code").unwrap_or("0");
            if code == "404" || code == "401" {
                return Ok(None);
            }
            let text = error_node
                .attrs()
                .optional_string("text")
                .unwrap_or("unknown error");
            return Err(anyhow!("Profile picture error {}: {}", code, text));
        }

        let id = picture_node
            .attrs()
            .optional_string("id")
            .map(|s| s.to_string())
            .unwrap_or_default();

        let url = picture_node
            .attrs()
            .optional_string("url")
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Picture response missing 'url' attribute"))?;

        let direct_path = picture_node
            .attrs()
            .optional_string("direct_path")
            .map(|s| s.to_string());

        Ok(Some(ProfilePicture {
            id,
            url,
            direct_path,
        }))
    }

    fn parse_user_info_response(node: &Node) -> Result<HashMap<Jid, UserInfo>> {
        let usync = node
            .get_optional_child("usync")
            .ok_or_else(|| anyhow!("Response missing <usync> node"))?;

        let list = usync
            .get_optional_child("list")
            .ok_or_else(|| anyhow!("Response missing <list> node"))?;

        let mut results = HashMap::new();

        for user_node in list.get_children_by_tag("user") {
            let jid_str = user_node.attrs().optional_string("jid");

            if let Some(jid_str) = jid_str
                && let Ok(jid) = jid_str.parse::<Jid>()
            {
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

                let picture_id = user_node
                    .get_optional_child("picture")
                    .and_then(|pic_node| {
                        if pic_node.get_optional_child("error").is_some() {
                            return None;
                        }
                        pic_node
                            .attrs()
                            .optional_string("id")
                            .map(|s| s.to_string())
                    });

                let is_business = user_node.get_optional_child("business").is_some();

                results.insert(
                    jid.clone(),
                    UserInfo {
                        jid,
                        lid,
                        status,
                        picture_id,
                        is_business,
                    },
                );
            }
        }

        Ok(results)
    }
}

impl Client {
    pub fn contacts(&self) -> Contacts<'_> {
        Contacts::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_info_struct() {
        let jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let lid: Jid = "12345678@lid".parse().expect("test JID should be valid");

        let info = ContactInfo {
            jid: jid.clone(),
            lid: Some(lid.clone()),
            is_registered: true,
            is_business: false,
            status: Some("Hey there!".to_string()),
            picture_id: Some(123456789),
        };

        assert!(info.is_registered);
        assert!(!info.is_business);
        assert_eq!(info.status, Some("Hey there!".to_string()));
        assert_eq!(info.picture_id, Some(123456789));
        assert!(info.lid.is_some());
    }

    #[test]
    fn test_profile_picture_struct() {
        let pic = ProfilePicture {
            id: "123456789".to_string(),
            url: "https://example.com/pic.jpg".to_string(),
            direct_path: Some("/v/pic.jpg".to_string()),
        };

        assert_eq!(pic.id, "123456789");
        assert_eq!(pic.url, "https://example.com/pic.jpg");
        assert!(pic.direct_path.is_some());
    }

    #[test]
    fn test_is_on_whatsapp_result_struct() {
        let jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let result = IsOnWhatsAppResult {
            jid,
            is_registered: true,
        };

        assert!(result.is_registered);
    }
}
