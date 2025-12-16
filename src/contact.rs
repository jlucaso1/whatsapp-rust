use crate::client::Client;
use crate::jid_utils::server_jid;
use crate::request::{InfoQuery, InfoQueryType};
use anyhow::{Result, anyhow};
use log::debug;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};

/// Result of checking if a phone number is registered on WhatsApp (minimal check).
#[derive(Debug, Clone)]
pub struct IsOnWhatsAppResult {
    /// The JID of the user (e.g., "1234567890@s.whatsapp.net")
    pub jid: Jid,
    /// Whether the user is registered on WhatsApp
    pub is_registered: bool,
}

/// Comprehensive contact information retrieved via usync.
#[derive(Debug, Clone)]
pub struct ContactInfo {
    /// The phone number JID (e.g., "5511999887766@s.whatsapp.net")
    pub jid: Jid,

    /// The LID JID if available (e.g., "12345678@lid")
    pub lid: Option<Jid>,

    /// Whether registered on WhatsApp
    pub is_registered: bool,

    /// Whether this is a business account
    pub is_business: bool,

    /// User's "about" / status text
    pub status: Option<String>,

    /// Profile picture ID (for change detection, not the URL)
    pub picture_id: Option<u64>,
}

/// Profile picture information retrieved via separate IQ.
#[derive(Debug, Clone)]
pub struct ProfilePicture {
    /// Picture ID / tag
    pub id: String,

    /// Encrypted URL to fetch the image
    pub url: String,

    /// Direct path for CDN fetch
    pub direct_path: Option<String>,
}

/// User information retrieved via usync by JID.
/// Similar to ContactInfo but used when querying by JID (phone or LID) rather than phone number.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// The JID that was queried
    pub jid: Jid,

    /// The LID JID if available (only populated when querying phone JIDs)
    pub lid: Option<Jid>,

    /// User's "about" / status text
    pub status: Option<String>,

    /// Profile picture ID (for change detection)
    pub picture_id: Option<String>,

    /// Whether this is a business account
    pub is_business: bool,
}

impl Client {
    /// Quick check if phone numbers are on WhatsApp (minimal data).
    ///
    /// Use this when you only need to verify registration status without
    /// fetching additional profile data like status or picture.
    ///
    /// # Arguments
    ///
    /// * `phones` - A list of phone numbers in international format (e.g., "+1234567890" or "1234567890")
    ///
    /// # Returns
    ///
    /// A list of results indicating whether each number is registered on WhatsApp.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(client: &whatsapp_rust::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let results = client.is_on_whatsapp(&["+5511999887766"]).await?;
    /// for result in results {
    ///     println!("{}: {}", result.jid, if result.is_registered { "registered" } else { "not found" });
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_on_whatsapp(&self, phones: &[&str]) -> Result<Vec<IsOnWhatsAppResult>> {
        if phones.is_empty() {
            return Ok(Vec::new());
        }

        let request_id = self.generate_request_id();
        debug!("is_on_whatsapp: checking {} numbers", phones.len());

        // Build query with just contact protocol
        let query_node = NodeBuilder::new("query")
            .children(vec![NodeBuilder::new("contact").build()])
            .build();

        // Build user list
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

        let iq = InfoQuery {
            namespace: "usync",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![usync_node])),
            timeout: None,
        };

        let response_node = self.send_iq(iq).await?;
        self.parse_is_on_whatsapp_response(&response_node)
    }

    /// Get comprehensive contact info for phone numbers.
    ///
    /// This method retrieves registration status, LID, about text, picture ID,
    /// and business status in a single request using the usync protocol.
    ///
    /// **Note:** This does NOT include the profile picture URL. Use
    /// [`get_profile_picture`](Self::get_profile_picture) for that.
    ///
    /// # Arguments
    ///
    /// * `phones` - A list of phone numbers in international format (e.g., "+1234567890" or "1234567890")
    ///
    /// # Returns
    ///
    /// A list of [`ContactInfo`] for each registered user.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(client: &whatsapp_rust::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let contacts = client.get_contact_info(&["+5511999887766"]).await?;
    /// for contact in contacts {
    ///     println!("JID: {}", contact.jid);
    ///     println!("  LID: {:?}", contact.lid);
    ///     println!("  Status: {:?}", contact.status);
    ///     println!("  Business: {}", contact.is_business);
    ///     println!("  Picture ID: {:?}", contact.picture_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_contact_info(&self, phones: &[&str]) -> Result<Vec<ContactInfo>> {
        if phones.is_empty() {
            return Ok(Vec::new());
        }

        let request_id = self.generate_request_id();
        debug!(
            "get_contact_info: fetching info for {} numbers",
            phones.len()
        );

        // Build query with multiple protocols: contact, lid, status, picture
        let query_node = NodeBuilder::new("query")
            .children(vec![
                NodeBuilder::new("contact").build(),
                NodeBuilder::new("lid").build(),
                NodeBuilder::new("status").build(),
                NodeBuilder::new("picture").build(),
                NodeBuilder::new("business").build(),
            ])
            .build();

        // Build user list
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

        let iq = InfoQuery {
            namespace: "usync",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![usync_node])),
            timeout: None,
        };

        let response_node = self.send_iq(iq).await?;
        self.parse_contact_info_response(&response_node)
    }

    /// Get profile picture URL for a specific user.
    ///
    /// This requires a separate request to WhatsApp servers using the
    /// `w:profile:picture` protocol. The returned URL can be used to
    /// download the profile picture.
    ///
    /// # Arguments
    ///
    /// * `jid` - The JID of the user to get the profile picture for
    /// * `preview` - If `true`, returns a smaller preview/thumbnail image.
    ///   If `false`, returns the full-size image.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(ProfilePicture))` - The profile picture information
    /// * `Ok(None)` - The user has no profile picture set
    /// * `Err(...)` - An error occurred during the request
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use wacore_binary::jid::Jid;
    /// # async fn example(client: &whatsapp_rust::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let jid: Jid = "5511999887766@s.whatsapp.net".parse()?;
    ///
    /// // Get thumbnail
    /// if let Some(pic) = client.get_profile_picture(&jid, true).await? {
    ///     println!("Picture URL: {}", pic.url);
    /// }
    ///
    /// // Get full-size picture
    /// if let Some(pic) = client.get_profile_picture(&jid, false).await? {
    ///     println!("Full picture URL: {}", pic.url);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

        // Build the picture query node
        let picture_type = if preview { "preview" } else { "image" };
        let picture_node = NodeBuilder::new("picture")
            .attr("type", picture_type)
            .attr("query", "url")
            .build();

        let iq = InfoQuery {
            namespace: "w:profile:picture",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: Some(jid.clone()),
            id: None,
            content: Some(NodeContent::Nodes(vec![picture_node])),
            timeout: None,
        };

        let response_node = self.send_iq(iq).await?;
        self.parse_profile_picture_response(&response_node)
    }

    /// Get user information by JID (works with both phone JIDs and LID JIDs).
    ///
    /// This method queries user information using the JID directly, which is useful
    /// when you have a JID from a message participant (which might be a LID in groups).
    ///
    /// Unlike [`get_contact_info`](Self::get_contact_info) which takes phone numbers,
    /// this method works with any JID type.
    ///
    /// # Arguments
    ///
    /// * `jids` - A list of JIDs to query (can be phone JIDs or LID JIDs)
    ///
    /// # Returns
    ///
    /// A map of JID to [`UserInfo`] for each queried user.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use wacore_binary::jid::Jid;
    /// # async fn example(client: &whatsapp_rust::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// // Query by phone JID
    /// let phone_jid: Jid = "5511999887766@s.whatsapp.net".parse()?;
    ///
    /// // Or query by LID JID (from group messages)
    /// let lid_jid: Jid = "123456789@lid".parse()?;
    ///
    /// let results = client.get_user_info(&[phone_jid, lid_jid]).await?;
    /// for (jid, info) in results {
    ///     println!("User {}: status={:?}, picture_id={:?}",
    ///         jid, info.status, info.picture_id);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_user_info(
        &self,
        jids: &[Jid],
    ) -> Result<std::collections::HashMap<Jid, UserInfo>> {
        use std::collections::HashMap;

        if jids.is_empty() {
            return Ok(HashMap::new());
        }

        let request_id = self.generate_request_id();
        debug!("get_user_info: fetching info for {} JIDs", jids.len());

        // Build query with protocols: status, picture, business, lid
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

        // Build user list with jid attribute (not <contact> child)
        // This is how whatsmeow's GetUserInfo works
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

        let iq = InfoQuery {
            namespace: "usync",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![usync_node])),
            timeout: None,
        };

        let response_node = self.send_iq(iq).await?;
        self.parse_user_info_response(&response_node)
    }

    // --- Private parsing methods ---

    fn parse_is_on_whatsapp_response(&self, node: &Node) -> Result<Vec<IsOnWhatsAppResult>> {
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

    fn parse_contact_info_response(&self, node: &Node) -> Result<Vec<ContactInfo>> {
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
                // Parse contact (registration status)
                let contact_node = user_node.get_optional_child("contact");
                let is_registered = contact_node
                    .map(|c| c.attrs().optional_string("type") == Some("in"))
                    .unwrap_or(false);

                // Parse LID
                let lid = user_node.get_optional_child("lid").and_then(|lid_node| {
                    lid_node
                        .attrs()
                        .optional_string("val")
                        .and_then(|val| val.parse::<Jid>().ok())
                });

                // Parse status (about text)
                let status = user_node
                    .get_optional_child("status")
                    .and_then(|status_node| {
                        // Check for error first
                        if status_node.get_optional_child("error").is_some() {
                            return None;
                        }
                        // Get content as string
                        match &status_node.content {
                            Some(NodeContent::String(s)) if !s.is_empty() => Some(s.clone()),
                            _ => None,
                        }
                    });

                // Parse picture ID
                let picture_id = user_node
                    .get_optional_child("picture")
                    .and_then(|pic_node| {
                        // Check for error first
                        if pic_node.get_optional_child("error").is_some() {
                            return None;
                        }
                        pic_node.attrs().optional_u64("id")
                    });

                // Parse business status
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

    fn parse_profile_picture_response(&self, node: &Node) -> Result<Option<ProfilePicture>> {
        // Check for picture node in response
        let picture_node = match node.get_optional_child("picture") {
            Some(p) => p,
            None => return Ok(None), // No picture set
        };

        // Check for error
        if let Some(error_node) = picture_node.get_optional_child("error") {
            let code = error_node.attrs().optional_string("code").unwrap_or("0");
            // 404 means no picture, not an error
            if code == "404" || code == "401" {
                return Ok(None);
            }
            let text = error_node
                .attrs()
                .optional_string("text")
                .unwrap_or("unknown error");
            return Err(anyhow!("Profile picture error {}: {}", code, text));
        }

        // Get picture attributes
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

    fn parse_user_info_response(
        &self,
        node: &Node,
    ) -> Result<std::collections::HashMap<Jid, UserInfo>> {
        use std::collections::HashMap;

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
                // Parse LID
                let lid = user_node.get_optional_child("lid").and_then(|lid_node| {
                    lid_node
                        .attrs()
                        .optional_string("val")
                        .and_then(|val| val.parse::<Jid>().ok())
                });

                // Parse status (about text)
                let status = user_node
                    .get_optional_child("status")
                    .and_then(|status_node| {
                        // Check for error first
                        if status_node.get_optional_child("error").is_some() {
                            return None;
                        }
                        // Get content as string
                        match &status_node.content {
                            Some(NodeContent::String(s)) if !s.is_empty() => Some(s.clone()),
                            _ => None,
                        }
                    });

                // Parse picture ID (as string, different from ContactInfo)
                let picture_id = user_node
                    .get_optional_child("picture")
                    .and_then(|pic_node| {
                        // Check for error first
                        if pic_node.get_optional_child("error").is_some() {
                            return None;
                        }
                        pic_node
                            .attrs()
                            .optional_string("id")
                            .map(|s| s.to_string())
                    });

                // Parse business status
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_info_struct() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let lid: Jid = "12345678@lid".parse().unwrap();

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
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let result = IsOnWhatsAppResult {
            jid,
            is_registered: true,
        };

        assert!(result.is_registered);
    }
}
