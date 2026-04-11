//! Contact-related IQ specifications.
//!
//! ## Profile Picture Wire Format
//! ```xml
//! <!-- Request (with optional tctoken for privacy gating) -->
//! <iq xmlns="w:profile:picture" type="get" to="s.whatsapp.net" target="1234567890@s.whatsapp.net" id="...">
//!   <picture type="preview" query="url">
//!     <tctoken><!-- raw token bytes (optional) --></tctoken>
//!   </picture>
//! </iq>
//!
//! <!-- Response (success) -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <picture id="123456789" url="https://..." direct_path="/v/..."/>
//! </iq>
//!
//! <!-- Response (not found) -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <picture>
//!     <error code="404" text="item-not-found"/>
//!   </picture>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::iq::tctoken::build_tc_token_node;
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, Server};
use wacore_binary::node::{Node, NodeContent};

/// Profile picture information.
#[derive(Debug, Clone)]
pub struct ProfilePicture {
    pub id: String,
    pub url: String,
    pub direct_path: Option<String>,
    /// SHA-256 hash for integrity/cache validation.
    pub hash: Option<String>,
}

/// Profile picture type (preview thumbnail or full-size).
#[derive(Debug, Clone, Copy, PartialEq, Eq, crate::StringEnum)]
pub enum ProfilePictureType {
    #[str = "preview"]
    Preview,
    #[str = "image"]
    Full,
}

/// Fetches the profile picture URL for a given JID.
#[derive(Debug, Clone)]
pub struct ProfilePictureSpec {
    pub jid: Jid,
    pub picture_type: ProfilePictureType,
    /// Optional tctoken to include in the IQ for privacy gating.
    pub tc_token: Option<Vec<u8>>,
    /// Current known picture ID. When set, the server can skip re-sending
    /// if the picture hasn't changed (cache optimization).
    pub existing_id: Option<String>,
}

impl ProfilePictureSpec {
    pub fn preview(jid: &Jid) -> Self {
        Self {
            jid: jid.clone(),
            picture_type: ProfilePictureType::Preview,
            tc_token: None,
            existing_id: None,
        }
    }

    pub fn full(jid: &Jid) -> Self {
        Self {
            jid: jid.clone(),
            picture_type: ProfilePictureType::Full,
            tc_token: None,
            existing_id: None,
        }
    }

    pub fn new(jid: &Jid, picture_type: ProfilePictureType) -> Self {
        Self {
            jid: jid.clone(),
            picture_type,
            tc_token: None,
            existing_id: None,
        }
    }

    /// Include a tctoken in the profile picture IQ for privacy gating.
    pub fn with_tc_token(mut self, token: Vec<u8>) -> Self {
        self.tc_token = Some(token);
        self
    }

    /// Set the existing picture ID for cache optimization.
    /// The server may return an empty result if the picture hasn't changed.
    pub fn with_existing_id(mut self, id: String) -> Self {
        self.existing_id = Some(id);
        self
    }
}

impl IqSpec for ProfilePictureSpec {
    type Response = Option<ProfilePicture>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let mut picture_builder = NodeBuilder::new("picture")
            .attr("type", self.picture_type.as_str())
            .attr("query", "url");

        if let Some(id) = &self.existing_id {
            picture_builder = picture_builder.attr("id", id);
        }

        // tctoken is a child of <picture>, matching WhatsApp Web's mixin merge pattern
        if let Some(token) = &self.tc_token {
            picture_builder = picture_builder.children([build_tc_token_node(token)]);
        }

        InfoQuery::get(
            "w:profile:picture",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![picture_builder.build()])),
        )
        .with_target_ref(&self.jid)
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let picture_node = match response.get_optional_child("picture") {
            Some(p) => p,
            None => return Ok(None),
        };

        // Check for error response
        if let Some(error_node) = picture_node.get_optional_child("error") {
            let code = error_node.attrs().optional_string("code");
            let code_str = code.as_deref().unwrap_or("0");
            if code_str == "404" || code_str == "401" {
                return Ok(None);
            }
            let text = error_node.attrs().optional_string("text");
            let text_str = text.as_deref().unwrap_or("unknown error");
            return Err(anyhow!("Profile picture error {}: {}", code_str, text_str));
        }

        let id = match picture_node.attrs().optional_string("id") {
            Some(s) => s.to_string(),
            // Empty <picture/> with no attributes = cache hit (picture unchanged)
            None => return Ok(None),
        };

        let url = match picture_node.attrs().optional_string("url") {
            Some(s) => s.to_string(),
            // <picture id="..."/> with no url = cache hit variant
            None => return Ok(None),
        };

        let direct_path = picture_node
            .attrs()
            .optional_string("direct_path")
            .map(|s| s.to_string());

        let hash = picture_node
            .attrs()
            .optional_string("hash")
            .map(|s| s.to_string());

        Ok(Some(ProfilePicture {
            id,
            url,
            direct_path,
            hash,
        }))
    }
}

/// Response from setting a profile picture.
#[derive(Debug, Clone)]
pub struct SetProfilePictureResponse {
    /// The server-assigned picture ID.
    pub id: String,
}

/// Sets or removes a profile picture.
///
/// ## Wire Format (Set)
/// ```xml
/// <iq xmlns="w:profile:picture" type="set" to="s.whatsapp.net" id="...">
///   <picture type="image">{binary image data}</picture>
/// </iq>
/// ```
///
/// ## Wire Format (Remove)
/// ```xml
/// <iq xmlns="w:profile:picture" type="set" to="s.whatsapp.net" id="...">
///   <picture type="image"/>
/// </iq>
/// ```
///
/// ## Response
/// ```xml
/// <iq type="result" from="s.whatsapp.net" id="...">
///   <picture id="123456789"/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetProfilePictureSpec {
    /// If Some, set picture for a group. If None, set for self.
    pub target: Option<Jid>,
    /// Image bytes. None means remove the picture.
    pub image_data: Option<Vec<u8>>,
}

impl SetProfilePictureSpec {
    /// Set own profile picture. Panics if `image_data` is empty (use `remove_own` instead).
    pub fn set_own(image_data: Vec<u8>) -> Self {
        assert!(
            !image_data.is_empty(),
            "image_data cannot be empty; use remove_own() to delete"
        );
        Self {
            target: None,
            image_data: Some(image_data),
        }
    }

    /// Remove own profile picture.
    pub fn remove_own() -> Self {
        Self {
            target: None,
            image_data: None,
        }
    }

    /// Set a group's profile picture. Panics if `image_data` is empty (use `remove_group` instead).
    pub fn set_group(group_jid: &Jid, image_data: Vec<u8>) -> Self {
        assert!(
            !image_data.is_empty(),
            "image_data cannot be empty; use remove_group() to delete"
        );
        Self {
            target: Some(group_jid.clone()),
            image_data: Some(image_data),
        }
    }

    /// Remove a group's profile picture.
    pub fn remove_group(group_jid: &Jid) -> Self {
        Self {
            target: Some(group_jid.clone()),
            image_data: None,
        }
    }
}

impl IqSpec for SetProfilePictureSpec {
    type Response = SetProfilePictureResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let mut picture_builder = NodeBuilder::new("picture").attr("type", "image");

        if let Some(data) = &self.image_data {
            picture_builder = picture_builder.bytes(data.clone());
        }

        let mut iq = InfoQuery::set(
            "w:profile:picture",
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![picture_builder.build()])),
        );

        if let Some(target) = &self.target {
            iq = iq.with_target_ref(target);
        }

        iq
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        if self.image_data.is_some() {
            // Set operation: server must return <picture id="..."/>
            let picture_node = response
                .get_optional_child("picture")
                .ok_or_else(|| anyhow!("Set picture response missing 'picture' child"))?;
            let id = picture_node
                .attrs()
                .optional_string("id")
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("Set picture response missing 'id' attribute"))?;
            Ok(SetProfilePictureResponse { id })
        } else {
            // Remove operation: server may return an empty result
            let id = response
                .get_optional_child("picture")
                .and_then(|p| p.attrs().optional_string("id").map(|s| s.to_string()))
                .unwrap_or_default();
            Ok(SetProfilePictureResponse { id })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_picture_spec_preview() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::preview(&jid);

        assert_eq!(spec.picture_type, ProfilePictureType::Preview);

        let iq = spec.build_iq();
        assert_eq!(iq.namespace, "w:profile:picture");
        assert_eq!(iq.target, Some(jid));

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "picture");
            assert!(nodes[0].attrs.get("type").is_some_and(|s| s == "preview"));
        }
    }

    #[test]
    fn test_profile_picture_spec_full() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::full(&jid);

        assert_eq!(spec.picture_type, ProfilePictureType::Full);

        let iq = spec.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert!(nodes[0].attrs.get("type").is_some_and(|s| s == "image"));
        }
    }

    #[test]
    fn test_profile_picture_spec_parse_success() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::preview(&jid);

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("picture")
                .attr("id", "123456789")
                .attr("url", "https://example.com/pic.jpg")
                .attr("direct_path", "/v/pic.jpg")
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert!(result.is_some());

        let pic = result.unwrap();
        assert_eq!(pic.id, "123456789");
        assert_eq!(pic.url, "https://example.com/pic.jpg");
        assert_eq!(pic.direct_path, Some("/v/pic.jpg".to_string()));
    }

    #[test]
    fn test_profile_picture_spec_parse_not_found() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::preview(&jid);

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("picture")
                .children([NodeBuilder::new("error")
                    .attr("code", "404")
                    .attr("text", "item-not-found")
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_profile_picture_spec_parse_no_picture_node() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::preview(&jid);

        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_profile_picture_spec_with_tc_token() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::preview(&jid).with_tc_token(vec![0xCA, 0xFE, 0xBA, 0xBE]);

        let iq = spec.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1, "IQ should have one child: picture");
            let picture = &nodes[0];
            assert_eq!(picture.tag, "picture");

            // tctoken is a child of picture (matching WhatsApp Web's mixin merge)
            let tctoken_children: Vec<_> = picture.get_children_by_tag("tctoken").collect();
            assert_eq!(tctoken_children.len(), 1);
            match &tctoken_children[0].content {
                Some(NodeContent::Bytes(data)) => {
                    assert_eq!(data, &[0xCA, 0xFE, 0xBA, 0xBE]);
                }
                _ => panic!("Expected binary content in tctoken node"),
            }
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_profile_picture_spec_without_tc_token() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::preview(&jid);

        let iq = spec.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1, "IQ should have one child: picture");
            let picture = &nodes[0];
            assert_eq!(picture.tag, "picture");
            let tctoken_children: Vec<_> = picture.get_children_by_tag("tctoken").collect();
            assert_eq!(tctoken_children.len(), 0, "No tctoken without token");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_set_profile_picture_spec_own() {
        let spec = SetProfilePictureSpec::set_own(vec![0xFF, 0xD8, 0xFF]);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "w:profile:picture");
        assert_eq!(iq.query_type.as_str(), "set");
        assert!(iq.target.is_none(), "Own picture should not have target");

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let picture = &nodes[0];
            assert_eq!(picture.tag, "picture");
            assert!(picture.attrs.get("type").is_some_and(|v| v == "image"));
            match &picture.content {
                Some(NodeContent::Bytes(data)) => {
                    assert_eq!(data, &[0xFF, 0xD8, 0xFF]);
                }
                _ => panic!("Expected binary content in picture node"),
            }
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_set_profile_picture_spec_group() {
        let group_jid: Jid = "123456789@g.us".parse().unwrap();
        let spec = SetProfilePictureSpec::set_group(&group_jid, vec![0x89, 0x50, 0x4E]);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "w:profile:picture");
        assert_eq!(iq.target, Some(group_jid));
    }

    #[test]
    fn test_set_profile_picture_spec_remove_own() {
        let spec = SetProfilePictureSpec::remove_own();
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let picture = &nodes[0];
            // Remove: picture node with no content
            assert!(
                picture.content.is_none(),
                "Remove should have no picture content"
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_set_profile_picture_spec_parse_response() {
        let spec = SetProfilePictureSpec::set_own(vec![0xFF, 0xD8]);
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("picture").attr("id", "987654321").build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.id, "987654321");
    }
}
