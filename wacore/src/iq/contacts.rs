//! Contact-related IQ specifications.
//!
//! ## Profile Picture Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="w:profile:picture" type="get" to="s.whatsapp.net" target="1234567890@s.whatsapp.net" id="...">
//!   <picture type="preview" query="url"/>
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
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// Profile picture information.
#[derive(Debug, Clone)]
pub struct ProfilePicture {
    pub id: String,
    pub url: String,
    pub direct_path: Option<String>,
}

/// Profile picture type (preview thumbnail or full-size).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfilePictureType {
    #[default]
    Preview,
    Full,
}

impl ProfilePictureType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Full => "image",
        }
    }
}

/// Fetches the profile picture URL for a given JID.
#[derive(Debug, Clone)]
pub struct ProfilePictureSpec {
    pub jid: Jid,
    pub picture_type: ProfilePictureType,
}

impl ProfilePictureSpec {
    pub fn preview(jid: &Jid) -> Self {
        Self {
            jid: jid.clone(),
            picture_type: ProfilePictureType::Preview,
        }
    }

    pub fn full(jid: &Jid) -> Self {
        Self {
            jid: jid.clone(),
            picture_type: ProfilePictureType::Full,
        }
    }

    pub fn new(jid: &Jid, picture_type: ProfilePictureType) -> Self {
        Self {
            jid: jid.clone(),
            picture_type,
        }
    }
}

impl IqSpec for ProfilePictureSpec {
    type Response = Option<ProfilePicture>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let picture_node = NodeBuilder::new("picture")
            .attr("type", self.picture_type.as_str())
            .attr("query", "url")
            .build();

        InfoQuery::get(
            "w:profile:picture",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![picture_node])),
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
            .ok_or_else(|| anyhow!("Picture response missing 'id' attribute"))?;

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
            assert_eq!(
                nodes[0].attrs.get("type").and_then(|s| s.as_str()),
                Some("preview")
            );
        }
    }

    #[test]
    fn test_profile_picture_spec_full() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let spec = ProfilePictureSpec::full(&jid);

        assert_eq!(spec.picture_type, ProfilePictureType::Full);

        let iq = spec.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(
                nodes[0].attrs.get("type").and_then(|s| s.as_str()),
                Some("image")
            );
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
}
