//! Media connection IQ specification.
//!
//! Wire format:
//! ```xml
//! <!-- Request -->
//! <iq xmlns="w:m" type="set" to="s.whatsapp.net" id="...">
//!   <media_conn/>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <media_conn auth="..." ttl="..." max_buckets="...">
//!     <host hostname="mmg.whatsapp.net"/>
//!     <host hostname="mmg-fna.whatsapp.net"/>
//!   </media_conn>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// Media connection host information.
#[derive(Debug, Clone)]
pub struct MediaConnHost {
    /// The hostname for media uploads/downloads.
    pub hostname: String,
}

/// Media connection response containing auth token and hosts.
#[derive(Debug, Clone)]
pub struct MediaConnResponse {
    /// Authentication token for media operations.
    pub auth: String,
    /// Time-to-live in seconds for this connection info.
    pub ttl: u64,
    /// Maximum number of buckets (optional).
    pub max_buckets: Option<u64>,
    /// List of available media hosts.
    pub hosts: Vec<MediaConnHost>,
}

/// Media connection IQ specification.
///
/// Requests media server connection details including authentication token
/// and available hosts for uploading/downloading media.
#[derive(Debug, Clone, Default)]
pub struct MediaConnSpec;

impl MediaConnSpec {
    /// Create a new media connection spec.
    pub fn new() -> Self {
        Self
    }
}

impl IqSpec for MediaConnSpec {
    type Response = MediaConnResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let media_conn_node = NodeBuilder::new("media_conn").build();

        InfoQuery::set(
            "w:m",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![media_conn_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let media_conn_node = response
            .get_optional_child("media_conn")
            .ok_or_else(|| anyhow!("Missing media_conn node in response"))?;

        let mut attrs = media_conn_node.attrs();
        let auth = attrs.string("auth");
        let ttl = attrs.optional_u64("ttl").unwrap_or(0);
        let max_buckets = attrs.optional_u64("max_buckets");

        let hosts = media_conn_node
            .get_children_by_tag("host")
            .iter()
            .map(|host_node| MediaConnHost {
                hostname: host_node.attrs().string("hostname"),
            })
            .collect();

        Ok(MediaConnResponse {
            auth,
            ttl,
            max_buckets,
            hosts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_conn_spec_build_iq() {
        let spec = MediaConnSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "w:m");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);
        assert!(iq.content.is_some());

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "media_conn");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_media_conn_spec_parse_response() {
        let spec = MediaConnSpec::new();

        // Build a mock response
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("media_conn")
                .attr("auth", "test-auth-token")
                .attr("ttl", "3600")
                .attr("max_buckets", "4")
                .children([
                    NodeBuilder::new("host")
                        .attr("hostname", "mmg.whatsapp.net")
                        .build(),
                    NodeBuilder::new("host")
                        .attr("hostname", "mmg-fna.whatsapp.net")
                        .build(),
                ])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();

        assert_eq!(result.auth, "test-auth-token");
        assert_eq!(result.ttl, 3600);
        assert_eq!(result.max_buckets, Some(4));
        assert_eq!(result.hosts.len(), 2);
        assert_eq!(result.hosts[0].hostname, "mmg.whatsapp.net");
        assert_eq!(result.hosts[1].hostname, "mmg-fna.whatsapp.net");
    }

    #[test]
    fn test_media_conn_spec_parse_response_missing_node() {
        let spec = MediaConnSpec::new();

        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response);
        assert!(result.is_err());
    }
}
