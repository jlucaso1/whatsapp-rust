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
use crate::protocol::ProtocolNode;
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// Media connection host information.
#[derive(Debug, Clone)]
pub struct MediaConnHost {
    pub hostname: String,
}

/// Extended media connection host with all attributes (for server-side responses).
#[derive(Debug, Clone)]
pub struct MediaConnHostExtended {
    pub hostname: String,
    pub host_type: String, // "primary" or "fallback"
    pub fallback_hostname: Option<String>,
    pub ip4: Option<String>,
    pub ip6: Option<String>,
    pub fallback_ip4: Option<String>,
    pub fallback_ip6: Option<String>,
    pub upload: bool,
    pub download: bool,
    pub download_categories: Vec<String>,
    pub download_buckets: Vec<String>,
}

impl MediaConnHostExtended {
    /// Create a simple host (for fallback hosts).
    pub fn simple(hostname: String, host_type: String) -> Self {
        Self {
            hostname,
            host_type,
            fallback_hostname: None,
            ip4: None,
            ip6: None,
            fallback_ip4: None,
            fallback_ip6: None,
            upload: false,
            download: false,
            download_categories: Vec::new(),
            download_buckets: Vec::new(),
        }
    }

    /// Create a primary host with upload/download capabilities.
    pub fn primary(
        hostname: String,
        fallback_hostname: String,
        ip4: String,
        ip6: String,
        download_categories: Vec<String>,
        download_buckets: Vec<String>,
    ) -> Self {
        Self {
            hostname,
            host_type: "primary".to_string(),
            fallback_hostname: Some(fallback_hostname),
            ip4: Some(ip4.clone()),
            ip6: Some(ip6.clone()),
            fallback_ip4: Some(ip4),
            fallback_ip6: Some(ip6),
            upload: true,
            download: true,
            download_categories,
            download_buckets,
        }
    }
}

impl ProtocolNode for MediaConnHostExtended {
    fn tag(&self) -> &'static str {
        "host"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("host")
            .attr("hostname", &self.hostname)
            .attr("type", &self.host_type);

        if let Some(ref fallback_hostname) = self.fallback_hostname {
            builder = builder.attr("fallback_hostname", fallback_hostname);
        }
        if let Some(ref ip4) = self.ip4 {
            builder = builder.attr("ip4", ip4);
        }
        if let Some(ref ip6) = self.ip6 {
            builder = builder.attr("ip6", ip6);
        }
        if let Some(ref fallback_ip4) = self.fallback_ip4 {
            builder = builder.attr("fallback_ip4", fallback_ip4);
        }
        if let Some(ref fallback_ip6) = self.fallback_ip6 {
            builder = builder.attr("fallback_ip6", fallback_ip6);
        }

        // Build children nodes if upload/download are enabled
        let mut children = Vec::new();

        if self.upload {
            children.push(NodeBuilder::new("upload").build());
        }

        if self.download {
            // Build download categories
            let download_cat_nodes: Vec<Node> = self
                .download_categories
                .iter()
                .map(|cat| NodeBuilder::new(cat).build())
                .collect();

            // Build download buckets
            let download_bucket_nodes: Vec<Node> = self
                .download_buckets
                .iter()
                .map(|bucket| NodeBuilder::new(bucket).build())
                .collect();

            children.push(
                NodeBuilder::new("download")
                    .children(download_cat_nodes)
                    .build(),
            );

            if !download_bucket_nodes.is_empty() {
                children.push(
                    NodeBuilder::new("download_buckets")
                        .children(download_bucket_nodes)
                        .build(),
                );
            }
        }

        if !children.is_empty() {
            builder = builder.children(children);
        }

        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        if node.tag != "host" {
            return Err(anyhow!("expected <host>, got <{}>", node.tag));
        }

        let mut attrs = node.attrs();
        let hostname = attrs
            .optional_string("hostname")
            .ok_or_else(|| anyhow!("missing hostname attribute"))?
            .to_string();
        let host_type = attrs
            .optional_string("type")
            .unwrap_or("primary")
            .to_string();

        Ok(Self {
            hostname,
            host_type,
            fallback_hostname: attrs.optional_string("fallback_hostname").map(String::from),
            ip4: attrs.optional_string("ip4").map(String::from),
            ip6: attrs.optional_string("ip6").map(String::from),
            fallback_ip4: attrs.optional_string("fallback_ip4").map(String::from),
            fallback_ip6: attrs.optional_string("fallback_ip6").map(String::from),
            upload: node.get_optional_child("upload").is_some(),
            download: node.get_optional_child("download").is_some(),
            download_categories: node
                .get_optional_child("download")
                .and_then(|d| d.children())
                .map(|children| children.iter().map(|c| c.tag.clone()).collect())
                .unwrap_or_default(),
            download_buckets: node
                .get_optional_child("download_buckets")
                .and_then(|d| d.children())
                .map(|children| children.iter().map(|c| c.tag.clone()).collect())
                .unwrap_or_default(),
        })
    }
}

/// Media connection response containing auth token and hosts.
#[derive(Debug, Clone)]
pub struct MediaConnResponse {
    pub auth: String,
    pub ttl: u64,
    pub max_buckets: Option<u64>,
    pub hosts: Vec<MediaConnHost>,
}

/// Extended media connection response with all server-side attributes.
#[derive(Debug, Clone)]
pub struct MediaConnResponseExtended {
    pub auth: String,
    pub ttl: u64,
    pub auth_ttl: Option<u64>,
    pub max_buckets: Option<u64>,
    pub ip_token: Option<String>,
    pub set_ip_token: Option<u64>,
    pub hosts: Vec<MediaConnHostExtended>,
}

impl MediaConnResponseExtended {
    /// Create a simple media conn response for mock servers.
    pub fn mock(auth: String, ttl: u64, hosts: Vec<MediaConnHostExtended>) -> Self {
        Self {
            auth,
            ttl,
            auth_ttl: Some(21600), // 6 hours
            max_buckets: Some(12),
            ip_token: Some("MOCK_IP_TOKEN".to_string()),
            set_ip_token: Some(1),
            hosts,
        }
    }
}

impl ProtocolNode for MediaConnResponseExtended {
    fn tag(&self) -> &'static str {
        "media_conn"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("media_conn")
            .attr("auth", &self.auth)
            .attr("ttl", self.ttl.to_string());

        if let Some(auth_ttl) = self.auth_ttl {
            builder = builder.attr("auth_ttl", auth_ttl.to_string());
        }
        if let Some(max_buckets) = self.max_buckets {
            builder = builder.attr("max_buckets", max_buckets.to_string());
        }
        if let Some(ref ip_token) = self.ip_token {
            builder = builder.attr("ip_token", ip_token);
        }
        if let Some(set_ip_token) = self.set_ip_token {
            builder = builder.attr("set_ip_token", set_ip_token.to_string());
        }

        let host_nodes: Vec<Node> = self.hosts.into_iter().map(|h| h.into_node()).collect();
        builder = builder.children(host_nodes);

        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        if node.tag != "media_conn" {
            return Err(anyhow!("expected <media_conn>, got <{}>", node.tag));
        }

        let mut attrs = node.attrs();
        let auth = attrs
            .optional_string("auth")
            .ok_or_else(|| anyhow!("missing auth attribute"))?
            .to_string();
        let ttl = attrs.optional_u64("ttl").unwrap_or(0);
        let auth_ttl = attrs.optional_u64("auth_ttl");
        let max_buckets = attrs.optional_u64("max_buckets");
        let ip_token = attrs.optional_string("ip_token").map(String::from);
        let set_ip_token = attrs.optional_u64("set_ip_token");

        let mut hosts = Vec::new();
        for host_node in node.get_children_by_tag("host") {
            hosts.push(MediaConnHostExtended::try_from_node(host_node)?);
        }

        Ok(Self {
            auth,
            ttl,
            auth_ttl,
            max_buckets,
            ip_token,
            set_ip_token,
            hosts,
        })
    }
}

/// Requests media server connection details (auth token and hosts).
#[derive(Debug, Clone, Default)]
pub struct MediaConnSpec;

impl MediaConnSpec {
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
        let auth = attrs
            .optional_string("auth")
            .ok_or_else(|| anyhow!("Missing 'auth' attribute in media_conn response"))?
            .to_string();
        let ttl = attrs.optional_u64("ttl").unwrap_or(0);
        let max_buckets = attrs.optional_u64("max_buckets");

        let mut hosts = Vec::new();
        for host_node in media_conn_node.get_children_by_tag("host") {
            let hostname = host_node
                .attrs()
                .optional_string("hostname")
                .ok_or_else(|| anyhow!("Missing 'hostname' attribute in host node"))?
                .to_string();
            hosts.push(MediaConnHost { hostname });
        }

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

    #[test]
    fn test_media_conn_host_extended_round_trip() {
        let host = MediaConnHostExtended::primary(
            "127.0.0.1:3000".to_string(),
            "127.0.0.1:3000".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            vec!["image".to_string(), "video".to_string()],
            vec!["0".to_string()],
        );

        let node = host.clone().into_node();
        assert_eq!(node.tag, "host");

        let parsed = MediaConnHostExtended::try_from_node(&node).unwrap();
        assert_eq!(parsed.hostname, host.hostname);
        assert_eq!(parsed.host_type, "primary");
        assert!(parsed.upload);
        assert!(parsed.download);
        assert_eq!(parsed.download_categories.len(), 2);
        assert_eq!(parsed.download_buckets.len(), 1);
    }

    #[test]
    fn test_media_conn_response_extended_round_trip() {
        let hosts = vec![
            MediaConnHostExtended::primary(
                "localhost:3000".to_string(),
                "localhost:3000".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                vec!["image".to_string()],
                vec!["0".to_string()],
            ),
            MediaConnHostExtended::simple("localhost:3000".to_string(), "fallback".to_string()),
        ];

        let response = MediaConnResponseExtended::mock("test-auth".to_string(), 300, hosts);

        let node = response.clone().into_node();
        assert_eq!(node.tag, "media_conn");

        let parsed = MediaConnResponseExtended::try_from_node(&node).unwrap();
        assert_eq!(parsed.auth, "test-auth");
        assert_eq!(parsed.ttl, 300);
        assert_eq!(parsed.auth_ttl, Some(21600));
        assert_eq!(parsed.max_buckets, Some(12));
        assert_eq!(parsed.ip_token, Some("MOCK_IP_TOKEN".to_string()));
        assert_eq!(parsed.hosts.len(), 2);
        assert_eq!(parsed.hosts[0].host_type, "primary");
        assert_eq!(parsed.hosts[1].host_type, "fallback");
    }
}
