//! Pre-key IQ specifications.
//!
//! ## Fetch Pre-Keys Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="encrypt" type="get" to="s.whatsapp.net" id="...">
//!   <key>
//!     <user jid="1234567890:0@s.whatsapp.net"/>
//!     <user jid="0987654321:0@s.whatsapp.net"/>
//!   </key>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <list>
//!     <user jid="1234567890:0@s.whatsapp.net">
//!       <registration>...</registration>
//!       <type>...</type>
//!       <identity>...</identity>
//!       <key><id>...</id><value>...</value></key>
//!       <skey><id>...</id><value>...</value><signature>...</signature></skey>
//!     </user>
//!   </list>
//! </iq>
//! ```
//!
//! ## Pre-Key Count Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="encrypt" type="get" to="s.whatsapp.net" id="...">
//!   <count/>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <count value="42"/>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::prekeys::PreKeyUtils;
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

// Re-export PreKeyBundle for convenience
pub use crate::libsignal::protocol::PreKeyBundle;

/// Pre-key count response.
#[derive(Debug, Clone)]
pub struct PreKeyCountResponse {
    pub count: usize,
}

/// Queries the server for how many pre-keys are currently stored.
#[derive(Debug, Clone, Default)]
pub struct PreKeyCountSpec;

impl PreKeyCountSpec {
    pub fn new() -> Self {
        Self
    }
}

impl IqSpec for PreKeyCountSpec {
    type Response = PreKeyCountResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let count_node = NodeBuilder::new("count").build();

        InfoQuery::get(
            "encrypt",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![count_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let count_node = response
            .get_optional_child("count")
            .ok_or_else(|| anyhow!("Missing <count> node in response"))?;

        // Server may return <count/> without value attribute when count is 0,
        // or return an unparseable value. Default to 0 in these cases.
        let count_str = count_node.attrs().optional_string("value").unwrap_or("0");
        let count = count_str.parse::<usize>().unwrap_or(0);

        Ok(PreKeyCountResponse { count })
    }
}

/// Fetches pre-key bundles for a list of JIDs.
#[derive(Debug, Clone)]
pub struct PreKeyFetchSpec {
    pub jids: Vec<Jid>,
    pub reason: Option<String>,
}

impl PreKeyFetchSpec {
    pub fn new(jids: Vec<Jid>) -> Self {
        Self { jids, reason: None }
    }

    pub fn with_reason(jids: Vec<Jid>, reason: impl Into<String>) -> Self {
        Self {
            jids,
            reason: Some(reason.into()),
        }
    }
}

impl IqSpec for PreKeyFetchSpec {
    type Response = std::collections::HashMap<Jid, PreKeyBundle>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let content = PreKeyUtils::build_fetch_prekeys_request(&self.jids, self.reason.as_deref());

        InfoQuery::get(
            "encrypt",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![content])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        PreKeyUtils::parse_prekeys_response(response)
    }
}

/// Digest Key Bundle Wire Format
/// ```xml
/// <!-- Request -->
/// <iq xmlns="encrypt" type="get" to="s.whatsapp.net" id="...">
///   <digest/>
/// </iq>
///
/// <!-- Response -->
/// <iq from="s.whatsapp.net" id="..." type="result">
///   <digest>[binary hash of server-side key bundle]</digest>
/// </iq>
/// ```
///
/// Used to validate that the server-side key bundle matches local keys.
/// If the hash doesn't match, prekeys need to be re-uploaded.
///
/// Verified against WhatsApp Web JS (WAWebDigestKeyJob).
#[derive(Debug, Clone, Default)]
pub struct DigestKeyBundleSpec;

impl DigestKeyBundleSpec {
    pub fn new() -> Self {
        Self
    }
}

/// Response from digest key bundle query.
#[derive(Debug, Clone)]
pub struct DigestKeyBundleResponse {
    /// The digest hash bytes from the server (20 bytes SHA-1 hash).
    pub digest: Option<Vec<u8>>,
}

impl IqSpec for DigestKeyBundleSpec {
    type Response = DigestKeyBundleResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let digest_node = NodeBuilder::new("digest").build();

        InfoQuery::get(
            "encrypt",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![digest_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let digest_node = response.get_optional_child("digest");

        let digest = digest_node.and_then(|node| {
            node.content.as_ref().and_then(|content| match content {
                NodeContent::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
        });

        Ok(DigestKeyBundleResponse { digest })
    }
}

/// Pre-Key Upload Wire Format
/// ```xml
/// <!-- Request -->
/// <iq xmlns="encrypt" type="set" to="s.whatsapp.net" id="...">
///   <registration>[4-byte BE registration ID]</registration>
///   <type>[1-byte: 5 for Signal protocol]</type>
///   <identity>[32-byte identity public key]</identity>
///   <list>
///     <key><id>[3-byte BE key ID]</id><value>[32-byte public key]</value></key>
///     ...
///   </list>
///   <skey>
///     <id>[3-byte BE signed pre-key ID]</id>
///     <value>[32-byte signed pre-key public]</value>
///     <signature>[64-byte signature]</signature>
///   </skey>
/// </iq>
///
/// <!-- Response -->
/// <iq from="s.whatsapp.net" id="..." type="result"/>
/// ```
///
/// Verified against WhatsApp Web JS (WAWebUploadPreKeysJob).
#[derive(Debug, Clone)]
pub struct PreKeyUploadSpec {
    /// 4-byte registration ID
    pub registration_id: u32,
    /// 32-byte identity public key
    pub identity_key_bytes: Vec<u8>,
    /// Signed pre-key ID (uses lower 3 bytes)
    pub signed_pre_key_id: u32,
    /// 32-byte signed pre-key public
    pub signed_pre_key_public_bytes: Vec<u8>,
    /// 64-byte signature
    pub signed_pre_key_signature: Vec<u8>,
    /// Pre-keys to upload: (id, 32-byte public key)
    pub pre_keys: Vec<(u32, Vec<u8>)>,
}

impl PreKeyUploadSpec {
    /// Create a new pre-key upload spec.
    pub fn new(
        registration_id: u32,
        identity_key_bytes: Vec<u8>,
        signed_pre_key_id: u32,
        signed_pre_key_public_bytes: Vec<u8>,
        signed_pre_key_signature: Vec<u8>,
        pre_keys: Vec<(u32, Vec<u8>)>,
    ) -> Self {
        Self {
            registration_id,
            identity_key_bytes,
            signed_pre_key_id,
            signed_pre_key_public_bytes,
            signed_pre_key_signature,
            pre_keys,
        }
    }
}

impl IqSpec for PreKeyUploadSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let content = PreKeyUtils::build_upload_prekeys_request(
            self.registration_id,
            self.identity_key_bytes.clone(),
            self.signed_pre_key_id,
            self.signed_pre_key_public_bytes.clone(),
            self.signed_pre_key_signature.clone(),
            &self.pre_keys,
        );

        InfoQuery::set(
            "encrypt",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(content)),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        // Pre-key upload just needs a successful response
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prekey_count_spec_build_iq() {
        let spec = PreKeyCountSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "encrypt");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "count");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_prekey_count_spec_parse_response() {
        let spec = PreKeyCountSpec::new();

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("count").attr("value", "42").build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.count, 42);
    }

    #[test]
    fn test_prekey_count_spec_parse_response_missing_value() {
        let spec = PreKeyCountSpec::new();

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("count").build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.count, 0); // Default to 0 if missing
    }

    #[test]
    fn test_prekey_fetch_spec_build_iq() {
        let jids = vec![
            "1234567890:0@s.whatsapp.net".parse().unwrap(),
            "0987654321:0@s.whatsapp.net".parse().unwrap(),
        ];
        let spec = PreKeyFetchSpec::new(jids);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "encrypt");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "key");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_prekey_fetch_spec_with_reason() {
        let jids = vec!["1234567890:0@s.whatsapp.net".parse().unwrap()];
        let spec = PreKeyFetchSpec::with_reason(jids, "retry");

        assert_eq!(spec.reason, Some("retry".to_string()));
    }

    #[test]
    fn test_digest_key_bundle_spec_build_iq() {
        let spec = DigestKeyBundleSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "encrypt");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "digest");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_digest_key_bundle_spec_parse_response() {
        let spec = DigestKeyBundleSpec::new();
        let digest_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("digest")
                .bytes(digest_bytes.clone())
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.digest, Some(digest_bytes));
    }

    #[test]
    fn test_digest_key_bundle_spec_parse_response_empty() {
        let spec = DigestKeyBundleSpec::new();

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("digest").build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.digest, None);
    }

    #[test]
    fn test_prekey_upload_spec_build_iq() {
        let spec = PreKeyUploadSpec::new(
            12345,                                            // registration_id
            vec![1u8; 32],                                    // identity_key_bytes
            1,                                                // signed_pre_key_id
            vec![2u8; 32],                                    // signed_pre_key_public_bytes
            vec![3u8; 64],                                    // signed_pre_key_signature
            vec![(100, vec![4u8; 32]), (101, vec![5u8; 32])], // pre_keys
        );
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "encrypt");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            // Expected: registration, type, identity, list, skey
            assert_eq!(nodes.len(), 5);
            assert_eq!(nodes[0].tag, "registration");
            assert_eq!(nodes[1].tag, "type");
            assert_eq!(nodes[2].tag, "identity");
            assert_eq!(nodes[3].tag, "list");
            assert_eq!(nodes[4].tag, "skey");

            // Check that list has 2 pre-keys
            if let Some(list_children) = nodes[3].children() {
                assert_eq!(list_children.len(), 2);
                assert_eq!(list_children[0].tag, "key");
                assert_eq!(list_children[1].tag, "key");
            } else {
                panic!("Expected list to have children");
            }
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_prekey_upload_spec_parse_response() {
        let spec = PreKeyUploadSpec::new(
            12345,
            vec![1u8; 32],
            1,
            vec![2u8; 32],
            vec![3u8; 64],
            vec![(100, vec![4u8; 32])],
        );

        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response);
        assert!(result.is_ok());
    }
}
