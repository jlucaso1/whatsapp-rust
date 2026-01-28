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

use crate::iq::node::{required_attr, required_child};
use crate::iq::spec::IqSpec;
use crate::prekeys::PreKeyUtils;
use crate::protocol::ProtocolNode;
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

// Re-export PreKeyBundle for convenience
pub use crate::libsignal::protocol::{PreKeyBundle, PublicKey};

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
    /// Identity public key
    pub identity_key: PublicKey,
    /// Signed pre-key ID (uses lower 3 bytes)
    pub signed_pre_key_id: u32,
    /// Signed pre-key public
    pub signed_pre_key_public: PublicKey,
    /// 64-byte signature
    pub signed_pre_key_signature: Vec<u8>,
    /// Pre-keys to upload: (id, public key)
    pub pre_keys: Vec<(u32, PublicKey)>,
}

impl PreKeyUploadSpec {
    /// Create a new pre-key upload spec.
    pub fn new(
        registration_id: u32,
        identity_key: PublicKey,
        signed_pre_key_id: u32,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        pre_keys: Vec<(u32, PublicKey)>,
    ) -> Self {
        Self {
            registration_id,
            identity_key,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            pre_keys,
        }
    }
}

impl IqSpec for PreKeyUploadSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        // Convert PublicKeys to 32-byte raw values for the wire
        let pre_keys_bytes: Vec<(u32, Vec<u8>)> = self
            .pre_keys
            .iter()
            .map(|(id, pk)| (*id, pk.public_key_bytes().to_vec()))
            .collect();

        let content = PreKeyUtils::build_upload_prekeys_request(
            self.registration_id,
            self.identity_key.public_key_bytes().to_vec(),
            self.signed_pre_key_id,
            self.signed_pre_key_public.public_key_bytes().to_vec(),
            self.signed_pre_key_signature.clone(),
            &pre_keys_bytes,
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

// ============================================================================
// Bidirectional ProtocolNode Types for PreKey Responses
// ============================================================================
//
// These types implement ProtocolNode for both building (server-side) and
// parsing (client-side) prekey bundle responses. The mock-server uses
// `into_node()` to build responses, while the client can use `try_from_node()`
// to parse them.

/// Helper function to truncate u32 to 3-byte big-endian representation.
fn truncate_to_3bytes(id: u32) -> Vec<u8> {
    debug_assert!(id <= 0x00FF_FFFF, "prekey id exceeds 3-byte range: {id}");
    id.to_be_bytes()[1..].to_vec()
}

/// Helper function to expand 3-byte big-endian to u32.
fn expand_from_3bytes(bytes: &[u8]) -> Result<u32, anyhow::Error> {
    if bytes.len() != 3 {
        return Err(anyhow!("Expected 3 bytes for ID, got {}", bytes.len()));
    }
    Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
}

/// Signed prekey node: `<skey><id/><value/><signature/></skey>`
///
/// Wire format:
/// ```xml
/// <skey>
///   <id>[3-byte BE u32]</id>
///   <value>[32-byte public key]</value>
///   <signature>[64-byte signature]</signature>
/// </skey>
/// ```
#[derive(Debug, Clone)]
pub struct SignedPreKeyNode {
    pub id: u32,
    pub public_bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedPreKeyNode {
    pub fn new(id: u32, public_bytes: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            id,
            public_bytes,
            signature,
        }
    }
}

impl ProtocolNode for SignedPreKeyNode {
    fn tag(&self) -> &'static str {
        "skey"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("skey")
            .children([
                NodeBuilder::new("id")
                    .bytes(truncate_to_3bytes(self.id))
                    .build(),
                NodeBuilder::new("value").bytes(self.public_bytes).build(),
                NodeBuilder::new("signature").bytes(self.signature).build(),
            ])
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        if node.tag != "skey" {
            return Err(anyhow!("expected <skey>, got <{}>", node.tag));
        }

        let id_node = required_child(node, "id")?;
        let id_bytes = id_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <id>"))?;
        let id = expand_from_3bytes(id_bytes)?;

        let value_node = required_child(node, "value")?;
        let public_bytes = value_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <value>"))?;
        if public_bytes.len() != 32 {
            return Err(anyhow!("signed prekey public key must be 32 bytes"));
        }

        let sig_node = required_child(node, "signature")?;
        let signature = sig_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <signature>"))?;
        if signature.len() != 64 {
            return Err(anyhow!("signed prekey signature must be 64 bytes"));
        }

        Ok(Self {
            id,
            public_bytes,
            signature,
        })
    }
}

/// One-time prekey node: `<key><id/><value/></key>`
///
/// Wire format:
/// ```xml
/// <key>
///   <id>[3-byte BE u32]</id>
///   <value>[32-byte public key]</value>
/// </key>
/// ```
#[derive(Debug, Clone)]
pub struct OneTimePreKeyNode {
    pub id: u32,
    pub public_bytes: Vec<u8>,
}

impl OneTimePreKeyNode {
    pub fn new(id: u32, public_bytes: Vec<u8>) -> Self {
        Self { id, public_bytes }
    }
}

impl ProtocolNode for OneTimePreKeyNode {
    fn tag(&self) -> &'static str {
        "key"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("key")
            .children([
                NodeBuilder::new("id")
                    .bytes(truncate_to_3bytes(self.id))
                    .build(),
                NodeBuilder::new("value").bytes(self.public_bytes).build(),
            ])
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        if node.tag != "key" {
            return Err(anyhow!("expected <key>, got <{}>", node.tag));
        }

        let id_node = required_child(node, "id")?;
        let id_bytes = id_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <id>"))?;
        let id = expand_from_3bytes(id_bytes)?;

        let value_node = required_child(node, "value")?;
        let public_bytes = value_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <value>"))?;
        if public_bytes.len() != 32 {
            return Err(anyhow!("one-time prekey public key must be 32 bytes"));
        }

        Ok(Self { id, public_bytes })
    }
}

/// Complete prekey bundle user node: `<user jid="..." type="result">...</user>`
///
/// Wire format:
/// ```xml
/// <user jid="..." type="result">
///   <registration>[4-byte BE u32]</registration>
///   <type>[0x05 = Curve25519]</type>
///   <identity>[32-byte raw public key]</identity>
///   <skey>...</skey>
///   <key>...</key>                              <!-- optional -->
///   <device-identity>...</device-identity>       <!-- optional, companion only -->
/// </user>
/// ```
///
/// This node represents a complete prekey bundle response for a single user/device.
/// Both client and server can use this type:
/// - **Server**: Use `from_bundle()` + `into_node()` to build responses
/// - **Client**: Use `try_from_node()` to parse responses
#[derive(Debug, Clone)]
pub struct PreKeyBundleUserNode {
    pub jid: Jid,
    pub registration_id: u32,
    pub identity_key: Vec<u8>, // Must be 32 bytes (raw key, not 33-byte serialized)
    pub signed_pre_key: SignedPreKeyNode,
    pub one_time_pre_key: Option<OneTimePreKeyNode>,
    pub device_identity: Option<Vec<u8>>, // ADVSignedDeviceIdentity protobuf (companion only)
}

impl PreKeyBundleUserNode {
    /// Create a PreKeyBundleUserNode from a PreKeyBundle.
    ///
    /// The `device_identity` parameter should be provided for companion devices
    /// (device ID != 0) and contains the ADVSignedDeviceIdentity protobuf bytes.
    pub fn from_bundle(
        jid: Jid,
        bundle: &PreKeyBundle,
        device_identity: Option<Vec<u8>>,
    ) -> Result<Self, anyhow::Error> {
        let registration_id = bundle.registration_id()?;

        // Identity key must be 32 bytes (raw key).
        // PublicKey::public_key_bytes() returns the raw 32-byte key without the 0x05 prefix.
        let identity_key = bundle
            .identity_key()?
            .public_key()
            .public_key_bytes()
            .to_vec();

        let signed_pre_key_id: u32 = bundle.signed_pre_key_id()?.into();
        let signed_pre_key_public = bundle.signed_pre_key_public()?.public_key_bytes().to_vec();
        let signed_pre_key_signature = bundle.signed_pre_key_signature()?.to_vec();

        let signed_pre_key = SignedPreKeyNode::new(
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
        );

        // Optional one-time prekey
        let one_time_pre_key = match (bundle.pre_key_id()?, bundle.pre_key_public()?) {
            (Some(id), Some(pk)) => {
                let pre_key_id: u32 = id.into();
                let public_bytes = pk.public_key_bytes().to_vec();
                Some(OneTimePreKeyNode::new(pre_key_id, public_bytes))
            }
            _ => None,
        };

        Ok(Self {
            jid,
            registration_id,
            identity_key,
            signed_pre_key,
            one_time_pre_key,
            device_identity,
        })
    }
}

impl ProtocolNode for PreKeyBundleUserNode {
    fn tag(&self) -> &'static str {
        "user"
    }

    fn into_node(self) -> Node {
        let mut children = vec![
            // Registration ID (4 bytes big-endian)
            NodeBuilder::new("registration")
                .bytes(self.registration_id.to_be_bytes().to_vec())
                .build(),
            // Key type: 0x05 = Curve25519
            NodeBuilder::new("type").bytes(vec![5]).build(),
            // Identity key (32 bytes raw public key)
            NodeBuilder::new("identity")
                .bytes(self.identity_key)
                .build(),
            // Signed prekey
            self.signed_pre_key.into_node(),
        ];

        // Add optional one-time prekey
        if let Some(otpk) = self.one_time_pre_key {
            children.push(otpk.into_node());
        }

        // Add optional device identity (required for companion devices)
        if let Some(dev_id) = self.device_identity {
            children.push(NodeBuilder::new("device-identity").bytes(dev_id).build());
        }

        NodeBuilder::new("user")
            .attr("jid", self.jid.to_string())
            .attr("type", "result")
            .children(children)
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        if node.tag != "user" {
            return Err(anyhow!("expected <user>, got <{}>", node.tag));
        }

        let jid_str = required_attr(node, "jid")?;
        let jid = jid_str.parse()?;

        // Parse registration ID (4 bytes big-endian)
        let reg_node = required_child(node, "registration")?;
        let reg_bytes = reg_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <registration>"))?;
        if reg_bytes.len() != 4 {
            return Err(anyhow!("registration ID must be 4 bytes"));
        }
        let registration_id =
            u32::from_be_bytes([reg_bytes[0], reg_bytes[1], reg_bytes[2], reg_bytes[3]]);

        // Parse identity key (32 bytes)
        let identity_node = required_child(node, "identity")?;
        let identity_key = identity_node
            .content
            .as_ref()
            .and_then(|c| match c {
                NodeContent::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing bytes in <identity>"))?;
        if identity_key.len() != 32 {
            return Err(anyhow!("identity key must be 32 bytes"));
        }

        // Parse signed prekey
        let skey_node = required_child(node, "skey")?;
        let signed_pre_key = SignedPreKeyNode::try_from_node(skey_node)?;

        // Parse optional one-time prekey
        let one_time_pre_key = match node.get_optional_child("key") {
            Some(n) => Some(OneTimePreKeyNode::try_from_node(n)?),
            None => None,
        };

        // Parse optional device identity
        let device_identity = match node.get_optional_child("device-identity") {
            Some(n) => match &n.content {
                Some(NodeContent::Bytes(b)) => Some(b.clone()),
                _ => return Err(anyhow!("device-identity must be bytes")),
            },
            None => None,
        };

        Ok(Self {
            jid,
            registration_id,
            identity_key,
            signed_pre_key,
            one_time_pre_key,
            device_identity,
        })
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
        let pk = |b| PublicKey::from_djb_public_key_bytes(&[b; 32]).unwrap();

        let spec = PreKeyUploadSpec::new(
            12345,                            // registration_id
            pk(1),                            // identity_key
            1,                                // signed_pre_key_id
            pk(2),                            // signed_pre_key_public
            vec![3u8; 64],                    // signed_pre_key_signature
            vec![(100, pk(4)), (101, pk(5))], // pre_keys
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
        let pk = |b| PublicKey::from_djb_public_key_bytes(&[b; 32]).unwrap();

        let spec = PreKeyUploadSpec::new(12345, pk(1), 1, pk(2), vec![3u8; 64], vec![(100, pk(4))]);

        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response);
        assert!(result.is_ok());
    }

    // ========================================================================
    // Tests for bidirectional ProtocolNode types
    // ========================================================================

    #[test]
    fn test_truncate_to_3bytes() {
        assert_eq!(truncate_to_3bytes(0x00345678), vec![0x34, 0x56, 0x78]);
        assert_eq!(truncate_to_3bytes(0x00000001), vec![0x00, 0x00, 0x01]);
        assert_eq!(truncate_to_3bytes(0x00ABCDEF), vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_expand_from_3bytes() {
        assert_eq!(expand_from_3bytes(&[0x34, 0x56, 0x78]).unwrap(), 0x00345678);
        assert_eq!(expand_from_3bytes(&[0x00, 0x00, 0x01]).unwrap(), 0x00000001);
        assert_eq!(expand_from_3bytes(&[0xAB, 0xCD, 0xEF]).unwrap(), 0x00ABCDEF);
    }

    #[test]
    fn test_signed_prekey_node_round_trip() {
        // Use an ID that fits in 3 bytes (0x00XXXXXX)
        let original = SignedPreKeyNode::new(0x00345678, vec![1; 32], vec![2; 64]);
        let node = original.clone().into_node();

        assert_eq!(node.tag, "skey");

        let parsed = SignedPreKeyNode::try_from_node(&node).unwrap();
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.public_bytes, original.public_bytes);
        assert_eq!(parsed.signature, original.signature);
    }

    #[test]
    fn test_onetime_prekey_node_round_trip() {
        let original = OneTimePreKeyNode::new(0xABCDEF, vec![3; 32]);
        let node = original.clone().into_node();

        assert_eq!(node.tag, "key");

        let parsed = OneTimePreKeyNode::try_from_node(&node).unwrap();
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.public_bytes, original.public_bytes);
    }

    #[test]
    fn test_prekey_bundle_user_node_structure() {
        let jid: Jid = "1234567890:33@s.whatsapp.net".parse().unwrap();
        let user_node = PreKeyBundleUserNode {
            jid: jid.clone(),
            registration_id: 12345,
            identity_key: vec![1; 32],
            signed_pre_key: SignedPreKeyNode::new(100, vec![2; 32], vec![3; 64]),
            one_time_pre_key: Some(OneTimePreKeyNode::new(200, vec![4; 32])),
            device_identity: Some(vec![5; 128]),
        };

        let node = user_node.into_node();

        assert_eq!(node.tag, "user");
        assert_eq!(
            node.attrs().optional_string("jid"),
            Some(jid.to_string().as_str())
        );
        assert_eq!(node.attrs().optional_string("type"), Some("result"));

        // Verify children count (registration, type, identity, skey, key, device-identity)
        if let Some(children) = node.children() {
            assert_eq!(children.len(), 6);
            assert_eq!(children[0].tag, "registration");
            assert_eq!(children[1].tag, "type");
            assert_eq!(children[2].tag, "identity");
            assert_eq!(children[3].tag, "skey");
            assert_eq!(children[4].tag, "key");
            assert_eq!(children[5].tag, "device-identity");
        } else {
            panic!("Expected user node to have children");
        }
    }

    #[test]
    fn test_prekey_bundle_user_node_round_trip() {
        let jid: Jid = "1234567890:33@s.whatsapp.net".parse().unwrap();
        let original = PreKeyBundleUserNode {
            jid: jid.clone(),
            registration_id: 12345,
            identity_key: vec![1; 32],
            signed_pre_key: SignedPreKeyNode::new(100, vec![2; 32], vec![3; 64]),
            one_time_pre_key: Some(OneTimePreKeyNode::new(200, vec![4; 32])),
            device_identity: Some(vec![5; 128]),
        };

        let node = original.clone().into_node();
        let parsed = PreKeyBundleUserNode::try_from_node(&node).unwrap();

        assert_eq!(parsed.jid, original.jid);
        assert_eq!(parsed.registration_id, original.registration_id);
        assert_eq!(parsed.identity_key, original.identity_key);
        assert_eq!(parsed.signed_pre_key.id, original.signed_pre_key.id);
        assert_eq!(
            parsed.signed_pre_key.public_bytes,
            original.signed_pre_key.public_bytes
        );
        assert_eq!(
            parsed.signed_pre_key.signature,
            original.signed_pre_key.signature
        );
        assert!(parsed.one_time_pre_key.is_some());
        assert_eq!(
            parsed.one_time_pre_key.as_ref().unwrap().id,
            original.one_time_pre_key.as_ref().unwrap().id
        );
        assert_eq!(parsed.device_identity, original.device_identity);
    }

    #[test]
    fn test_prekey_bundle_user_node_without_optional_fields() {
        let jid: Jid = "1234567890:0@s.whatsapp.net".parse().unwrap();
        let original = PreKeyBundleUserNode {
            jid: jid.clone(),
            registration_id: 54321,
            identity_key: vec![9; 32],
            signed_pre_key: SignedPreKeyNode::new(500, vec![8; 32], vec![7; 64]),
            one_time_pre_key: None,
            device_identity: None,
        };

        let node = original.clone().into_node();

        // Verify structure
        if let Some(children) = node.children() {
            // Should have 4 children (registration, type, identity, skey) - no key, no device-identity
            assert_eq!(children.len(), 4);
            assert_eq!(children[0].tag, "registration");
            assert_eq!(children[1].tag, "type");
            assert_eq!(children[2].tag, "identity");
            assert_eq!(children[3].tag, "skey");
        } else {
            panic!("Expected user node to have children");
        }

        // Round-trip test
        let parsed = PreKeyBundleUserNode::try_from_node(&node).unwrap();
        assert_eq!(parsed.jid, original.jid);
        assert_eq!(parsed.registration_id, original.registration_id);
        assert!(parsed.one_time_pre_key.is_none());
        assert!(parsed.device_identity.is_none());
    }
}
