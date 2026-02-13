//! Trusted Contact (tcToken) privacy token lifecycle.
//!
//! Implements the complete tcToken lifecycle matching WhatsApp Web behavior
//! (WAWebTrustedContactsUtils / WAWebPrivacyTokenJob).
//!
//! ## Wire Formats
//!
//! ### Issue Privacy Tokens (IQ set)
//! ```xml
//! <!-- Request -->
//! <iq xmlns="privacy" type="set" to="s.whatsapp.net" id="...">
//!   <tokens>
//!     <token jid="user@lid" t="1707000000" type="trusted_contact"/>
//!   </tokens>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <tokens>
//!     <token jid="user@lid" t="1707000000" type="trusted_contact">
//!       <!-- token bytes -->
//!     </token>
//!   </tokens>
//! </iq>
//! ```
//!
//! ### Incoming Token Notification
//! ```xml
//! <notification type="privacy_token" from="user@s.whatsapp.net">
//!   <tokens>
//!     <token type="trusted_contact" t="1707000000"><!-- bytes --></token>
//!   </tokens>
//! </notification>
//! ```
//!
//! ### Message Stanza
//! ```xml
//! <tctoken><!-- raw token bytes --></tctoken>
//! ```

use crate::iq::node::{optional_attr, required_attr, required_child};
use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for privacy tokens (shared with privacy settings).
pub const PRIVACY_NAMESPACE: &str = "privacy";

/// 7 days in seconds — matches WA Web AB prop `tctoken_duration`.
pub const TC_TOKEN_BUCKET_DURATION: i64 = 604_800;

/// Number of buckets in the rolling window — matches WA Web `tctoken_num_buckets`.
pub const TC_TOKEN_NUM_BUCKETS: i64 = 4;

/// Total rolling window duration in seconds (bucket_duration * num_buckets).
pub const TC_TOKEN_TOTAL_DURATION: i64 = TC_TOKEN_BUCKET_DURATION * TC_TOKEN_NUM_BUCKETS;

/// Get the current unix timestamp in seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Check if a tcToken has expired (older than the rolling window).
pub fn is_tc_token_expired(token_timestamp: i64) -> bool {
    is_tc_token_expired_at(token_timestamp, unix_now())
}

fn is_tc_token_expired_at(token_timestamp: i64, now: i64) -> bool {
    now - token_timestamp >= TC_TOKEN_TOTAL_DURATION
}

/// Compute the bucket index for a given timestamp.
fn bucket_index(timestamp: i64) -> i64 {
    timestamp / TC_TOKEN_BUCKET_DURATION
}

/// Check if we should issue a new tcToken to a contact.
///
/// Returns true if:
/// - We have never issued a token (`sender_timestamp` is None)
/// - The current bucket is ahead of the sender_timestamp bucket
///   (meaning a bucket boundary has been crossed)
pub fn should_send_new_tc_token(sender_timestamp: Option<i64>) -> bool {
    should_send_new_tc_token_at(sender_timestamp, unix_now())
}

fn should_send_new_tc_token_at(sender_timestamp: Option<i64>, now: i64) -> bool {
    match sender_timestamp {
        None => true,
        Some(ts) => bucket_index(now) > bucket_index(ts),
    }
}

/// Compute the expiration cutoff timestamp for pruning.
/// Tokens with `token_timestamp < cutoff` should be deleted.
pub fn tc_token_expiration_cutoff() -> i64 {
    unix_now() - TC_TOKEN_TOTAL_DURATION
}

/// A token received from the server in an IQ response or notification.
#[derive(Debug, Clone)]
pub struct ReceivedTcToken {
    /// The JID this token belongs to.
    pub jid: Jid,
    /// Raw token bytes.
    pub token: Vec<u8>,
    /// Timestamp from the `t` attribute.
    pub timestamp: i64,
}

/// Token data parsed from a notification (JID resolved by caller).
#[derive(Debug, Clone)]
pub struct ParsedTokenData {
    /// Raw token bytes.
    pub token: Vec<u8>,
    /// Timestamp from the `t` attribute.
    pub timestamp: i64,
}

/// Issues privacy tokens to one or more contacts.
///
/// Sends our token to the specified JIDs and receives their tokens back.
pub struct IssuePrivacyTokensSpec {
    /// JIDs to issue tokens for (should be LID JIDs).
    pub jids: Vec<Jid>,
    /// Current timestamp to use for the token issuance.
    pub timestamp: i64,
}

impl IssuePrivacyTokensSpec {
    pub fn new(jids: &[Jid]) -> Self {
        Self {
            jids: jids.to_vec(),
            timestamp: unix_now(),
        }
    }
}

/// Response from issuing privacy tokens.
#[derive(Debug, Clone, Default)]
pub struct IssuePrivacyTokensResponse {
    /// Tokens received back from the server.
    pub tokens: Vec<ReceivedTcToken>,
}

impl IqSpec for IssuePrivacyTokensSpec {
    type Response = IssuePrivacyTokensResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let token_nodes: Vec<Node> = self
            .jids
            .iter()
            .map(|jid| {
                NodeBuilder::new("token")
                    .attr("jid", jid.to_string())
                    .attr("t", self.timestamp.to_string())
                    .attr("type", "trusted_contact")
                    .build()
            })
            .collect();

        InfoQuery::set(
            PRIVACY_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("tokens").children(token_nodes).build(),
            ])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let tokens_node = match response.get_optional_child("tokens") {
            Some(n) => n,
            None => return Ok(IssuePrivacyTokensResponse::default()),
        };

        let mut tokens = Vec::new();
        for token_node in tokens_node.get_children_by_tag("token") {
            let jid_str = required_attr(token_node, "jid")?;
            let jid: Jid = jid_str
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid jid '{}': {}", jid_str, e))?;
            let t_str = required_attr(token_node, "t")?;
            let timestamp: i64 = t_str
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid timestamp '{}': {}", t_str, e))?;

            let token_bytes = match &token_node.content {
                Some(NodeContent::Bytes(data)) => data.clone(),
                _ => {
                    log::warn!(target: "TcToken", "Token node for {} has no binary content, skipping", jid);
                    continue;
                }
            };

            tokens.push(ReceivedTcToken {
                jid,
                token: token_bytes,
                timestamp,
            });
        }

        Ok(IssuePrivacyTokensResponse { tokens })
    }
}

/// Parse incoming privacy_token notification.
///
/// Extracts token data from a `<notification type="privacy_token">` stanza.
/// Returns `ParsedTokenData` items without JID — the caller is responsible for
/// resolving the sender JID from the notification's `sender_lid` / `from` attributes.
pub fn parse_privacy_token_notification(
    notification: &Node,
) -> Result<Vec<ParsedTokenData>, anyhow::Error> {
    let tokens_node = required_child(notification, "tokens")?;

    let mut tokens = Vec::new();
    for token_node in tokens_node.get_children_by_tag("token") {
        let token_type = optional_attr(token_node, "type").unwrap_or("");
        if token_type != "trusted_contact" {
            continue;
        }

        let t_str = required_attr(token_node, "t")?;
        let timestamp: i64 = t_str.parse().map_err(|e| {
            anyhow::anyhow!(
                "invalid timestamp '{}' in privacy_token notification: {}",
                t_str,
                e
            )
        })?;

        let token_bytes = match &token_node.content {
            Some(NodeContent::Bytes(data)) => data.clone(),
            _ => {
                log::warn!(target: "TcToken", "Notification token node has no binary content, skipping");
                continue;
            }
        };

        tokens.push(ParsedTokenData {
            token: token_bytes,
            timestamp,
        });
    }

    Ok(tokens)
}

/// Build a `<tctoken>` stanza child for including in outgoing messages.
pub fn build_tc_token_node(token: &[u8]) -> Node {
    NodeBuilder::new("tctoken").bytes(token.to_vec()).build()
}

/// Build a `<tctoken>` stanza child with timestamp attribute.
pub fn build_tc_token_node_with_timestamp(token: &[u8], timestamp: i64) -> Node {
    NodeBuilder::new("tctoken")
        .attr("t", timestamp.to_string())
        .bytes(token.to_vec())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_index() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(604799), 0);
        assert_eq!(bucket_index(604800), 1);
        assert_eq!(bucket_index(1209599), 1);
        assert_eq!(bucket_index(1209600), 2);
    }

    #[test]
    fn test_should_send_new_tc_token_none() {
        assert!(should_send_new_tc_token_at(None, 1_000_000));
    }

    #[test]
    fn test_should_send_new_tc_token_same_bucket() {
        let now = 2 * TC_TOKEN_BUCKET_DURATION + 100;
        let same_bucket_ts = 2 * TC_TOKEN_BUCKET_DURATION;
        assert!(!should_send_new_tc_token_at(Some(same_bucket_ts), now));
    }

    #[test]
    fn test_should_send_new_tc_token_different_bucket() {
        let now = 3 * TC_TOKEN_BUCKET_DURATION + 100;
        let old_ts = 1 * TC_TOKEN_BUCKET_DURATION + 50;
        assert!(should_send_new_tc_token_at(Some(old_ts), now));
    }

    #[test]
    fn test_should_send_new_tc_token_clock_backward_no_reissue() {
        // If clock goes backwards, should NOT trigger re-issuance (> not !=)
        let future_ts = 5 * TC_TOKEN_BUCKET_DURATION + 100;
        let now = 3 * TC_TOKEN_BUCKET_DURATION + 100;
        assert!(!should_send_new_tc_token_at(Some(future_ts), now));
    }

    #[test]
    fn test_is_tc_token_expired() {
        let now = 10 * TC_TOKEN_BUCKET_DURATION;

        // Recent token should not be expired
        assert!(!is_tc_token_expired_at(now - 100, now));

        // Token older than total window should be expired
        assert!(is_tc_token_expired_at(
            now - TC_TOKEN_TOTAL_DURATION - 1,
            now
        ));

        // Token at exact boundary
        assert!(is_tc_token_expired_at(now - TC_TOKEN_TOTAL_DURATION, now));
    }

    #[test]
    fn test_tc_token_expiration_cutoff() {
        let now = unix_now();
        let cutoff = tc_token_expiration_cutoff();
        let expected = now - TC_TOKEN_TOTAL_DURATION;
        assert!((cutoff - expected).abs() <= 1);
    }

    #[test]
    fn test_issue_privacy_tokens_spec_build_iq() {
        let jid1: Jid = "100000000000001@lid".parse().unwrap();
        let jid2: Jid = "100000000000002@lid".parse().unwrap();
        let spec = IssuePrivacyTokensSpec {
            jids: vec![jid1, jid2],
            timestamp: 1707000000,
        };
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, PRIVACY_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "tokens");
            let token_children: Vec<_> = nodes[0].get_children_by_tag("token").collect();
            assert_eq!(token_children.len(), 2);
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_issue_privacy_tokens_spec_parse_response() {
        let spec = IssuePrivacyTokensSpec {
            jids: vec!["100000000000001@lid".parse().unwrap()],
            timestamp: 1707000000,
        };

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("tokens")
                .children([NodeBuilder::new("token")
                    .attr("jid", "100000000000001@lid")
                    .attr("t", "1707000000")
                    .attr("type", "trusted_contact")
                    .bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.tokens.len(), 1);
        assert_eq!(result.tokens[0].jid.to_string(), "100000000000001@lid");
        assert_eq!(result.tokens[0].token, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(result.tokens[0].timestamp, 1707000000);
    }

    #[test]
    fn test_issue_privacy_tokens_spec_parse_skips_empty_token() {
        let spec = IssuePrivacyTokensSpec {
            jids: vec!["100000000000001@lid".parse().unwrap()],
            timestamp: 1707000000,
        };

        // Token node without binary content should be skipped
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("tokens")
                .children([NodeBuilder::new("token")
                    .attr("jid", "100000000000001@lid")
                    .attr("t", "1707000000")
                    .attr("type", "trusted_contact")
                    .build()])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert!(result.tokens.is_empty());
    }

    #[test]
    fn test_parse_privacy_token_notification() {
        let notification = NodeBuilder::new("notification")
            .attr("type", "privacy_token")
            .children([NodeBuilder::new("tokens")
                .children([NodeBuilder::new("token")
                    .attr("type", "trusted_contact")
                    .attr("t", "1707000000")
                    .bytes(vec![0xCA, 0xFE])
                    .build()])
                .build()])
            .build();

        let tokens = parse_privacy_token_notification(&notification).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, vec![0xCA, 0xFE]);
        assert_eq!(tokens[0].timestamp, 1707000000);
    }

    #[test]
    fn test_parse_privacy_token_notification_skips_non_trusted_contact() {
        let notification = NodeBuilder::new("notification")
            .children([NodeBuilder::new("tokens")
                .children([
                    NodeBuilder::new("token")
                        .attr("type", "other_type")
                        .attr("t", "1000")
                        .build(),
                    NodeBuilder::new("token")
                        .attr("type", "trusted_contact")
                        .attr("t", "2000")
                        .bytes(vec![0x01])
                        .build(),
                ])
                .build()])
            .build();

        let tokens = parse_privacy_token_notification(&notification).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].timestamp, 2000);
    }

    #[test]
    fn test_parse_privacy_token_notification_skips_empty_content() {
        let notification = NodeBuilder::new("notification")
            .children([NodeBuilder::new("tokens")
                .children([NodeBuilder::new("token")
                    .attr("type", "trusted_contact")
                    .attr("t", "1707000000")
                    .build()])
                .build()])
            .build();

        let tokens = parse_privacy_token_notification(&notification).unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_build_tc_token_node() {
        let node = build_tc_token_node(&[0x01, 0x02, 0x03]);
        assert_eq!(node.tag, "tctoken");
        match &node.content {
            Some(NodeContent::Bytes(data)) => assert_eq!(data, &[0x01, 0x02, 0x03]),
            _ => panic!("Expected binary content"),
        }
    }

    #[test]
    fn test_build_tc_token_node_with_timestamp() {
        let node = build_tc_token_node_with_timestamp(&[0x01], 1707000000);
        assert_eq!(node.tag, "tctoken");
        assert_eq!(node.attrs().optional_string("t"), Some("1707000000"));
    }

    #[test]
    fn test_issue_privacy_tokens_spec_empty_response() {
        let spec = IssuePrivacyTokensSpec {
            jids: vec![],
            timestamp: 1707000000,
        };

        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response).unwrap();
        assert!(result.tokens.is_empty());
    }

    #[test]
    fn test_issue_privacy_tokens_spec_new_from_slice() {
        let jid1: Jid = "100000000000001@lid".parse().unwrap();
        let jid2: Jid = "100000000000002@lid".parse().unwrap();
        let jids = [jid1.clone(), jid2.clone()];
        let spec = IssuePrivacyTokensSpec::new(&jids);
        assert_eq!(spec.jids.len(), 2);
        assert_eq!(spec.jids[0], jid1);
        assert_eq!(spec.jids[1], jid2);
    }
}
