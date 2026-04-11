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
use wacore_binary::jid::{Jid, Server};
use wacore_binary::node::{Node, NodeContent};

use super::privacy::PRIVACY_NAMESPACE;

/// Default bucket duration in seconds — WA Web AB prop `tctoken_duration` (default 604800 = 7 days).
pub const TC_TOKEN_BUCKET_DURATION: i64 = 604_800;

/// Default number of buckets — WA Web AB prop `tctoken_num_buckets` (default 4).
pub const TC_TOKEN_NUM_BUCKETS: i64 = 4;

/// Maximum allowed bucket duration (180 days) — matches WA Web's cap.
pub const TC_TOKEN_MAX_DURATION: i64 = 15_552_000;

/// Runtime-configurable tctoken timing from AB props.
/// All fields must be >= 1 (division-by-zero guard in bucket math).
#[derive(Debug, Clone, Copy)]
pub struct TcTokenConfig {
    pub bucket_duration: i64,
    pub num_buckets: i64,
    pub sender_bucket_duration: i64,
    pub sender_num_buckets: i64,
}

impl TcTokenConfig {
    /// Clamp fields to safe ranges: durations to [1, MAX], counts to >= 1.
    pub fn clamped(self) -> Self {
        Self {
            bucket_duration: self.bucket_duration.clamp(1, TC_TOKEN_MAX_DURATION),
            num_buckets: self.num_buckets.max(1),
            sender_bucket_duration: self.sender_bucket_duration.clamp(1, TC_TOKEN_MAX_DURATION),
            sender_num_buckets: self.sender_num_buckets.max(1),
        }
    }
}

impl Default for TcTokenConfig {
    fn default() -> Self {
        Self {
            bucket_duration: TC_TOKEN_BUCKET_DURATION,
            num_buckets: TC_TOKEN_NUM_BUCKETS,
            sender_bucket_duration: TC_TOKEN_BUCKET_DURATION,
            sender_num_buckets: TC_TOKEN_NUM_BUCKETS,
        }
    }
}

/// Get the current unix timestamp in seconds.
fn unix_now() -> i64 {
    crate::time::now_secs()
}

/// Check if a tcToken has expired using default constants.
///
/// For AB-prop-aware expiration, use [`is_tc_token_expired_with`].
pub fn is_tc_token_expired(token_timestamp: i64) -> bool {
    is_tc_token_expired_at(
        token_timestamp,
        unix_now(),
        TC_TOKEN_BUCKET_DURATION,
        TC_TOKEN_NUM_BUCKETS,
    )
}

/// Check if a tcToken has expired using configurable receiver-side timing.
pub fn is_tc_token_expired_with(token_timestamp: i64, config: &TcTokenConfig) -> bool {
    let cfg = config.clamped();
    is_tc_token_expired_at(
        token_timestamp,
        unix_now(),
        cfg.bucket_duration,
        cfg.num_buckets,
    )
}

/// Check if a sender-side timestamp has expired using sender-specific timing.
pub fn is_sender_tc_token_expired(sender_timestamp: i64, config: &TcTokenConfig) -> bool {
    let cfg = config.clamped();
    is_tc_token_expired_at(
        sender_timestamp,
        unix_now(),
        cfg.sender_bucket_duration,
        cfg.sender_num_buckets,
    )
}

fn is_tc_token_expired_at(
    token_timestamp: i64,
    now: i64,
    bucket_duration: i64,
    num_buckets: i64,
) -> bool {
    token_timestamp < expiration_cutoff_at(now, bucket_duration, num_buckets)
}

/// Compute the bucket index for a given timestamp.
fn bucket_index(timestamp: i64, bucket_duration: i64) -> i64 {
    timestamp / bucket_duration
}

/// Bucket-aligned expiration cutoff matching WA Web's `tokenExpirationCutoff`.
fn expiration_cutoff_at(now: i64, bucket_duration: i64, num_buckets: i64) -> i64 {
    let current_bucket = bucket_index(now, bucket_duration);
    let expired_bucket = current_bucket - (num_buckets - 1);
    expired_bucket * bucket_duration
}

/// Check if we should issue a new tcToken to a contact (default constants).
///
/// For AB-prop-aware check, use [`should_send_new_tc_token_with`].
pub fn should_send_new_tc_token(sender_timestamp: Option<i64>) -> bool {
    should_send_new_tc_token_at(sender_timestamp, unix_now(), TC_TOKEN_BUCKET_DURATION)
}

/// Check if we should issue a new tcToken using configurable sender bucket duration.
pub fn should_send_new_tc_token_with(
    sender_timestamp: Option<i64>,
    config: &TcTokenConfig,
) -> bool {
    let cfg = config.clamped();
    should_send_new_tc_token_at(sender_timestamp, unix_now(), cfg.sender_bucket_duration)
}

fn should_send_new_tc_token_at(
    sender_timestamp: Option<i64>,
    now: i64,
    bucket_duration: i64,
) -> bool {
    match sender_timestamp {
        None => true,
        Some(ts) => bucket_index(now, bucket_duration) > bucket_index(ts, bucket_duration),
    }
}

/// Compute the expiration cutoff timestamp for pruning (default constants).
///
/// For AB-prop-aware cutoff, use [`tc_token_expiration_cutoff_with`].
pub fn tc_token_expiration_cutoff() -> i64 {
    expiration_cutoff_at(unix_now(), TC_TOKEN_BUCKET_DURATION, TC_TOKEN_NUM_BUCKETS)
}

/// Compute the expiration cutoff using configurable timing.
pub fn tc_token_expiration_cutoff_with(config: &TcTokenConfig) -> i64 {
    let cfg = config.clamped();
    expiration_cutoff_at(unix_now(), cfg.bucket_duration, cfg.num_buckets)
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

    /// Create a spec with a specific timestamp (for identity change re-issuance).
    ///
    /// WA Web passes the stored senderTimestamp when re-issuing after identity change
    /// (`sendTcTokenWhenDeviceIdentityChange`), preserving the original issuance epoch.
    pub fn with_timestamp(jids: &[Jid], timestamp: i64) -> Self {
        Self {
            jids: jids.to_vec(),
            timestamp,
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
                    .attr("jid", jid)
                    .attr("t", self.timestamp.to_string())
                    .attr("type", "trusted_contact")
                    .build()
            })
            .collect();

        InfoQuery::set(
            PRIVACY_NAMESPACE,
            Jid::new("", Server::Pn),
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
        let token_type = optional_attr(token_node, "type");
        let token_type = token_type.as_deref().unwrap_or("");
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

/// Compute a cstoken (client-side token / NCT) for a recipient.
///
/// This is the fallback token used when no tctoken exists for the recipient.
/// Matches WA Web: `genCsTokenBody` in `MsgCreateFanoutStanza.js`.
///
/// `salt` — NCT salt from app state sync (raw bytes, not base64).
/// `recipient_lid` — The recipient's bare account LID string (e.g. `"12345@lid"`).
pub fn compute_cs_token(salt: &[u8], recipient_lid: &str) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC-SHA256 accepts any key length");
    mac.update(recipient_lid.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Build a `<cstoken>` stanza child for including in outgoing messages.
pub fn build_cs_token_node(token: &[u8]) -> Node {
    NodeBuilder::new("cstoken").bytes(token.to_vec()).build()
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

    const DUR: i64 = TC_TOKEN_BUCKET_DURATION;
    const BUCKETS: i64 = TC_TOKEN_NUM_BUCKETS;

    #[test]
    fn test_bucket_index() {
        assert_eq!(bucket_index(0, DUR), 0);
        assert_eq!(bucket_index(604799, DUR), 0);
        assert_eq!(bucket_index(604800, DUR), 1);
        assert_eq!(bucket_index(1209599, DUR), 1);
        assert_eq!(bucket_index(1209600, DUR), 2);
    }

    #[test]
    fn test_should_send_new_tc_token_none() {
        assert!(should_send_new_tc_token_at(None, 1_000_000, DUR));
    }

    #[test]
    fn test_should_send_new_tc_token_same_bucket() {
        let now = 2 * DUR + 100;
        let same_bucket_ts = 2 * DUR;
        assert!(!should_send_new_tc_token_at(Some(same_bucket_ts), now, DUR));
    }

    #[test]
    fn test_should_send_new_tc_token_different_bucket() {
        let now = 3 * DUR + 100;
        let old_ts = DUR + 50;
        assert!(should_send_new_tc_token_at(Some(old_ts), now, DUR));
    }

    #[test]
    fn test_should_send_new_tc_token_clock_backward_no_reissue() {
        let future_ts = 5 * DUR + 100;
        let now = 3 * DUR + 100;
        assert!(!should_send_new_tc_token_at(Some(future_ts), now, DUR));
    }

    #[test]
    fn test_is_tc_token_expired() {
        let now = 10 * DUR;
        // cutoff = (10 - 3) * dur = 7 * dur — buckets 7..=10 are valid

        assert!(!is_tc_token_expired_at(now - 100, now, DUR, BUCKETS));
        assert!(!is_tc_token_expired_at(7 * DUR, now, DUR, BUCKETS));
        assert!(is_tc_token_expired_at(7 * DUR - 1, now, DUR, BUCKETS));
        assert!(is_tc_token_expired_at(6 * DUR, now, DUR, BUCKETS));
    }

    #[test]
    fn test_is_tc_token_expired_mid_bucket() {
        let now = 10 * DUR + DUR / 2;
        // cutoff = (10 - 3) * dur = 7 * dur (bucket-aligned, doesn't change mid-bucket)

        assert!(!is_tc_token_expired_at(7 * DUR, now, DUR, BUCKETS));
        assert!(is_tc_token_expired_at(7 * DUR - 1, now, DUR, BUCKETS));
    }

    #[test]
    fn test_expiration_cutoff_is_bucket_aligned() {
        let now = 10 * DUR + 12345;
        let cutoff = expiration_cutoff_at(now, DUR, BUCKETS);
        assert_eq!(cutoff % DUR, 0);
        assert_eq!(cutoff, 7 * DUR);
    }

    #[test]
    fn test_tc_token_expiration_cutoff() {
        let now = unix_now();
        let cutoff = tc_token_expiration_cutoff();
        let expected = expiration_cutoff_at(now, DUR, BUCKETS);
        assert!((cutoff - expected).abs() <= 1);
    }

    #[test]
    fn test_custom_config_shorter_duration() {
        let config = TcTokenConfig {
            bucket_duration: 3600, // 1 hour
            num_buckets: 3,
            sender_bucket_duration: 3600,
            sender_num_buckets: 3,
        };
        let now = 10 * 3600;
        // cutoff = (10 - 2) * 3600 = 8 * 3600
        assert!(!is_tc_token_expired_at(
            8 * 3600,
            now,
            config.bucket_duration,
            config.num_buckets
        ));
        assert!(is_tc_token_expired_at(
            8 * 3600 - 1,
            now,
            config.bucket_duration,
            config.num_buckets
        ));
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
        assert_eq!(
            node.attrs().optional_string("t").as_deref(),
            Some("1707000000")
        );
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
        let jid1: Jid = "alice@lid".parse().unwrap();
        let jid2: Jid = "bob@lid".parse().unwrap();
        let jids = [jid1.clone(), jid2.clone()];
        let spec = IssuePrivacyTokensSpec::new(&jids);
        assert_eq!(spec.jids.len(), 2);
        assert_eq!(spec.jids[0], jid1);
        assert_eq!(spec.jids[1], jid2);
    }

    #[test]
    fn test_compute_cs_token_deterministic() {
        let salt = b"test_salt_bytes_16";
        let lid = "alice@lid";
        let token1 = compute_cs_token(salt, lid);
        let token2 = compute_cs_token(salt, lid);
        assert_eq!(token1, token2);
        assert_eq!(token1.len(), 32); // HMAC-SHA256 output is 32 bytes
    }

    #[test]
    fn test_compute_cs_token_different_lids() {
        let salt = b"test_salt_bytes_16";
        let token1 = compute_cs_token(salt, "alice@lid");
        let token2 = compute_cs_token(salt, "bob@lid");
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_compute_cs_token_different_salts() {
        let lid = "alice@lid";
        let token1 = compute_cs_token(b"salt_a", lid);
        let token2 = compute_cs_token(b"salt_b", lid);
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_compute_cs_token_known_answer() {
        // Pre-computed HMAC-SHA256 to catch accidental algorithm changes
        // (e.g., if someone swaps key/data arguments).
        let salt = b"whatsapp_nct_salt_example";
        let lid = "alice@lid";
        let expected: [u8; 32] = [
            0x7c, 0x6a, 0xfc, 0x32, 0x57, 0x85, 0xac, 0x3c, 0x4f, 0x57, 0x1e, 0x64, 0x8a, 0x3b,
            0xb8, 0x22, 0xf0, 0xe2, 0xe4, 0x94, 0x34, 0x81, 0x2e, 0xd2, 0x80, 0x9a, 0xea, 0x2e,
            0x70, 0x43, 0xb5, 0x76,
        ];
        assert_eq!(compute_cs_token(salt, lid), expected);
    }

    #[test]
    fn test_build_cs_token_node() {
        let node = build_cs_token_node(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(node.tag, "cstoken");
        match &node.content {
            Some(NodeContent::Bytes(data)) => assert_eq!(data, &[0xAA, 0xBB, 0xCC]),
            _ => panic!("Expected binary content"),
        }
    }
}
