//! Newsletter (Channel) feature.
//!
//! Provides methods for listing, fetching, and managing newsletter channels.
//! Uses MEX (GraphQL) for metadata/management and standard IQ for message operations.
//! Newsletter messages are plaintext (no Signal E2E encryption).

use crate::client::Client;
use crate::features::mex::{MexError, MexRequest};
use prost::Message as ProtoMessage;
use serde_json::json;
use wacore::iq::newsletter::NEWSLETTER_XMLNS;
use wacore::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};
use waproto::whatsapp as wa;

// Types

/// Newsletter verification status.
#[derive(Debug, Clone)]
pub enum NewsletterVerification {
    Verified,
    Unverified,
}

/// Newsletter state.
#[derive(Debug, Clone)]
pub enum NewsletterState {
    Active,
    Suspended,
    Geosuspended,
}

/// The viewer's role in a newsletter.
#[derive(Debug, Clone)]
pub enum NewsletterRole {
    Owner,
    Admin,
    Subscriber,
    Guest,
}

/// Metadata for a newsletter (channel).
#[derive(Debug, Clone)]
pub struct NewsletterMetadata {
    pub jid: Jid,
    pub name: String,
    pub description: Option<String>,
    pub subscriber_count: u64,
    pub verification: NewsletterVerification,
    pub state: NewsletterState,
    pub picture_url: Option<String>,
    pub preview_url: Option<String>,
    pub invite_code: Option<String>,
    pub role: Option<NewsletterRole>,
    pub creation_time: Option<u64>,
}

/// A reaction count on a newsletter message.
#[derive(Debug, Clone)]
pub struct NewsletterReactionCount {
    pub code: String,
    pub count: u64,
}

/// A message from a newsletter's history.
#[derive(Debug, Clone)]
pub struct NewsletterMessage {
    /// Server-assigned message ID (monotonic, used for pagination cursors).
    pub server_id: u64,
    /// Message timestamp (Unix seconds).
    pub timestamp: u64,
    /// Message type ("text", "media", etc.).
    pub message_type: String,
    /// Whether the viewer is the sender.
    pub is_sender: bool,
    /// Decoded protobuf message (from `<plaintext>` bytes).
    pub message: Option<wa::Message>,
    /// Reaction counts on this message.
    pub reactions: Vec<NewsletterReactionCount>,
}

/// Feature handle for newsletter (channel) operations.
pub struct Newsletter<'a> {
    client: &'a Client,
}

impl<'a> Newsletter<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// List all newsletters the user is subscribed to.
    pub async fn list_subscribed(&self) -> Result<Vec<NewsletterMetadata>, MexError> {
        let response = self
            .client
            .mex()
            .query(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::LIST_SUBSCRIBED,
                variables: json!({}),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        let newsletters = data["xwa2_newsletter_subscribed"]
            .as_array()
            .ok_or_else(|| {
                MexError::PayloadParsing("missing xwa2_newsletter_subscribed array".into())
            })?;

        newsletters.iter().map(parse_newsletter_metadata).collect()
    }

    /// Fetch metadata for a newsletter by its JID.
    pub async fn get_metadata(&self, jid: &Jid) -> Result<NewsletterMetadata, MexError> {
        let response = self
            .client
            .mex()
            .query(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::FETCH_METADATA,
                variables: json!({
                    "input": {
                        "key": jid.to_string(),
                        "type": "JID",
                        "view_role": "GUEST"
                    },
                    "fetch_viewer_metadata": true,
                    "fetch_full_image": true,
                    "fetch_creation_time": true
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        let newsletter = &data["xwa2_newsletter"];
        if newsletter.is_null() {
            return Err(MexError::PayloadParsing(format!(
                "newsletter not found: {}",
                jid
            )));
        }
        parse_newsletter_metadata(newsletter)
    }

    /// Create a new newsletter.
    ///
    /// Returns the metadata of the newly created newsletter.
    pub async fn create(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<NewsletterMetadata, MexError> {
        let mut input = json!({ "name": name });
        if let Some(desc) = description {
            input["description"] = json!(desc);
        }

        let response = self
            .client
            .mex()
            .mutate(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::CREATE,
                variables: json!({ "input": input }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        let newsletter = &data["xwa2_newsletter_create"];
        if newsletter.is_null() {
            return Err(MexError::PayloadParsing(
                "newsletter creation failed".into(),
            ));
        }
        parse_newsletter_metadata(newsletter)
    }

    /// Join (subscribe to) a newsletter.
    ///
    /// Returns the newsletter metadata with the viewer's role set to `Subscriber`.
    pub async fn join(&self, jid: &Jid) -> Result<NewsletterMetadata, MexError> {
        let response = self
            .client
            .mex()
            .mutate(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::JOIN,
                variables: json!({
                    "newsletter_id": jid.to_string()
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        let newsletter = &data["xwa2_newsletter_join_v2"];
        if newsletter.is_null() {
            return Err(MexError::PayloadParsing(format!(
                "failed to join newsletter: {}",
                jid
            )));
        }
        parse_newsletter_metadata(newsletter)
    }

    /// Leave (unsubscribe from) a newsletter.
    pub async fn leave(&self, jid: &Jid) -> Result<(), MexError> {
        let response = self
            .client
            .mex()
            .mutate(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::LEAVE,
                variables: json!({
                    "newsletter_id": jid.to_string()
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        if data["xwa2_newsletter_leave_v2"].is_null() {
            return Err(MexError::PayloadParsing(format!(
                "failed to leave newsletter: {}",
                jid
            )));
        }
        Ok(())
    }

    /// Update a newsletter's name and/or description.
    pub async fn update(
        &self,
        jid: &Jid,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<NewsletterMetadata, MexError> {
        let mut updates = json!({});
        if let Some(name) = name {
            updates["name"] = json!(name);
        }
        if let Some(desc) = description {
            updates["description"] = json!(desc);
        }

        let response = self
            .client
            .mex()
            .mutate(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::UPDATE,
                variables: json!({
                    "newsletter_id": jid.to_string(),
                    "updates": updates
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        let newsletter = &data["xwa2_newsletter_update"];
        if newsletter.is_null() {
            return Err(MexError::PayloadParsing(format!(
                "failed to update newsletter: {}",
                jid
            )));
        }
        parse_newsletter_metadata(newsletter)
    }

    /// Fetch metadata for a newsletter by its invite code.
    pub async fn get_metadata_by_invite(
        &self,
        invite_code: &str,
    ) -> Result<NewsletterMetadata, MexError> {
        let response = self
            .client
            .mex()
            .query(MexRequest {
                doc_id: wacore::iq::newsletter::mex_docs::FETCH_METADATA,
                variables: json!({
                    "input": {
                        "key": invite_code,
                        "type": "INVITE",
                        "view_role": "GUEST"
                    },
                    "fetch_viewer_metadata": true,
                    "fetch_full_image": true,
                    "fetch_creation_time": true
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data".into()))?;
        let newsletter = &data["xwa2_newsletter"];
        if newsletter.is_null() {
            return Err(MexError::PayloadParsing(format!(
                "newsletter not found for invite: {}",
                invite_code
            )));
        }
        parse_newsletter_metadata(newsletter)
    }

    // ─── Live updates ───────────────────────────────────────────────────

    /// Subscribe to live updates for a newsletter (reaction counts, message changes).
    ///
    /// The server will send `<notification type="newsletter">` stanzas with
    /// `<live_updates>` children, dispatched as `Event::NewsletterLiveUpdate`.
    /// Returns the subscription duration in seconds.
    pub async fn subscribe_live_updates(&self, jid: &Jid) -> Result<u64, anyhow::Error> {
        let iq = InfoQuery::set(
            NEWSLETTER_XMLNS,
            jid.clone(),
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("live_updates").build(),
            ])),
        );

        let response = self.client.send_iq(iq).await?;
        let duration = response
            .get_optional_child("live_updates")
            .and_then(|n| n.attrs.get("duration"))
            .map(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        Ok(duration)
    }

    // ─── Message operations ────────────────────────────────────────────

    /// Send a message to a newsletter.
    ///
    /// Newsletter messages are plaintext (no Signal E2E encryption).
    /// Returns the message ID assigned by the client.
    pub async fn send_message(
        &self,
        jid: &Jid,
        message: &wa::Message,
    ) -> Result<String, anyhow::Error> {
        let request_id = self.client.generate_message_id().await;
        let encoded = message.encode_to_vec();

        let stanza = NodeBuilder::new("message")
            .attr("to", jid.clone())
            .attr("type", "text")
            .attr("id", &request_id)
            .children([NodeBuilder::new("plaintext").bytes(encoded).build()])
            .build();

        self.client.send_node(stanza).await?;
        Ok(request_id)
    }

    /// Send a reaction to a newsletter message.
    ///
    /// `server_id` is the server-assigned ID of the message to react to.
    /// `reaction` is the emoji code (e.g., "👍", "❤️"), or empty to remove.
    pub async fn send_reaction(
        &self,
        jid: &Jid,
        server_id: u64,
        reaction: &str,
    ) -> Result<(), anyhow::Error> {
        let request_id = self.client.generate_message_id().await;

        let stanza = NodeBuilder::new("message")
            .attr("to", jid.clone())
            .attr("type", "reaction")
            .attr("id", &request_id)
            .attr("server_id", server_id.to_string())
            .children([NodeBuilder::new("reaction").attr("code", reaction).build()])
            .build();

        self.client.send_node(stanza).await?;
        Ok(())
    }

    /// Fetch message history from a newsletter.
    ///
    /// Returns up to `count` messages. Use `before` with a `server_id` from a previous
    /// response to paginate backwards through history.
    pub async fn get_messages(
        &self,
        jid: &Jid,
        count: u32,
        before: Option<u64>,
    ) -> Result<Vec<NewsletterMessage>, anyhow::Error> {
        let mut messages_node = NodeBuilder::new("messages").attr("count", count.to_string());
        if let Some(before_id) = before {
            messages_node = messages_node.attr("before", before_id.to_string());
        }

        let iq = InfoQuery::get(
            NEWSLETTER_XMLNS,
            jid.clone(),
            Some(NodeContent::Nodes(vec![messages_node.build()])),
        );

        let response = self.client.send_iq(iq).await?;
        parse_newsletter_messages_response(&response)
    }
}

impl Client {
    /// Access newsletter (channel) operations.
    #[inline]
    pub fn newsletter(&self) -> Newsletter<'_> {
        Newsletter::new(self)
    }
}

// JSON parsing helper

fn parse_newsletter_metadata(value: &serde_json::Value) -> Result<NewsletterMetadata, MexError> {
    let jid_str = value["id"]
        .as_str()
        .ok_or_else(|| MexError::PayloadParsing("missing newsletter id".into()))?;
    let jid: Jid = jid_str
        .parse()
        .map_err(|e| MexError::PayloadParsing(format!("invalid newsletter JID: {e}")))?;

    let thread = &value["thread_metadata"];

    let name = thread["name"]["text"].as_str().unwrap_or("").to_string();
    let description = thread["description"]["text"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let subscriber_count = thread["subscribers_count"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let verification = match thread["verification"].as_str() {
        Some("VERIFIED") => NewsletterVerification::Verified,
        _ => NewsletterVerification::Unverified,
    };

    let state = match value["state"]["type"].as_str() {
        Some("suspended") => NewsletterState::Suspended,
        Some("geosuspended") => NewsletterState::Geosuspended,
        _ => NewsletterState::Active,
    };

    let picture_url = thread["picture"]["direct_path"]
        .as_str()
        .map(|s| s.to_string());
    let preview_url = thread["preview"]["direct_path"]
        .as_str()
        .map(|s| s.to_string());
    let invite_code = thread["invite"].as_str().map(|s| s.to_string());

    let creation_time = thread["creation_time"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok());

    let role = value["viewer_metadata"]["role"]
        .as_str()
        .and_then(|r| match r {
            "owner" => Some(NewsletterRole::Owner),
            "admin" => Some(NewsletterRole::Admin),
            "subscriber" => Some(NewsletterRole::Subscriber),
            "guest" => Some(NewsletterRole::Guest),
            _ => None,
        });

    Ok(NewsletterMetadata {
        jid,
        name,
        description,
        subscriber_count,
        verification,
        state,
        picture_url,
        preview_url,
        invite_code,
        role,
        creation_time,
    })
}

// Node response parsing helpers

/// Parse the IQ response for newsletter message history.
///
/// Response format:
/// ```xml
/// <messages jid="NL_JID" t="TS">
///   <message id="..." server_id="123" t="TS" type="text" [is_sender="true"]>
///     <plaintext>...</plaintext>
///     <reactions><reaction code="👍" count="3"/></reactions>
///   </message>
/// </messages>
/// ```
fn parse_newsletter_messages_response(
    response: &Node,
) -> Result<Vec<NewsletterMessage>, anyhow::Error> {
    // Response is the IQ result node; find <messages> child
    let messages_node = response
        .get_optional_child("messages")
        .ok_or_else(|| anyhow::anyhow!("missing <messages> in newsletter response"))?;

    let children = match messages_node.children() {
        Some(c) => c,
        None => return Ok(vec![]),
    };

    let mut result = Vec::with_capacity(children.len());
    for msg_node in children.iter().filter(|n| n.tag.as_ref() == "message") {
        let server_id = msg_node
            .attrs
            .get("server_id")
            .map(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let timestamp = msg_node
            .attrs
            .get("t")
            .map(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        let message_type = msg_node
            .attrs
            .get("type")
            .map(|v| v.as_str().into_owned())
            .unwrap_or_default();

        let is_sender = msg_node.attrs.get("is_sender").is_some_and(|v| v == "true");

        // Decode <plaintext> protobuf bytes
        let message = msg_node
            .get_optional_child("plaintext")
            .and_then(|pt| match &pt.content {
                Some(NodeContent::Bytes(bytes)) => wa::Message::decode(bytes.as_slice()).ok(),
                _ => None,
            });

        // Parse <reactions> counts
        let mut reactions = Vec::new();
        if let Some(reactions_node) = msg_node.get_optional_child("reactions")
            && let Some(reaction_children) = reactions_node.children()
        {
            for r in reaction_children
                .iter()
                .filter(|n| n.tag.as_ref() == "reaction")
            {
                let code = r
                    .attrs
                    .get("code")
                    .map(|v| v.as_str().into_owned())
                    .unwrap_or_default();
                let count = r
                    .attrs
                    .get("count")
                    .map(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                reactions.push(NewsletterReactionCount { code, count });
            }
        }

        result.push(NewsletterMessage {
            server_id,
            timestamp,
            message_type,
            is_sender,
            message,
            reactions,
        });
    }

    Ok(result)
}
