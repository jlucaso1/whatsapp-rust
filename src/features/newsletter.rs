//! Newsletter (Channel) feature.
//!
//! Provides methods for listing, fetching, and managing newsletter channels
//! via the MEX (GraphQL) protocol layer.

use crate::client::Client;
use crate::features::mex::{MexError, MexRequest};
use serde_json::json;
use wacore_binary::jid::Jid;

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
