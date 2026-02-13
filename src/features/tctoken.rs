//! Trusted contact privacy token feature.
//!
//! Provides high-level APIs for managing tcTokens, matching WhatsApp Web's
//! `WAWebTrustedContactsUtils` and `WAWebPrivacyTokenJob`.
//!
//! ## Usage
//! ```ignore
//! // Issue tokens to contacts
//! let tokens = client.tc_token().issue_tokens(&[jid]).await?;
//!
//! // Prune expired tokens
//! let count = client.tc_token().prune_expired().await?;
//! ```

use crate::client::Client;
use crate::request::IqError;
use wacore::iq::tctoken::{IssuePrivacyTokensSpec, ReceivedTcToken, tc_token_expiration_cutoff};
use wacore::store::traits::TcTokenEntry;
use wacore_binary::jid::Jid;

/// Feature handle for trusted contact token operations.
pub struct TcToken<'a> {
    client: &'a Client,
}

impl<'a> TcToken<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Issue privacy tokens for the given contacts.
    ///
    /// Sends an IQ to the server requesting tokens for the specified JIDs (should be LID JIDs).
    /// Stores the received tokens and returns them.
    pub async fn issue_tokens(&self, jids: &[Jid]) -> Result<Vec<ReceivedTcToken>, IqError> {
        if jids.is_empty() {
            return Ok(Vec::new());
        }

        let spec = IssuePrivacyTokensSpec::new(jids);
        let response = self.client.execute(spec).await?;
        let backend = self.client.persistence_manager.backend();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        for received in &response.tokens {
            let entry = TcTokenEntry {
                token: received.token.clone(),
                token_timestamp: received.timestamp,
                sender_timestamp: Some(now),
            };

            if let Err(e) = backend.put_tc_token(&received.jid.user, &entry).await {
                log::warn!(target: "Client/TcToken", "Failed to store issued tc_token for {}: {e}", received.jid);
            }
        }

        Ok(response.tokens)
    }

    /// Prune expired tc tokens from the store.
    ///
    /// Deletes all tokens older than the rolling window (28 days by default).
    /// Returns the number of tokens deleted.
    pub async fn prune_expired(&self) -> Result<u32, anyhow::Error> {
        let backend = self.client.persistence_manager.backend();
        let cutoff = tc_token_expiration_cutoff();
        let deleted = backend.delete_expired_tc_tokens(cutoff).await?;

        if deleted > 0 {
            log::info!(target: "Client/TcToken", "Pruned {} expired tc_tokens", deleted);
        }

        Ok(deleted)
    }

    /// Get a stored tc token for a JID.
    pub async fn get(&self, jid: &str) -> Result<Option<TcTokenEntry>, anyhow::Error> {
        let backend = self.client.persistence_manager.backend();
        Ok(backend.get_tc_token(jid).await?)
    }

    /// Get all JIDs that have stored tc tokens.
    pub async fn get_all_jids(&self) -> Result<Vec<String>, anyhow::Error> {
        let backend = self.client.persistence_manager.backend();
        Ok(backend.get_all_tc_token_jids().await?)
    }
}

impl Client {
    /// Access trusted contact token operations.
    pub fn tc_token(&self) -> TcToken<'_> {
        TcToken::new(self)
    }
}
