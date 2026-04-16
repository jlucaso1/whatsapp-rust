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
//!
//! ## TODO: VoIP call integration
//! WA Web calls `sendTcToken` for each participant when initiating calls
//! (WAWeb/Voip/StartCall.js). When a calls/VoIP module is added, it should
//! call `issue_tc_token_after_send` (or equivalent) for every call participant
//! — both 1:1 and group calls. This prevents 463 nacks on call offers.

use crate::client::Client;
use crate::request::IqError;
use wacore::iq::tctoken::{IssuePrivacyTokensSpec, ReceivedTcToken};
use wacore::store::traits::TcTokenEntry;
use wacore_binary::Jid;

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
        self.client.store_issued_tc_tokens(&response.tokens).await;

        Ok(response.tokens)
    }

    /// Prune expired tc tokens from the store.
    ///
    /// Cutoff is AB-prop-aware via [`Client::tc_token_config()`] — the server
    /// may override the default 28-day window (e.g. 26 buckets = 182 days).
    pub async fn prune_expired(&self) -> Result<u32, anyhow::Error> {
        let backend = self.client.persistence_manager.backend();
        let tc_config = self.client.tc_token_config().await;
        let cutoff = wacore::iq::tctoken::tc_token_expiration_cutoff_with(&tc_config);
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
