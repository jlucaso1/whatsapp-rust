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
//! ## VoIP call integration
//! WA Web calls `sendTcToken` for each participant when initiating calls
//! (`WAWeb/Voip/StartCall.js:140` →
//! `WAWeb/Send/TcTokenChatAction.js::sendTcToken`). That amounts to
//! `issuePrivacyToken(peer_lid, [TrustedContact], now)` gated by a
//! per-chat timestamp (`shouldSendNewToken`). Without it the server
//! returns **463 nack** on the call offer and the call is aborted.
//!
//! Use [`TcToken::pre_call_send`] before [`crate::calls::CallManager::start_call`].

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

    /// Issue a TrustedContact privacy token for `peer` before placing a
    /// call, matching WA Web's `sendTcToken(jid)` step in `StartCall.js`.
    /// Without this, the server returns **463 nack** on the call offer.
    ///
    /// This is a best-effort path: any IQ error is swallowed and logged at
    /// WARN, because (a) the server only enforces the token for privacy
    /// protection features, and (b) we want the call to still go through
    /// so the user gets a UI-level error from the call handler, not a
    /// silent abort from this pre-step.
    ///
    /// Returns `true` if a token was issued, `false` if we skipped
    /// (issue failed). Callers shouldn't gate the call on the return.
    pub async fn pre_call_send(&self, peer: &Jid) -> bool {
        match self.issue_tokens(std::slice::from_ref(peer)).await {
            Ok(tokens) => !tokens.is_empty(),
            Err(e) => {
                log::warn!(
                    target: "Client/TcToken",
                    "pre_call_send: issue_tokens({}) failed: {:?}",
                    peer, e
                );
                false
            }
        }
    }
}

impl Client {
    /// Access trusted contact token operations.
    pub fn tc_token(&self) -> TcToken<'_> {
        TcToken::new(self)
    }
}
