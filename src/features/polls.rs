//! Poll creation, voting, and vote decryption.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use wacore::poll;
use wacore_binary::{Jid, JidExt};
use waproto::whatsapp as wa;

use crate::client::Client;
use crate::send::SendResult;

#[derive(Debug, Clone)]
pub struct PollOptionResult {
    pub name: String,
    pub voters: Vec<String>,
}

pub struct Polls<'a> {
    client: &'a Client,
}

impl<'a> Polls<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Caller needs the returned `message_secret` to decrypt votes.
    pub async fn create(
        &self,
        to: &Jid,
        name: &str,
        options: &[String],
        selectable_count: u32,
    ) -> Result<(SendResult, Vec<u8>)> {
        if options.len() < 2 {
            return Err(anyhow!("Poll must have at least 2 options"));
        }
        if options.len() > 12 {
            return Err(anyhow!("Polls can have a maximum of 12 options"));
        }
        if selectable_count < 1 || selectable_count > options.len() as u32 {
            return Err(anyhow!(
                "selectable_count must be between 1 and {} (got {selectable_count})",
                options.len()
            ));
        }

        // Duplicate names would produce identical SHA-256 hashes, making votes indistinguishable
        let mut seen = std::collections::HashSet::new();
        for opt in options {
            if !seen.insert(opt) {
                return Err(anyhow!("Duplicate option name: {opt}"));
            }
        }

        let poll_options: Vec<wa::message::poll_creation_message::Option> = options
            .iter()
            .map(|name| wa::message::poll_creation_message::Option {
                option_name: Some(name.clone()),
                ..Default::default()
            })
            .collect();

        let poll_msg = wa::message::PollCreationMessage {
            name: Some(name.to_string()),
            options: poll_options,
            selectable_options_count: Some(selectable_count),
            ..Default::default()
        };

        // WA Web: v3 for single-select, v1 for multi-select (GeneratePollCreationMessageProto.js:39-41)
        let mut message = if selectable_count == 1 {
            wa::Message {
                poll_creation_message_v3: buffa::MessageField::some(poll_msg),
                ..Default::default()
            }
        } else {
            wa::Message {
                poll_creation_message: buffa::MessageField::some(poll_msg),
                ..Default::default()
            }
        };

        // WA Web generates a 32-byte random secret at poll creation time
        // (SendPollCreationMsgAction.js:158). Voters need this to derive their encryption key.
        let message_secret: Vec<u8> = {
            use rand::Rng;
            let mut secret = vec![0u8; 32];
            rand::make_rng::<rand::rngs::StdRng>().fill_bytes(&mut secret);
            secret
        };

        message.message_context_info = buffa::MessageField::some(wa::MessageContextInfo {
            message_secret: Some(message_secret.clone()),
            ..Default::default()
        });

        let result = self.client.send_message(to.clone(), message).await?;
        Ok((result, message_secret))
    }

    pub async fn vote(
        &self,
        chat_jid: &Jid,
        poll_msg_id: &str,
        poll_creator_jid: &Jid,
        message_secret: &[u8],
        option_names: &[String],
    ) -> Result<SendResult> {
        let my_jid = self
            .client
            .get_pn()
            .await
            .ok_or_else(|| anyhow!("Not logged in — cannot determine own JID"))?;
        let my_base = my_jid.to_non_ad();
        let voter_jid_str = my_base.to_string();
        let creator_jid_str = poll_creator_jid.to_non_ad().to_string();

        let selected_hashes: Vec<Vec<u8>> = option_names
            .iter()
            .map(|name| poll::compute_option_hash(name).to_vec())
            .collect();

        let key = poll::derive_vote_encryption_key(
            message_secret,
            poll_msg_id,
            &creator_jid_str,
            &voter_jid_str,
        )?;

        let (enc_payload, iv) =
            poll::encrypt_poll_vote(&selected_hashes, &key, poll_msg_id, &voter_jid_str)?;

        let from_me = my_base.is_same_user_as(poll_creator_jid);

        let poll_update = wa::message::PollUpdateMessage {
            poll_creation_message_key: buffa::MessageField::some(wa::MessageKey {
                remote_jid: Some(chat_jid.to_string()),
                from_me: Some(from_me),
                id: Some(poll_msg_id.to_string()),
                participant: if chat_jid.is_group() {
                    Some(poll_creator_jid.to_string())
                } else {
                    None
                },
                ..Default::default()
            }),
            vote: buffa::MessageField::some(wa::message::PollEncValue {
                enc_payload: Some(enc_payload),
                enc_iv: Some(iv.to_vec()),
                ..Default::default()
            }),
            metadata: buffa::MessageField::some(wa::message::PollUpdateMessageMetadata {
                ..Default::default()
            }),
            sender_timestamp_ms: Some(wacore::time::now_millis()),
            ..Default::default()
        };

        let message = wa::Message {
            poll_update_message: buffa::MessageField::some(poll_update),
            ..Default::default()
        };

        self.client.send_message(chat_jid.clone(), message).await
    }

    /// Returns the selected option hashes (each 32 bytes).
    /// JIDs are normalized (AD suffix stripped) to match the key derivation in `vote()`.
    pub fn decrypt_vote(
        enc_payload: &[u8],
        enc_iv: &[u8],
        message_secret: &[u8],
        poll_msg_id: &str,
        poll_creator_jid: &Jid,
        voter_jid: &Jid,
    ) -> Result<Vec<Vec<u8>>> {
        let creator = poll_creator_jid.to_non_ad().to_string();
        let voter = voter_jid.to_non_ad().to_string();
        let key = poll::derive_vote_encryption_key(message_secret, poll_msg_id, &creator, &voter)?;
        poll::decrypt_poll_vote(enc_payload, enc_iv, &key, poll_msg_id, &voter)
    }

    /// Decrypts each vote and tallies per-option results.
    /// Later votes from the same voter replace earlier ones (last-vote-wins).
    /// `votes` should be ordered oldest-first.
    pub fn aggregate_votes(
        poll_options: &[String],
        votes: &[(&Jid, &[u8], &[u8])], // (voter_jid, enc_payload, enc_iv)
        message_secret: &[u8],
        poll_msg_id: &str,
        poll_creator_jid: &Jid,
    ) -> Result<Vec<PollOptionResult>> {
        let option_hashes: Vec<([u8; 32], &str)> = poll_options
            .iter()
            .map(|name| (poll::compute_option_hash(name), name.as_str()))
            .collect();

        // `creator_str` is invariant across voters; `decrypt_vote` used to
        // recompute it per voter via `poll_creator_jid.to_non_ad().to_string()`.
        let creator_str = poll_creator_jid.to_non_ad().to_string();

        // Last-vote-wins: each new vote from the same voter replaces the previous
        let mut latest_votes: HashMap<String, Vec<Vec<u8>>> = HashMap::with_capacity(votes.len());
        for (voter_jid, enc_payload, enc_iv) in votes {
            let voter_str = voter_jid.to_non_ad().to_string();
            let key = match poll::derive_vote_encryption_key(
                message_secret,
                poll_msg_id,
                &creator_str,
                &voter_str,
            ) {
                Ok(k) => k,
                Err(e) => {
                    log::warn!("Failed to derive vote key for {voter_jid}: {e}");
                    continue;
                }
            };
            match poll::decrypt_poll_vote(enc_payload, enc_iv, &key, poll_msg_id, &voter_str) {
                Ok(selected_hashes) => {
                    if selected_hashes.is_empty() {
                        // Empty selection = voter cleared their vote
                        latest_votes.remove(&voter_str);
                    } else {
                        latest_votes.insert(voter_str, selected_hashes);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to decrypt vote from {voter_jid}: {e}");
                }
            }
        }

        let mut results: Vec<PollOptionResult> = poll_options
            .iter()
            .map(|name| PollOptionResult {
                name: name.clone(),
                voters: Vec::new(),
            })
            .collect();

        for (voter_jid, selected_hashes) in &latest_votes {
            for hash in selected_hashes {
                if let Ok(hash_arr) = <[u8; 32]>::try_from(hash.as_slice())
                    && let Some(idx) = option_hashes.iter().position(|(h, _)| *h == hash_arr)
                {
                    results[idx].voters.push(voter_jid.clone());
                }
            }
        }

        Ok(results)
    }
}

impl Client {
    pub fn polls(&self) -> Polls<'_> {
        Polls::new(self)
    }
}
