use crate::client::Client;
use anyhow::{Result, anyhow};
use wacore::poll::{
    compute_poll_option_hash, decrypt_poll_option, encrypt_poll_option, encrypt_poll_vote,
    generate_poll_enc_key,
};
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Type of poll: regular poll or quiz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollType {
    /// A standard poll where all choices are equally valid.
    Poll,
    /// A quiz-style poll with a correct answer.
    Quiz,
}

impl From<PollType> for i32 {
    fn from(pt: PollType) -> Self {
        match pt {
            PollType::Poll => 0,
            PollType::Quiz => 1,
        }
    }
}

/// Options for creating a poll.
#[derive(Debug, Clone)]
pub struct PollOptions {
    /// The question text for the poll.
    pub name: String,
    /// The available options, limited to 12 options.
    pub options: Vec<String>,
    /// Maximum number of options a user can select (default: 1 for single choice).
    pub selectable_count: u32,
    /// Type of poll (regular or quiz).
    pub poll_type: PollType,
    /// For quiz polls, the index of the correct answer (0-based).
    pub correct_answer_index: Option<usize>,
}

impl PollOptions {
    /// Create a new poll with a question and options.
    pub fn new(name: impl Into<String>, options: Vec<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(anyhow!("Poll name cannot be empty"));
        }
        if options.is_empty() {
            return Err(anyhow!("Poll must have at least one option"));
        }
        if options.len() > 12 {
            return Err(anyhow!("Polls can have a maximum of 12 options"));
        }
        for (i, opt) in options.iter().enumerate() {
            if opt.is_empty() {
                return Err(anyhow!("Poll option {} cannot be empty", i + 1));
            }
        }
        Ok(Self {
            name,
            options,
            selectable_count: 1,
            poll_type: PollType::Poll,
            correct_answer_index: None,
        })
    }

    /// Create a quiz-style poll with a correct answer.
    pub fn new_quiz(
        name: impl Into<String>,
        options: Vec<String>,
        correct_answer_index: usize,
    ) -> Result<Self> {
        let mut poll = Self::new(name, options)?;
        if correct_answer_index >= poll.options.len() {
            return Err(anyhow!(
                "Correct answer index {} out of bounds (poll has {} options)",
                correct_answer_index,
                poll.options.len()
            ));
        }
        poll.poll_type = PollType::Quiz;
        poll.correct_answer_index = Some(correct_answer_index);
        Ok(poll)
    }

    /// Set the number of options users can select (for multi-select polls).
    pub fn with_selectable_count(mut self, count: u32) -> Result<Self> {
        if count == 0 {
            return Err(anyhow!("Selectable count must be at least 1"));
        }
        if count as usize > self.options.len() {
            return Err(anyhow!(
                "Selectable count {} exceeds number of options {}",
                count,
                self.options.len()
            ));
        }
        self.selectable_count = count;
        Ok(self)
    }
}

/// Result of poll creation, containing the message ID and encryption key.
#[derive(Debug, Clone)]
pub struct PollCreationResult {
    /// The message ID of the sent poll.
    pub message_id: String,
    /// The encryption key used for this poll (needed for decrypting votes).
    pub enc_key: [u8; 32],
}

/// A vote to submit on a poll.
#[derive(Debug, Clone)]
pub struct PollVote {
    /// The indices of selected options (0-based).
    pub selected_option_indices: Vec<usize>,
}

impl PollVote {
    /// Create a single-choice vote.
    pub fn single(option_index: usize) -> Self {
        Self {
            selected_option_indices: vec![option_index],
        }
    }

    /// Create a multi-choice vote.
    pub fn multiple(option_indices: Vec<usize>) -> Self {
        Self {
            selected_option_indices: option_indices,
        }
    }
}

pub struct Polls<'a> {
    client: &'a Client,
}

impl<'a> Polls<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Create and send a poll to a chat.
    ///
    /// Returns the message ID and encryption key needed to decrypt votes.
    ///
    /// # Example
    /// ```no_run
    /// # use whatsapp_rust::features::{Polls, PollOptions};
    /// # async fn example(polls: Polls<'_>, chat_jid: wacore_binary::jid::Jid) -> anyhow::Result<()> {
    /// let options = PollOptions::new(
    ///     "What's your favorite color?",
    ///     vec!["Red".into(), "Blue".into(), "Green".into()]
    /// )?;
    /// let result = polls.create(&chat_jid, options).await?;
    /// println!("Poll created with ID: {}", result.message_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(&self, to: &Jid, options: PollOptions) -> Result<PollCreationResult> {
        // Generate encryption key
        let enc_key = generate_poll_enc_key();

        // Encrypt each option
        let mut encrypted_options = Vec::new();
        for option_name in &options.options {
            let (encrypted_payload, iv) = encrypt_poll_option(option_name, &enc_key)?;
            let option_hash = compute_poll_option_hash(&encrypted_payload, &iv);

            encrypted_options.push(wa::message::poll_creation_message::Option {
                option_name: Some(option_name.clone()),
                option_hash: Some(hex::encode(option_hash)),
            });
        }

        // Handle correct answer for quiz
        let correct_answer = options
            .correct_answer_index
            .map(|index| encrypted_options[index].clone());

        // Build poll creation message
        let poll_msg = wa::message::PollCreationMessage {
            enc_key: Some(enc_key.to_vec()),
            name: Some(options.name),
            options: encrypted_options,
            selectable_options_count: Some(options.selectable_count),
            context_info: None,
            poll_content_type: None,
            poll_type: Some(options.poll_type.into()),
            correct_answer,
        };

        let message = wa::Message {
            poll_creation_message_v3: Some(Box::new(poll_msg)),
            message_context_info: None,
            ..Default::default()
        };

        // Send the message
        let message_id = self.client.send_message(to.clone(), message).await?;

        Ok(PollCreationResult {
            message_id,
            enc_key,
        })
    }

    /// Vote on a poll.
    ///
    /// You must provide the original poll's message key and encryption key.
    ///
    /// # Arguments
    /// * `poll_chat_jid` - The JID of the chat where the poll was sent
    /// * `poll_message_id` - The message ID of the original poll
    /// * `poll_sender_jid` - The JID of who created the poll
    /// * `enc_key` - The encryption key from the original poll message
    /// * `encrypted_option_hashes` - The SHA-256 hashes of the encrypted options to vote for
    ///
    /// # Example
    /// ```no_run
    /// # use whatsapp_rust::features::{Polls, PollVote};
    /// # async fn example(
    /// #     polls: Polls<'_>,
    /// #     chat_jid: wacore_binary::jid::Jid,
    /// #     poll_msg_id: String,
    /// #     poll_sender: wacore_binary::jid::Jid,
    /// #     enc_key: [u8; 32],
    /// #     option_hashes: Vec<Vec<u8>>
    /// # ) -> anyhow::Result<()> {
    /// let message_id = polls.vote(
    ///     &chat_jid,
    ///     &poll_msg_id,
    ///     &poll_sender,
    ///     &enc_key,
    ///     &option_hashes,
    /// ).await?;
    /// println!("Vote submitted with ID: {}", message_id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn vote(
        &self,
        poll_chat_jid: &Jid,
        poll_message_id: &str,
        poll_sender_jid: &Jid,
        enc_key: &[u8; 32],
        encrypted_option_hashes: &[Vec<u8>],
    ) -> Result<String> {
        if encrypted_option_hashes.is_empty() {
            return Err(anyhow!("Must select at least one option"));
        }

        // Encrypt the vote
        let (encrypted_vote, vote_iv) = encrypt_poll_vote(encrypted_option_hashes, enc_key)?;

        // Determine if this is our own poll
        let my_jid = self.client.get_pn().await;
        let from_me = my_jid.as_ref() == Some(poll_sender_jid);

        // Build poll update message
        let poll_update = wa::message::PollUpdateMessage {
            poll_creation_message_key: Some(wa::MessageKey {
                remote_jid: Some(poll_chat_jid.to_string()),
                from_me: Some(from_me),
                id: Some(poll_message_id.to_string()),
                participant: Some(poll_sender_jid.to_string()),
            }),
            vote: Some(wa::message::PollEncValue {
                enc_payload: Some(encrypted_vote),
                enc_iv: Some(vote_iv.to_vec()),
            }),
            metadata: Some(wa::message::PollUpdateMessageMetadata {}),
            sender_timestamp_ms: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis() as i64,
            ),
        };

        let message = wa::Message {
            poll_update_message: Some(poll_update),
            ..Default::default()
        };

        // Send to the chat
        let message_id = self
            .client
            .send_message(poll_chat_jid.clone(), message)
            .await?;

        Ok(message_id)
    }

    /// Decrypt a poll option from an encrypted payload.
    ///
    /// This is a utility function for decrypting poll options when processing
    /// incoming poll messages or votes.
    pub fn decrypt_option(
        &self,
        encrypted_payload: &[u8],
        iv: &[u8],
        enc_key: &[u8],
    ) -> Result<String> {
        decrypt_poll_option(encrypted_payload, iv, enc_key)
    }
}

impl Client {
    /// Access polls operations.
    pub fn polls(&self) -> Polls<'_> {
        Polls::new(self)
    }
}
