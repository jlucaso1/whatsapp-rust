//! Example demonstrating poll creation and voting.
//!
//! This example shows how to:
//! - Create a simple poll
//! - Create a quiz with a correct answer
//! - Vote on a poll
//!
//! Run with: cargo run --example polls --features sqlite-storage

use wacore_binary::jid::Jid;
use whatsapp_rust::{Client, PollOptions, PollType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize client (see other examples for full setup)
    // let client = Client::new(...).await?;

    println!("=== WhatsApp Polls Example ===\n");

    // Example 1: Create a simple poll
    println!("Example 1: Creating a simple poll");
    let poll_options = PollOptions::new(
        "What's your favorite programming language?",
        vec![
            "Rust".to_string(),
            "Python".to_string(),
            "JavaScript".to_string(),
            "Go".to_string(),
        ],
    )?;

    println!("Poll created with {} options", poll_options.options.len());
    println!("Poll type: {:?}", poll_options.poll_type);
    println!("Selectable count: {}\n", poll_options.selectable_count);

    // To send the poll:
    // let chat_jid: Jid = "1234567890@s.whatsapp.net".parse()?;
    // let result = client.polls().create(&chat_jid, poll_options).await?;
    // println!("Poll sent! Message ID: {}", result.message_id);
    // // Save the encryption key for decrypting votes later
    // let enc_key = result.enc_key;

    // Example 2: Create a quiz with a correct answer
    println!("Example 2: Creating a quiz");
    let quiz_options = PollOptions::new_quiz(
        "What is the capital of France?",
        vec![
            "London".to_string(),
            "Paris".to_string(), // Correct answer (index 1)
            "Berlin".to_string(),
            "Madrid".to_string(),
        ],
        1, // Index of correct answer
    )?;

    println!("Quiz created with correct answer at index 1");
    println!("Poll type: {:?}\n", quiz_options.poll_type);

    // To send the quiz:
    // let result = client.polls().create(&chat_jid, quiz_options).await?;

    // Example 3: Create a multi-select poll
    println!("Example 3: Creating a multi-select poll");
    let multi_select = PollOptions::new(
        "Which frameworks have you used?",
        vec![
            "Tokio".to_string(),
            "Actix".to_string(),
            "Axum".to_string(),
            "Rocket".to_string(),
        ],
    )?
    .with_selectable_count(3)?; // Allow selecting up to 3 options

    println!(
        "Multi-select poll allows {} selections\n",
        multi_select.selectable_count
    );

    // Example 4: Voting on a poll
    println!("Example 4: Voting on a poll");
    // To vote on a poll, you need:
    // - The chat JID where the poll was sent
    // - The message ID of the poll
    // - The JID of who created the poll
    // - The encryption key from the original poll
    // - The hashes of the encrypted options you want to vote for

    // Single choice vote:
    // let vote = PollVote::single(0); // Vote for first option

    // Multi choice vote:
    // let vote = PollVote::multiple(vec![0, 2]); // Vote for options 0 and 2

    // To submit the vote:
    // let message_id = client.polls().vote(
    //     &chat_jid,
    //     &poll_message_id,
    //     &poll_sender_jid,
    //     &enc_key,
    //     &selected_option_hashes,
    // ).await?;
    // println!("Vote submitted! Message ID: {}", message_id);

    println!("\nNote: This example shows the API structure.");
    println!("Connect a real client to send/receive polls.");

    Ok(())
}
