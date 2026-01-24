//! Pair code authentication for phone number linking.
//!
//! This module provides an alternative to QR code pairing. Users enter an
//! 8-character code on their phone instead of scanning a QR code.
//!
//! # Usage
//!
//! ## Random Code (Default)
//!
//! ```rust,no_run
//! use whatsapp_rust::pair_code::PairCodeOptions;
//!
//! # async fn example(client: std::sync::Arc<whatsapp_rust::Client>) -> Result<(), Box<dyn std::error::Error>> {
//! let options = PairCodeOptions {
//!     phone_number: "15551234567".to_string(),
//!     ..Default::default()
//! };
//! let code = client.pair_with_code(options).await?;
//! println!("Enter this code on your phone: {}", code);
//! # Ok(())
//! # }
//! ```
//!
//! ## Custom Pairing Code
//!
//! You can specify your own 8-character code using Crockford Base32 alphabet
//! (characters: `123456789ABCDEFGHJKLMNPQRSTVWXYZ` - excludes 0, I, O, U):
//!
//! ```rust,no_run
//! use whatsapp_rust::pair_code::PairCodeOptions;
//!
//! # async fn example(client: std::sync::Arc<whatsapp_rust::Client>) -> Result<(), Box<dyn std::error::Error>> {
//! let options = PairCodeOptions {
//!     phone_number: "15551234567".to_string(),
//!     custom_code: Some("MYCODE12".to_string()), // Must be exactly 8 valid chars
//!     ..Default::default()
//! };
//! let code = client.pair_with_code(options).await?;
//! assert_eq!(code, "MYCODE12");
//! # Ok(())
//! # }
//! ```
//!
//! ## Concurrent with QR Codes
//!
//! Pair code and QR code can run simultaneously. Whichever completes first wins.

use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use crate::types::events::Event;
use log::{error, info, warn};
use rand::TryRngCore;
use std::sync::Arc;
use wacore::libsignal::protocol::KeyPair;
use wacore::pair_code::{PairCodeError, PairCodeState, PairCodeUtils};
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

// Re-export types for user convenience
pub use wacore::pair_code::{PairCodeOptions, PlatformId};

impl Client {
    /// Initiates pair code authentication as an alternative to QR code pairing.
    ///
    /// This method starts the phone number linking process. The returned code should
    /// be displayed to the user, who then enters it on their phone in:
    /// **WhatsApp > Linked Devices > Link a Device > Link with phone number instead**
    ///
    /// This can run concurrently with QR code pairing - whichever completes first wins.
    ///
    /// # Arguments
    ///
    /// * `options` - Configuration for pair code authentication
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The 8-character pairing code to display
    /// * `Err` - If validation fails, not connected, or server error
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use whatsapp_rust::pair_code::PairCodeOptions;
    ///
    /// # async fn example(client: std::sync::Arc<whatsapp_rust::Client>) -> Result<(), Box<dyn std::error::Error>> {
    /// let options = PairCodeOptions {
    ///     phone_number: "15551234567".to_string(),
    ///     show_push_notification: true,
    ///     custom_code: None, // Generate random code
    ///     ..Default::default()
    /// };
    ///
    /// let code = client.pair_with_code(options).await?;
    /// println!("Enter this code on your phone: {}", code);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn pair_with_code(
        self: &Arc<Self>,
        options: PairCodeOptions,
    ) -> Result<String, PairCodeError> {
        // Strip non-digit characters from phone number (allows "+1-555-123-4567" format)
        let phone_number: String = options
            .phone_number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();

        // Validate phone number
        if phone_number.is_empty() {
            return Err(PairCodeError::PhoneNumberRequired);
        }
        if phone_number.len() < 7 {
            return Err(PairCodeError::PhoneNumberTooShort);
        }
        if phone_number.starts_with('0') {
            return Err(PairCodeError::PhoneNumberNotInternational);
        }

        // Generate or validate code
        let code = match &options.custom_code {
            Some(custom) => {
                if !PairCodeUtils::validate_code(custom) {
                    return Err(PairCodeError::InvalidCustomCode);
                }
                custom.to_uppercase()
            }
            None => PairCodeUtils::generate_code(),
        };

        info!(
            target: "Client/PairCode",
            "Starting pair code authentication for phone: {}",
            phone_number
        );

        // Generate ephemeral keypair for this pairing session
        let ephemeral_keypair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());

        // Get device state for noise key
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let noise_static_pub: [u8; 32] = device_snapshot
            .noise_key
            .public_key
            .public_key_bytes()
            .try_into()
            .expect("noise key is 32 bytes");

        // Derive key and encrypt ephemeral pub (expensive PBKDF2 operation)
        // Run in spawn_blocking to avoid stalling the async runtime
        let code_clone = code.clone();
        let ephemeral_pub: [u8; 32] = ephemeral_keypair
            .public_key
            .public_key_bytes()
            .try_into()
            .expect("ephemeral key is 32 bytes");

        let wrapped_ephemeral = tokio::task::spawn_blocking(move || {
            PairCodeUtils::encrypt_ephemeral_pub(&ephemeral_pub, &code_clone)
        })
        .await
        .map_err(|e| PairCodeError::CryptoError(format!("spawn_blocking failed: {e}")))?;

        // Build the stage 1 IQ node
        let req_id = self.generate_request_id();
        let iq_content = PairCodeUtils::build_companion_hello_iq(
            &phone_number,
            &noise_static_pub,
            &wrapped_ephemeral,
            options.platform_id,
            &options.platform_display,
            options.show_push_notification,
            req_id.clone(),
        );

        // Send the IQ and wait for response using the standard send_iq method
        let query = InfoQuery {
            query_type: InfoQueryType::Set,
            namespace: "md",
            to: Jid::new("", SERVER_JID),
            target: None,
            content: Some(NodeContent::Nodes(
                iq_content
                    .children()
                    .map(|c| c.to_vec())
                    .unwrap_or_default(),
            )),
            id: Some(req_id),
            timeout: Some(std::time::Duration::from_secs(30)),
        };

        let response = self
            .send_iq(query)
            .await
            .map_err(|e: IqError| PairCodeError::RequestFailed(e.to_string()))?;

        // Extract pairing ref from response
        let pairing_ref = PairCodeUtils::parse_companion_hello_response(&response)
            .ok_or(PairCodeError::MissingPairingRef)?;

        info!(
            target: "Client/PairCode",
            "Stage 1 complete, waiting for phone confirmation. Code: {}",
            code
        );

        // Store state for when phone confirms
        *self.pair_code_state.lock().await = PairCodeState::WaitingForPhoneConfirmation {
            pairing_ref,
            phone_jid: phone_number,
            pair_code: code.clone(),
            ephemeral_keypair: Box::new(ephemeral_keypair),
        };

        // Dispatch event for user to display the code
        self.core.event_bus.dispatch(&Event::PairingCode {
            code: code.clone(),
            timeout: PairCodeUtils::code_validity(),
        });

        Ok(code)
    }
}

/// Handles the `link_code_companion_reg` notification (stage 2 trigger).
///
/// This is called when the user enters the code on their phone. The notification
/// contains the primary device's encrypted ephemeral public key and identity public key.
pub(crate) async fn handle_pair_code_notification(client: &Arc<Client>, node: &Node) -> bool {
    // Check if this is a link_code_companion_reg notification
    let Some(reg_node) = node.get_optional_child_by_tag(&["link_code_companion_reg"]) else {
        return false;
    };

    // Extract primary's wrapped ephemeral public key (80 bytes: salt + iv + encrypted key)
    let primary_wrapped_ephemeral = match reg_node
        .get_optional_child_by_tag(&["link_code_pairing_wrapped_primary_ephemeral_pub"])
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(b)) if b.len() == 80 => b.clone(),
        _ => {
            warn!(
                target: "Client/PairCode",
                "Missing or invalid primary wrapped ephemeral pub in notification"
            );
            return false;
        }
    };

    // Extract primary's identity public key (32 bytes, unencrypted)
    let primary_identity_pub: [u8; 32] = match reg_node
        .get_optional_child_by_tag(&["primary_identity_pub"])
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(b)) if b.len() == 32 => match b.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                warn!(
                    target: "Client/PairCode",
                    "Failed to convert primary identity pub to array"
                );
                return false;
            }
        },
        _ => {
            warn!(
                target: "Client/PairCode",
                "Missing or invalid primary identity pub in notification"
            );
            return false;
        }
    };

    // Get current pair code state
    let mut state_guard = client.pair_code_state.lock().await;
    let state = std::mem::take(&mut *state_guard);
    drop(state_guard);

    let (pairing_ref, phone_jid, pair_code, ephemeral_keypair) = match state {
        PairCodeState::WaitingForPhoneConfirmation {
            pairing_ref,
            phone_jid,
            pair_code,
            ephemeral_keypair,
        } => (pairing_ref, phone_jid, pair_code, ephemeral_keypair),
        _ => {
            warn!(
                target: "Client/PairCode",
                "Received pair code notification but not in waiting state"
            );
            return false;
        }
    };

    info!(
        target: "Client/PairCode",
        "Phone confirmed code entry, processing stage 2"
    );

    // Decrypt primary's ephemeral public key (expensive PBKDF2 operation)
    // Run in spawn_blocking to avoid stalling the async runtime
    let pair_code_clone = pair_code.clone();
    let primary_ephemeral_pub = match tokio::task::spawn_blocking(move || {
        PairCodeUtils::decrypt_primary_ephemeral_pub(&primary_wrapped_ephemeral, &pair_code_clone)
    })
    .await
    {
        Ok(Ok(pub_key)) => pub_key,
        Ok(Err(e)) => {
            error!(
                target: "Client/PairCode",
                "Failed to decrypt primary ephemeral pub: {e}"
            );
            return false;
        }
        Err(e) => {
            error!(
                target: "Client/PairCode",
                "spawn_blocking failed: {e}"
            );
            return false;
        }
    };

    // Get device keys
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;

    // Prepare encrypted key bundle
    // TODO: Store `new_adv_secret` via DeviceCommand::SetAdvSecretKey to enable HMAC
    // verification in pair-success. Currently the HMAC check in do_pair_crypto is
    // commented out, so pairing works without it. See wacore/src/pair.rs:147-153.
    let (wrapped_bundle, _new_adv_secret) = match PairCodeUtils::prepare_key_bundle(
        &ephemeral_keypair,
        &primary_ephemeral_pub,
        &primary_identity_pub,
        &device_snapshot.identity_key,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!(target: "Client/PairCode", "Failed to prepare key bundle: {e}");
            return false;
        }
    };

    // Build and send stage 2 IQ
    let req_id = client.generate_request_id();
    let identity_pub: [u8; 32] = device_snapshot
        .identity_key
        .public_key
        .public_key_bytes()
        .try_into()
        .expect("identity key is 32 bytes");

    let iq = PairCodeUtils::build_companion_finish_iq(
        &phone_jid,
        wrapped_bundle,
        &identity_pub,
        &pairing_ref,
        req_id,
    );

    if let Err(e) = client.send_node(iq).await {
        error!(target: "Client/PairCode", "Failed to send companion_finish: {e}");
        return false;
    }

    info!(
        target: "Client/PairCode",
        "Sent companion_finish, waiting for pair-success"
    );

    // Mark state as completed
    *client.pair_code_state.lock().await = PairCodeState::Completed;

    true
}
