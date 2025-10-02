use crate::client::Client;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;

/// Phone linking cache for pairing code authentication
#[derive(Clone)]
pub struct PhoneLinkingCache {
    pub jid: Jid,
    pub key_pair: wacore::libsignal::protocol::KeyPair,
    pub linking_code: String,
    pub pairing_ref: String,
}

impl Client {
    /// Generates a pairing code that can be used to link to a phone without scanning a QR code.
    ///
    /// You must connect the client normally before calling this (which means you'll also receive a QR code
    /// event, but that can be ignored when doing code pairing). You should also wait for `*events.Connected`
    /// before calling this to ensure the connection is fully established. If using `Client::connect()`, wait for
    /// the first item in the channel. Alternatively, sleeping for a second after calling connect will probably work too.
    ///
    /// The exact expiry of pairing codes is unknown, but QR codes are always generated and the login websocket is closed
    /// after the QR codes run out, which means there's a 160-second time limit. It is recommended to generate the pairing
    /// code immediately after connecting to the websocket to have the maximum time.
    ///
    /// The client_type parameter must be one of the PairClientType constants, but which one doesn't matter.
    /// The client_display_name must be formatted as `Browser (OS)`, and only common browsers/OSes are allowed
    /// (the server will validate it and return 400 if it's wrong).
    ///
    /// See https://faq.whatsapp.com/1324084875126592 for more info
    pub async fn pair_phone(
        &self,
        phone: String,
        show_push_notification: bool,
        client_type: PairClientType,
        client_display_name: String,
    ) -> Result<String, anyhow::Error> {
        if self.phone_linking_cache.lock().await.is_some() {
            return Err(anyhow::anyhow!("Pairing already in progress"));
        }

        // Clean phone number - remove non-digits
        let phone = phone
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>();
        if phone.len() <= 6 {
            return Err(anyhow::anyhow!("Phone number too short"));
        }
        if phone.starts_with('0') {
            return Err(anyhow::anyhow!(
                "Phone number should not start with 0 (use international format)"
            ));
        }

        let jid = format!("{}@s.whatsapp.net", phone).parse::<Jid>()?;

        // Generate ephemeral key pair and linking code using wacore utilities
        let (ephemeral_key_pair, ephemeral_key, encoded_linking_code) =
            wacore::pair::PairUtils::generate_companion_ephemeral_key()?;

        // Send IQ request
        let link_code_companion_reg = NodeBuilder::new("link_code_companion_reg")
            .attr("jid", jid.to_string())
            .attr("stage", "companion_hello")
            .attr(
                "should_show_push_notification",
                if show_push_notification {
                    "true"
                } else {
                    "false"
                },
            )
            .children(vec![
                NodeBuilder::new("link_code_pairing_wrapped_companion_ephemeral_pub")
                    .bytes(ephemeral_key)
                    .build(),
                NodeBuilder::new("companion_server_auth_key_pub")
                    .bytes(
                        self.core
                            .device
                            .noise_key
                            .public_key
                            .public_key_bytes()
                            .to_vec(),
                    )
                    .build(),
                NodeBuilder::new("companion_platform_id")
                    .bytes(vec![b'0' + (client_type as u8)])
                    .build(),
                NodeBuilder::new("companion_platform_display")
                    .bytes(client_display_name)
                    .build(),
                NodeBuilder::new("link_code_pairing_nonce")
                    .bytes(vec![0])
                    .build(),
            ])
            .build();

        let resp = self
            .send_iq(crate::request::InfoQuery {
                namespace: "md",
                query_type: crate::request::InfoQueryType::Set,
                to: "s.whatsapp.net".parse().unwrap(),
                target: None,
                id: None,
                content: Some(wacore_binary::node::NodeContent::Nodes(vec![
                    link_code_companion_reg,
                ])),
                timeout: None,
            })
            .await?;

        // Extract pairing reference from response
        let link_code_companion_regs = resp.get_children_by_tag("link_code_companion_reg");
        if link_code_companion_regs.is_empty() {
            return Err(anyhow::anyhow!(
                "No link_code_companion_reg found in response"
            ));
        }
        let link_code_companion_reg = &link_code_companion_regs[0];
        let pairing_ref_nodes =
            link_code_companion_reg.get_children_by_tag("link_code_pairing_ref");
        if pairing_ref_nodes.is_empty() {
            return Err(anyhow::anyhow!(
                "No link_code_pairing_ref found in response"
            ));
        }
        let pairing_ref_node = &pairing_ref_nodes[0];
        let pairing_ref = match &pairing_ref_node.content {
            Some(wacore_binary::node::NodeContent::Bytes(bytes)) => {
                String::from_utf8(bytes.clone())?
            }
            _ => return Err(anyhow::anyhow!("Unexpected pairing ref content type")),
        };

        // Store pairing state
        *self.phone_linking_cache.lock().await = Some(PhoneLinkingCache {
            jid,
            key_pair: ephemeral_key_pair,
            linking_code: encoded_linking_code.clone(),
            pairing_ref,
        });

        // Return formatted pairing code (XXXX-XXXX)
        Ok(format!(
            "{}-{}",
            &encoded_linking_code[0..4],
            &encoded_linking_code[4..8]
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairClientType {
    Unknown = 0,
    Chrome = 1,
    Edge = 2,
    Firefox = 3,
    IE = 4,
    Opera = 5,
    Safari = 6,
    Electron = 7,
    UWP = 8,
    OtherWebClient = 9,
}

impl From<PairClientType> for i32 {
    fn from(client_type: PairClientType) -> i32 {
        client_type as i32
    }
}

#[cfg(test)]
mod tests {

    use rand::rng;
    use wacore::libsignal::protocol::{IdentityKeyPair, KeyPair};
    use wacore::pair::PairUtils;

    #[tokio::test]
    async fn test_pairing_code_crypto_roundtrip() {
        // Test that the pairing code crypto utilities work correctly
        // (These tests remain relevant as they test the underlying crypto that pair_phone() uses)

        // Generate companion ephemeral key and pairing code
        let (companion_ephemeral, wrapped_key, pairing_code) =
            PairUtils::generate_companion_ephemeral_key().unwrap();

        // The wrapped_key contains the encrypted companion ephemeral public key
        // Let's decrypt it back using the pairing code
        let decrypted_companion_pub =
            PairUtils::decrypt_primary_ephemeral_pub(&pairing_code, &wrapped_key).unwrap();

        // Should match the original companion ephemeral public key
        assert_eq!(
            decrypted_companion_pub,
            *companion_ephemeral.public_key.public_key_bytes()
        );

        // Test that we can compute a shared secret (using the same key for both sides as a test)
        // In real usage, this would be with different keys from primary and companion devices
        let shared_secret = PairUtils::compute_pairing_shared_secret(
            &companion_ephemeral.private_key,
            &decrypted_companion_pub,
        )
        .unwrap();

        // Shared secret should be 32 bytes
        assert_eq!(shared_secret.len(), 32);
    }

    #[tokio::test]
    async fn test_pairing_code_uniqueness() {
        // Test that generated pairing codes are unique
        let mut codes = std::collections::HashSet::new();

        for _ in 0..10 {
            let (_, _, code) = PairUtils::generate_companion_ephemeral_key().unwrap();
            assert!(codes.insert(code), "Generated duplicate pairing code");
        }
    }

    #[tokio::test]
    async fn test_invalid_pairing_code() {
        // Test that invalid pairing codes produce different decryption results
        let (_, wrapped_key, _) = PairUtils::generate_companion_ephemeral_key().unwrap();

        // Try to decrypt with wrong pairing code
        let result1 = PairUtils::decrypt_primary_ephemeral_pub("INVALID", &wrapped_key);

        // Try to decrypt with another wrong pairing code
        let result2 = PairUtils::decrypt_primary_ephemeral_pub("ALSOINV", &wrapped_key);

        // Both should succeed (PBKDF2 always produces a key), but produce different results
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_ne!(result1.unwrap(), result2.unwrap());
    }

    #[tokio::test]
    async fn test_key_bundle_encryption_decryption() {
        // Test the complete key bundle encryption and decryption flow
        let companion_identity = IdentityKeyPair::generate(&mut rng());
        let primary_identity = IdentityKeyPair::generate(&mut rng());

        // Generate test data
        let companion_ephemeral = KeyPair::generate(&mut rng());
        let primary_ephemeral = KeyPair::generate(&mut rng());

        // Compute shared secrets
        let ephemeral_shared_secret = PairUtils::compute_pairing_shared_secret(
            &companion_ephemeral.private_key,
            &primary_ephemeral
                .public_key
                .public_key_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let identity_shared_secret = PairUtils::compute_pairing_shared_secret(
            companion_identity.private_key(),
            &primary_identity
                .public_key()
                .public_key_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        // Generate random bytes for ADV secret
        let adv_secret_random = {
            use rand::RngCore;
            let mut random = [0u8; 32];
            rand::rng().fill_bytes(&mut random);
            random
        };

        // Encrypt the key bundle
        let wrapped_key_bundle = PairUtils::encrypt_key_bundle(
            &ephemeral_shared_secret,
            companion_identity
                .public_key()
                .public_key_bytes()
                .try_into()
                .unwrap(),
            &primary_identity
                .public_key()
                .public_key_bytes()
                .try_into()
                .unwrap(),
            &adv_secret_random,
        )
        .unwrap();

        // Verify the wrapped key bundle structure
        assert_eq!(wrapped_key_bundle.len(), 32 + 12 + (32 + 32 + 32) + 16); // salt + nonce + encrypted(96) + tag

        // Test ADV secret computation
        let adv_secret = PairUtils::compute_adv_secret(
            &ephemeral_shared_secret,
            &identity_shared_secret,
            &adv_secret_random,
        );

        // ADV secret should be 32 bytes
        assert_eq!(adv_secret.len(), 32);

        // ADV secret should be deterministic (same inputs produce same output)
        let adv_secret2 = PairUtils::compute_adv_secret(
            &ephemeral_shared_secret,
            &identity_shared_secret,
            &adv_secret_random,
        );
        assert_eq!(adv_secret, adv_secret2);
    }

    #[tokio::test]
    async fn test_pairing_reference_handling() {
        // Test that pairing references are handled correctly
        let test_ref = "3@2:test-pairing-reference:12345";

        // Convert to bytes and back (simulating the notification parsing)
        let ref_bytes = test_ref.as_bytes();
        let parsed_ref = String::from_utf8(ref_bytes.to_vec()).unwrap();

        assert_eq!(test_ref, parsed_ref);

        // Test that the bytes are preserved correctly
        assert_eq!(ref_bytes, parsed_ref.as_bytes());
    }

    #[tokio::test]
    async fn test_shared_secret_computation() {
        // Test that shared secret computation works with different key pairs
        let keypair1 = KeyPair::generate(&mut rng());
        let keypair2 = KeyPair::generate(&mut rng());

        // Compute shared secret from both perspectives
        let secret1 = PairUtils::compute_pairing_shared_secret(
            &keypair1.private_key,
            &keypair2.public_key.public_key_bytes().try_into().unwrap(),
        )
        .unwrap();

        let secret2 = PairUtils::compute_pairing_shared_secret(
            &keypair2.private_key,
            &keypair1.public_key.public_key_bytes().try_into().unwrap(),
        )
        .unwrap();

        // ECDH should be commutative - both sides should get the same secret
        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 32);
    }

    #[tokio::test]
    async fn test_pairing_code_format() {
        // Test that pairing codes are properly formatted
        for _ in 0..10 {
            let (_, _, code) = PairUtils::generate_companion_ephemeral_key().unwrap();

            // Raw code should be 8 characters (base32 encoded 5 bytes)
            assert_eq!(code.len(), 8, "Raw pairing code should be 8 characters");

            // Formatted code should be 9 characters: XXXX-XXXX
            let formatted = format!("{}-{}", &code[0..4], &code[4..8]);
            assert_eq!(
                formatted.len(),
                9,
                "Formatted pairing code should be 9 characters (XXXX-XXXX)"
            );
            assert_eq!(
                formatted.chars().nth(4),
                Some('-'),
                "Formatted pairing code should have dash at position 4"
            );

            // Should only contain valid base32 characters
            let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            for c in code.chars() {
                assert!(
                    valid_chars.contains(c),
                    "Invalid character '{}' in pairing code",
                    c
                );
            }
        }
    }

    #[tokio::test]
    async fn test_key_bundle_structure() {
        // Test that the key bundle has the correct structure
        let companion_identity = IdentityKeyPair::generate(&mut rng());
        let primary_identity = IdentityKeyPair::generate(&mut rng());

        let companion_ephemeral = KeyPair::generate(&mut rng());
        let primary_ephemeral = KeyPair::generate(&mut rng());

        let ephemeral_shared_secret = PairUtils::compute_pairing_shared_secret(
            &companion_ephemeral.private_key,
            &primary_ephemeral
                .public_key
                .public_key_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let adv_secret_random = {
            use rand::RngCore;
            let mut random = [0u8; 32];
            rand::rng().fill_bytes(&mut random);
            random
        };

        let wrapped_key_bundle = PairUtils::encrypt_key_bundle(
            &ephemeral_shared_secret,
            companion_identity
                .public_key()
                .public_key_bytes()
                .try_into()
                .unwrap(),
            &primary_identity
                .public_key()
                .public_key_bytes()
                .try_into()
                .unwrap(),
            &adv_secret_random,
        )
        .unwrap();

        // Key bundle structure: salt(32) + nonce(12) + encrypted_data
        assert!(
            wrapped_key_bundle.len() > 32 + 12,
            "Key bundle should contain salt, nonce, and encrypted data"
        );

        // Extract components
        let salt = &wrapped_key_bundle[0..32];
        let nonce = &wrapped_key_bundle[32..44];
        let encrypted_data = &wrapped_key_bundle[44..];

        // Salt and nonce should not be all zeros (with very high probability)
        assert!(
            !salt.iter().all(|&b| b == 0),
            "Salt should not be all zeros"
        );
        assert!(
            !nonce.iter().all(|&b| b == 0),
            "Nonce should not be all zeros"
        );

        // Encrypted data should exist
        assert!(
            !encrypted_data.is_empty(),
            "Encrypted data should not be empty"
        );
    }

    #[tokio::test]
    async fn test_adv_secret_determinism() {
        // Test that ADV secret computation is deterministic
        let ephemeral_secret = [1u8; 32];
        let identity_secret = [2u8; 32];
        let random_bytes = [3u8; 32];

        let adv_secret1 =
            PairUtils::compute_adv_secret(&ephemeral_secret, &identity_secret, &random_bytes);

        let adv_secret2 =
            PairUtils::compute_adv_secret(&ephemeral_secret, &identity_secret, &random_bytes);

        assert_eq!(
            adv_secret1, adv_secret2,
            "ADV secret should be deterministic"
        );

        // Different inputs should produce different results
        let different_random = [4u8; 32];
        let adv_secret3 =
            PairUtils::compute_adv_secret(&ephemeral_secret, &identity_secret, &different_random);

        assert_ne!(
            adv_secret1, adv_secret3,
            "Different inputs should produce different ADV secrets"
        );
    }

    #[tokio::test]
    async fn test_ephemeral_key_encryption_consistency() {
        // Test that the same pairing code always decrypts to the same key
        let (ephemeral_key, wrapped_key, pairing_code) =
            PairUtils::generate_companion_ephemeral_key().unwrap();

        let original_pubkey = ephemeral_key.public_key.public_key_bytes();

        // Decrypt multiple times with the same code
        for _ in 0..5 {
            let decrypted =
                PairUtils::decrypt_primary_ephemeral_pub(&pairing_code, &wrapped_key).unwrap();
            assert_eq!(
                decrypted, *original_pubkey,
                "Decryption should be consistent"
            );
        }
    }

    #[tokio::test]
    async fn test_wrapped_key_bundle_length() {
        // Test that wrapped key bundles have consistent lengths
        let companion_identity = IdentityKeyPair::generate(&mut rng());
        let primary_identity = IdentityKeyPair::generate(&mut rng());

        let companion_ephemeral = KeyPair::generate(&mut rng());
        let primary_ephemeral = KeyPair::generate(&mut rng());

        let ephemeral_shared_secret = PairUtils::compute_pairing_shared_secret(
            &companion_ephemeral.private_key,
            &primary_ephemeral
                .public_key
                .public_key_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let adv_secret_random = {
            use rand::RngCore;
            let mut random = [0u8; 32];
            rand::rng().fill_bytes(&mut random);
            random
        };

        // Generate multiple key bundles and check they have the same length
        let mut lengths = Vec::new();
        for _ in 0..5 {
            let wrapped_key_bundle = PairUtils::encrypt_key_bundle(
                &ephemeral_shared_secret,
                companion_identity
                    .public_key()
                    .public_key_bytes()
                    .try_into()
                    .unwrap(),
                &primary_identity
                    .public_key()
                    .public_key_bytes()
                    .try_into()
                    .unwrap(),
                &adv_secret_random,
            )
            .unwrap();
            lengths.push(wrapped_key_bundle.len());
        }

        // All lengths should be the same (deterministic encryption with same inputs)
        let first_length = lengths[0];
        for length in lengths {
            assert_eq!(
                length, first_length,
                "Key bundle lengths should be consistent"
            );
        }
    }
}
