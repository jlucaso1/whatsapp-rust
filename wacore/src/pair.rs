use crate::libsignal::crypto::Aes256Ctr32;
use crate::libsignal::protocol::{KeyPair, PublicKey};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base32;
use base64::Engine as _;
use base64::prelude::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use prost::Message;
use rand::TryRngCore;
use sha2::Sha256;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::Node;
use waproto::whatsapp as wa;
use waproto::whatsapp::AdvEncryptionType;

// Prefixes from whatsmeow/pair.go, crucial for signature verification
const ADV_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 0];
const ADV_PREFIX_DEVICE_SIGNATURE_GENERATE: &[u8] = &[6, 1];
const ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE: &[u8] = &[6, 5];
const ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION: &[u8] = &[6, 6];

// Aliases for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct PairCryptoError {
    pub code: u16,
    pub text: &'static str,
    pub source: anyhow::Error,
}

impl std::fmt::Display for PairCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pairing crypto failed with code {}: {} (source: {})",
            self.code, self.text, self.source
        )
    }
}

impl std::error::Error for PairCryptoError {}

/// Device state needed for pairing operations
pub struct DeviceState {
    pub identity_key: KeyPair,
    pub noise_key: KeyPair,
    pub adv_secret_key: [u8; 32],
}

/// Core pairing utilities that are platform-independent
pub struct PairUtils;

impl PairUtils {
    /// Constructs the full QR code string from the ref and device keys.
    pub fn make_qr_data(device_state: &DeviceState, ref_str: String) -> String {
        let noise_b64 =
            BASE64_STANDARD.encode(device_state.noise_key.public_key.public_key_bytes());
        let identity_b64 =
            BASE64_STANDARD.encode(device_state.identity_key.public_key.public_key_bytes());
        let adv_b64 = BASE64_STANDARD.encode(device_state.adv_secret_key);

        [ref_str, noise_b64, identity_b64, adv_b64].join(",")
    }

    /// Builds acknowledgment node for a pairing request
    pub fn build_ack_node(request_node: &Node) -> Option<Node> {
        if let (Some(to), Some(id)) = (request_node.attrs.get("from"), request_node.attrs.get("id"))
        {
            Some(
                NodeBuilder::new("iq")
                    .attrs([
                        ("to", to.clone()),
                        ("id", id.clone()),
                        ("type", "result".to_string()),
                    ])
                    .build(),
            )
        } else {
            None
        }
    }

    /// Builds pair error node
    pub fn build_pair_error_node(req_id: &str, code: u16, text: &str) -> Node {
        let error_node = NodeBuilder::new("error")
            .attrs([("code", code.to_string()), ("text", text.to_string())])
            .build();
        NodeBuilder::new("iq")
            .attrs([
                ("to", SERVER_JID.to_string()),
                ("type", "error".to_string()),
                ("id", req_id.to_string()),
            ])
            .children([error_node])
            .build()
    }

    /// Performs the cryptographic operations for pairing
    pub fn do_pair_crypto(
        device_state: &DeviceState,
        device_identity_bytes: &[u8],
    ) -> Result<(Vec<u8>, u32), PairCryptoError> {
        // 1. Unmarshal HMAC container and verify HMAC
        let hmac_container = wa::AdvSignedDeviceIdentityHmac::decode(device_identity_bytes)
            .map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;

        // Determine if this is a hosted account
        let is_hosted_account = hmac_container.account_type.is_some()
            && hmac_container.account_type() == AdvEncryptionType::Hosted;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&device_state.adv_secret_key).unwrap();
        // Get details and hmac as slices, handling potential None values
        let details_bytes = hmac_container
            .details
            .as_deref()
            .ok_or_else(|| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: anyhow::anyhow!("HMAC container missing details"),
            })?;
        let hmac_bytes = hmac_container
            .hmac
            .as_deref()
            .ok_or_else(|| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: anyhow::anyhow!("HMAC container missing hmac"),
            })?;

        if is_hosted_account {
            mac.update(ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE);
        }
        mac.update(details_bytes);
        if mac.verify_slice(hmac_bytes).is_err() {
            return Err(PairCryptoError {
                code: 401,
                text: "hmac-mismatch",
                source: anyhow::anyhow!("HMAC mismatch"),
            });
        }

        // 2. Unmarshal inner container and verify account signature
        let mut signed_identity =
            wa::AdvSignedDeviceIdentity::decode(details_bytes).map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;

        let account_sig_key_bytes = signed_identity.account_signature_key();
        let account_sig_bytes = signed_identity.account_signature();
        let inner_details_bytes = signed_identity.details().to_vec();

        let account_sig_prefix = if is_hosted_account {
            ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE
        } else {
            ADV_PREFIX_ACCOUNT_SIGNATURE
        };

        let msg_to_verify = Self::concat_bytes(&[
            account_sig_prefix,
            &inner_details_bytes,
            device_state.identity_key.public_key.public_key_bytes(),
        ]);

        let account_public_key = PublicKey::from_djb_public_key_bytes(account_sig_key_bytes)
            .map_err(|e| PairCryptoError {
                code: 401,
                text: "invalid-key",
                source: e.into(),
            })?;

        if !account_public_key.verify_signature(&msg_to_verify, account_sig_bytes) {
            return Err(PairCryptoError {
                code: 401,
                text: "signature-mismatch",
                source: anyhow::anyhow!("libsignal signature verification failed"),
            });
        }

        // 3. Generate our device signature
        let device_sig_prefix = if is_hosted_account {
            ADV_HOSTED_PREFIX_DEVICE_SIGNATURE_VERIFICATION
        } else {
            ADV_PREFIX_DEVICE_SIGNATURE_GENERATE
        };

        let msg_to_sign = Self::concat_bytes(&[
            device_sig_prefix,
            &inner_details_bytes,
            device_state.identity_key.public_key.public_key_bytes(),
            account_sig_key_bytes,
        ]);
        let device_signature = device_state
            .identity_key
            .private_key
            .calculate_signature(
                &msg_to_sign,
                &mut rand::rngs::OsRng::unwrap_err(rand_core::OsRng),
            )
            .map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;
        signed_identity.device_signature = Some(device_signature.to_vec());

        // 4. Unmarshal final details to get key_index
        let identity_details =
            wa::AdvDeviceIdentity::decode(&*inner_details_bytes).map_err(|e| PairCryptoError {
                code: 500,
                text: "internal-error",
                source: e.into(),
            })?;
        let key_index = identity_details.key_index();

        // 5. Marshal the modified signed_identity to send back
        let self_signed_identity_bytes = signed_identity.encode_to_vec();

        Ok((self_signed_identity_bytes, key_index))
    }

    /// Builds the pair-device-sign response node
    pub fn build_pair_success_response(
        req_id: &str,
        self_signed_identity_bytes: Vec<u8>,
        key_index: u32,
    ) -> Node {
        let response_content = NodeBuilder::new("pair-device-sign")
            .children([NodeBuilder::new("device-identity")
                .attr("key-index", key_index.to_string())
                .bytes(self_signed_identity_bytes)
                .build()])
            .build();
        NodeBuilder::new("iq")
            .attrs([
                ("to", SERVER_JID.to_string()),
                ("id", req_id.to_string()),
                ("type", "result".to_string()),
            ])
            .children([response_content])
            .build()
    }

    /// Parses QR code and extracts crypto keys for pairing
    pub fn parse_qr_code(qr_code: &str) -> Result<(String, [u8; 32], [u8; 32]), anyhow::Error> {
        let parts: Vec<&str> = qr_code.split(',').collect();
        if parts.len() != 4 {
            return Err(anyhow::anyhow!("Invalid QR code format"));
        }
        let pairing_ref = parts[0].to_string();
        let dut_noise_pub_b64 = parts[1];
        let dut_identity_pub_b64 = parts[2];
        // The ADV secret is not used by the phone side.

        let dut_noise_pub_bytes = BASE64_STANDARD
            .decode(dut_noise_pub_b64)
            .map_err(|e| anyhow::anyhow!(e))?;
        let dut_identity_pub_bytes = BASE64_STANDARD
            .decode(dut_identity_pub_b64)
            .map_err(|e| anyhow::anyhow!(e))?;

        let dut_noise_pub: [u8; 32] = dut_noise_pub_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid noise public key length"))?;
        let dut_identity_pub: [u8; 32] = dut_identity_pub_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid identity public key length"))?;

        Ok((pairing_ref, dut_noise_pub, dut_identity_pub))
    }

    /// Prepares pairing message for master device (phone simulation)
    pub fn prepare_master_pairing_message(
        device_state: &DeviceState,
        pairing_ref: &str,
        dut_noise_pub: &[u8; 32],
        dut_identity_pub: &[u8; 32],
        master_ephemeral: KeyPair,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // Perform the cryptographic exchange to create the shared secrets
        let adv_key = &device_state.adv_secret_key;
        let identity_key = &device_state.identity_key;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(adv_key).unwrap();
        mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
        mac.update(dut_identity_pub);
        mac.update(master_ephemeral.public_key.public_key_bytes());
        let account_signature = mac.finalize().into_bytes();

        let their_public_key = PublicKey::from_djb_public_key_bytes(dut_noise_pub)?;
        let shared_secret = master_ephemeral
            .private_key
            .calculate_agreement(&their_public_key)?;

        let mut final_message = Vec::new();
        final_message.extend_from_slice(&account_signature);
        final_message.extend_from_slice(master_ephemeral.public_key.public_key_bytes());
        final_message.extend_from_slice(identity_key.public_key.public_key_bytes());

        // Encrypt the final message
        let encryption_key = {
            let hk = Hkdf::<Sha256>::new(None, &shared_secret);
            let mut result = vec![0u8; 32];
            hk.expand(b"WA-Ads-Key", &mut result)
                .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
            result
        };
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|_| anyhow::anyhow!("Invalid key size for AES-GCM"))?;
        let nonce = aes_gcm::Nonce::from_slice(&[0; 12]);
        let payload = Payload {
            msg: &final_message,
            aad: pairing_ref.as_bytes(),
        };
        let encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

        Ok(encrypted)
    }

    /// Builds pairing IQ for master device
    pub fn build_master_pair_iq(
        master_jid: &Jid,
        encrypted_message: Vec<u8>,
        req_id: String,
    ) -> Node {
        let response_content = NodeBuilder::new("pair-device-sign")
            .attr("jid", master_jid.to_string())
            .bytes(encrypted_message)
            .build();
        NodeBuilder::new("iq")
            .attrs([
                ("to", SERVER_JID.to_string()),
                ("type", "set".to_string()),
                ("id", req_id),
                ("xmlns", "md".to_string()),
            ])
            .children([response_content])
            .build()
    }

    /// Helper to concatenate multiple byte slices into a single Vec.
    fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
        slices.iter().flat_map(|s| s.iter().cloned()).collect()
    }

    /// Generates a companion ephemeral key pair and encrypts it with a pairing code
    pub fn generate_companion_ephemeral_key() -> Result<(KeyPair, Vec<u8>, String), anyhow::Error> {
        let ephemeral_key_pair =
            KeyPair::generate(&mut rand::rngs::OsRng::unwrap_err(rand_core::OsRng));

        // Generate random salt and IV
        let salt = rand::random::<[u8; 32]>();
        let iv = rand::random::<[u8; 16]>();
        let linking_code_bytes = rand::random::<[u8; 5]>();

        // Encode linking code to base32
        let linking_code = base32::encode(
            base32::Alphabet::RFC4648 { padding: false },
            &linking_code_bytes,
        );

        // Derive encryption key from linking code using PBKDF2
        let mut link_code_key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(linking_code.as_bytes(), &salt, 2 << 16, &mut link_code_key)
            .map_err(|_| anyhow::anyhow!("PBKDF2 key derivation failed"))?;

        // Encrypt the ephemeral public key
        let pubkey_bytes = ephemeral_key_pair.public_key.public_key_bytes();
        let mut encrypted_pubkey = [0u8; 32];
        encrypted_pubkey.copy_from_slice(pubkey_bytes);

        let mut cipher_ctr = Aes256Ctr32::from_key(&link_code_key, &iv[0..12], 0)?;
        cipher_ctr.process(&mut encrypted_pubkey);

        // Construct the wrapped key bundle: salt(32) + iv(16) + encrypted_pubkey(32)
        let mut ephemeral_key = Vec::with_capacity(80);
        ephemeral_key.extend_from_slice(&salt);
        ephemeral_key.extend_from_slice(&iv);
        ephemeral_key.extend_from_slice(&encrypted_pubkey);

        Ok((ephemeral_key_pair, ephemeral_key, linking_code))
    }

    /// Decrypts the primary device's ephemeral public key using the pairing code
    pub fn decrypt_primary_ephemeral_pub(
        linking_code: &str,
        wrapped_primary_ephemeral_pub: &[u8],
    ) -> Result<[u8; 32], anyhow::Error> {
        if wrapped_primary_ephemeral_pub.len() != 80 {
            return Err(anyhow::anyhow!(
                "Invalid wrapped primary ephemeral pub length"
            ));
        }

        let salt = &wrapped_primary_ephemeral_pub[0..32];
        let iv = &wrapped_primary_ephemeral_pub[32..48];
        let encrypted_pubkey = &wrapped_primary_ephemeral_pub[48..80];

        // Derive decryption key from linking code using PBKDF2
        let mut link_code_key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(linking_code.as_bytes(), salt, 2 << 16, &mut link_code_key)
            .map_err(|_| anyhow::anyhow!("PBKDF2 key derivation failed"))?;

        // Decrypt the primary ephemeral public key
        let mut decrypted_pubkey = encrypted_pubkey.to_vec();

        let mut cipher_ctr = Aes256Ctr32::from_key(&link_code_key, &iv[0..12], 0)?;
        cipher_ctr.process(&mut decrypted_pubkey);

        let primary_ephemeral_pub: [u8; 32] = decrypted_pubkey
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid decrypted public key length"))?;

        Ok(primary_ephemeral_pub)
    }

    /// Computes the shared secret for pairing code authentication
    pub fn compute_pairing_shared_secret(
        companion_ephemeral_priv: &crate::libsignal::protocol::PrivateKey,
        primary_ephemeral_pub: &[u8; 32],
    ) -> Result<[u8; 32], anyhow::Error> {
        let primary_public_key = PublicKey::from_djb_public_key_bytes(primary_ephemeral_pub)?;
        let shared_secret_box =
            companion_ephemeral_priv.calculate_agreement(&primary_public_key)?;
        let shared_secret: [u8; 32] = shared_secret_box
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid shared secret length"))?;
        Ok(shared_secret)
    }

    /// Encrypts the key bundle containing identity keys and randomness
    pub fn encrypt_key_bundle(
        shared_secret: &[u8; 32],
        companion_identity_pub: &[u8; 32],
        primary_identity_pub: &[u8; 32],
        adv_secret_random: &[u8; 32],
    ) -> Result<Vec<u8>, anyhow::Error> {
        // Create salt and nonce for key bundle encryption
        let key_bundle_salt = rand::random::<[u8; 32]>();
        let key_bundle_nonce = rand::random::<[u8; 12]>();

        // Derive encryption key from shared secret
        let key_bundle_encryption_key = {
            let hk = Hkdf::<Sha256>::new(None, shared_secret);
            let mut result = [0u8; 32];
            hk.expand(b"link_code_pairing_key_bundle_encryption_key", &mut result)
                .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
            result
        };

        // Create plaintext key bundle: companion_identity_pub + primary_identity_pub + adv_secret_random
        let mut plaintext_key_bundle = Vec::with_capacity(96);
        plaintext_key_bundle.extend_from_slice(companion_identity_pub);
        plaintext_key_bundle.extend_from_slice(primary_identity_pub);
        plaintext_key_bundle.extend_from_slice(adv_secret_random);

        // Encrypt the key bundle
        let cipher = Aes256Gcm::new_from_slice(&key_bundle_encryption_key)
            .map_err(|_| anyhow::anyhow!("Invalid key size for AES-GCM"))?;
        let nonce = aes_gcm::Nonce::from_slice(&key_bundle_nonce);
        let payload = Payload {
            msg: &plaintext_key_bundle,
            aad: b"",
        };
        let encrypted_key_bundle = cipher
            .encrypt(nonce, payload)
            .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

        // Construct wrapped key bundle: salt(32) + nonce(12) + encrypted_bundle
        let mut wrapped_key_bundle = Vec::with_capacity(32 + 12 + encrypted_key_bundle.len());
        wrapped_key_bundle.extend_from_slice(&key_bundle_salt);
        wrapped_key_bundle.extend_from_slice(&key_bundle_nonce);
        wrapped_key_bundle.extend_from_slice(&encrypted_key_bundle);

        Ok(wrapped_key_bundle)
    }

    /// Computes the ADV secret key for pairing code authentication
    pub fn compute_adv_secret(
        ephemeral_shared_secret: &[u8; 32],
        identity_shared_secret: &[u8; 32],
        adv_secret_random: &[u8; 32],
    ) -> [u8; 32] {
        let mut adv_secret_input = Vec::with_capacity(96);
        adv_secret_input.extend_from_slice(ephemeral_shared_secret);
        adv_secret_input.extend_from_slice(identity_shared_secret);
        adv_secret_input.extend_from_slice(adv_secret_random);

        let hk = Hkdf::<Sha256>::new(None, &adv_secret_input);
        let mut adv_secret = [0u8; 32];
        hk.expand(b"adv_secret", &mut adv_secret)
            .expect("HKDF expand should not fail for adv_secret");
        adv_secret
    }
}
