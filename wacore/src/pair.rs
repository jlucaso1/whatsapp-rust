use crate::binary::node::{Node, NodeContent};
use crate::crypto::xed25519;
use crate::types::jid::{Jid, SERVER_JID};
use base64::Engine as _;
use base64::prelude::*;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
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
    pub identity_key: crate::crypto::key_pair::KeyPair,
    pub noise_key: crate::crypto::key_pair::KeyPair,
    pub adv_secret_key: [u8; 32],
}

/// Core pairing utilities that are platform-independent
pub struct PairUtils;

impl PairUtils {
    /// Constructs the full QR code string from the ref and device keys.
    pub fn make_qr_data(device_state: &DeviceState, ref_str: String) -> String {
        let noise_b64 = BASE64_STANDARD.encode(device_state.noise_key.public_key);
        let identity_b64 = BASE64_STANDARD.encode(device_state.identity_key.public_key);
        let adv_b64 = BASE64_STANDARD.encode(device_state.adv_secret_key);

        [ref_str, noise_b64, identity_b64, adv_b64].join(",")
    }

    /// Builds acknowledgment node for a pairing request
    pub fn build_ack_node(request_node: &Node) -> Option<Node> {
        if let (Some(to), Some(id)) = (request_node.attrs.get("from"), request_node.attrs.get("id"))
        {
            Some(Node {
                tag: "iq".into(),
                attrs: [
                    ("to".into(), to.clone()),
                    ("id".into(), id.clone()),
                    ("type".into(), "result".into()),
                ]
                .iter()
                .cloned()
                .collect(),
                content: None,
            })
        } else {
            None
        }
    }

    /// Builds pair error node
    pub fn build_pair_error_node(req_id: &str, code: u16, text: &str) -> Node {
        let error_node = Node {
            tag: "error".into(),
            attrs: [
                ("code".into(), code.to_string()),
                ("text".into(), text.to_string()),
            ]
            .into(),
            content: None,
        };
        Node {
            tag: "iq".into(),
            attrs: [
                ("to".into(), SERVER_JID.to_string()),
                ("type".into(), "error".into()),
                ("id".into(), req_id.to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![error_node])),
        }
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

        let mut mac = HmacSha256::new_from_slice(&device_state.adv_secret_key).unwrap();
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
            &device_state.identity_key.public_key,
        ]);

        let Ok(signature) = ed25519_dalek::Signature::from_slice(account_sig_bytes) else {
            return Err(PairCryptoError {
                code: 500,
                text: "internal-error",
                source: anyhow::anyhow!("Invalid account signature format"),
            });
        };

        if !xed25519::verify(
            account_sig_key_bytes.try_into().unwrap(),
            &msg_to_verify,
            &signature.to_bytes(),
        ) {
            return Err(PairCryptoError {
                code: 401,
                text: "signature-mismatch",
                source: anyhow::anyhow!("XEd25519 account signature mismatch"),
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
            &device_state.identity_key.public_key,
            account_sig_key_bytes,
        ]);
        let device_signature = device_state
            .identity_key
            .sign_message(&msg_to_sign)
            .to_vec();
        signed_identity.device_signature = Some(device_signature);

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
        let response_content = Node {
            tag: "pair-device-sign".into(),
            attrs: [].into(),
            content: Some(NodeContent::Nodes(vec![Node {
                tag: "device-identity".into(),
                attrs: [("key-index".into(), key_index.to_string())].into(),
                content: Some(NodeContent::Bytes(self_signed_identity_bytes)),
            }])),
        };
        Node {
            tag: "iq".into(),
            attrs: [
                ("to".into(), SERVER_JID.to_string()),
                ("id".into(), req_id.to_string()),
                ("type".into(), "result".into()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![response_content])),
        }
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
        master_ephemeral: &crate::crypto::key_pair::KeyPair,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // Perform the cryptographic exchange to create the shared secrets
        let adv_key = &device_state.adv_secret_key;
        let identity_key = &device_state.identity_key;

        let mut mac = HmacSha256::new_from_slice(adv_key).unwrap();
        mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
        mac.update(dut_identity_pub);
        mac.update(&master_ephemeral.public_key);
        let account_signature = mac.finalize().into_bytes();

        let secret = x25519_dalek::StaticSecret::from(master_ephemeral.private_key);
        let shared_secret = x25519_dalek::x25519(secret.to_bytes(), *dut_noise_pub);

        let mut final_message = Vec::new();
        final_message.extend_from_slice(&account_signature);
        final_message.extend_from_slice(&master_ephemeral.public_key);
        final_message.extend_from_slice(&identity_key.public_key);

        // Encrypt the final message
        let encryption_key = crate::crypto::hkdf::sha256(&shared_secret, None, b"WA-Ads-Key", 32)?;
        let encrypted = crate::crypto::gcm::encrypt(
            &encryption_key,
            &[0; 12],
            &final_message,
            pairing_ref.as_bytes(),
        )?;

        Ok(encrypted)
    }

    /// Builds pairing IQ for master device
    pub fn build_master_pair_iq(
        master_jid: &Jid,
        encrypted_message: Vec<u8>,
        req_id: String,
    ) -> Node {
        let response_content = Node {
            tag: "pair-device-sign".into(),
            attrs: [("jid".into(), master_jid.to_string())].into(),
            content: Some(NodeContent::Bytes(encrypted_message)),
        };
        Node {
            tag: "iq".into(),
            attrs: [
                ("to".into(), SERVER_JID.to_string()),
                ("type".into(), "set".into()),
                ("id".into(), req_id),
                ("xmlns".into(), "md".into()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![response_content])),
        }
    }

    /// Helper to concatenate multiple byte slices into a single Vec.
    fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
        slices.iter().flat_map(|s| s.iter().cloned()).collect()
    }
}
