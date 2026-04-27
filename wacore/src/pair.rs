use crate::companion_reg::CompanionWebClientType;
use crate::libsignal::crypto::aes_256_gcm_encrypt;
use crate::libsignal::protocol::{KeyPair, PublicKey};
use base64::Engine as _;
use base64::prelude::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;

use sha2::Sha256;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, SERVER_JID};
use wacore_binary::{Node, NodeRef};
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
    /// `<ref>,<noise>,<identity>,<adv>,<client_type>` per WA Web
    /// (`WAWebLinkDeviceQrcode.react`); 4-field form rejected since
    /// tulir/whatsmeow#1110.
    pub fn make_qr_data(
        device_state: &DeviceState,
        ref_str: &str,
        client_type: CompanionWebClientType,
    ) -> String {
        let noise_b64 =
            BASE64_STANDARD.encode(device_state.noise_key.public_key.public_key_bytes());
        let identity_b64 =
            BASE64_STANDARD.encode(device_state.identity_key.public_key.public_key_bytes());
        let adv_b64 = BASE64_STANDARD.encode(device_state.adv_secret_key);

        format!("{ref_str},{noise_b64},{identity_b64},{adv_b64},{client_type}")
    }

    /// Builds acknowledgment node for a pairing request
    pub fn build_ack_node(request_node: &Node) -> Option<Node> {
        if let (Some(to), Some(id)) = (request_node.attrs.get("from"), request_node.attrs.get("id"))
        {
            Some(
                NodeBuilder::new("iq")
                    .attrs([
                        ("to", to.to_string()),
                        ("id", id.to_string()),
                        ("type", "result".to_string()),
                    ])
                    .build(),
            )
        } else {
            None
        }
    }

    /// Builds acknowledgment node for a pairing request from a NodeRef.
    pub fn build_ack_node_ref(request_node: &NodeRef<'_>) -> Option<Node> {
        let to = request_node.get_attr("from").map(|v| v.as_str())?;
        let id = request_node.get_attr("id").map(|v| v.as_str())?;
        Some(
            NodeBuilder::new("iq")
                .attrs([
                    ("to", to.to_string()),
                    ("id", id.to_string()),
                    ("type", "result".to_string()),
                ])
                .build(),
        )
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

        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&device_state.adv_secret_key)
            .map_err(|e| PairCryptoError {
            code: 500,
            text: "internal-error",
            source: e.into(),
        })?;
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
        // adv_secret is shared with the primary out-of-band (QR string or
        // pair-code DH). HMAC mismatch means the container is forged:
        // account_signature alone is not a backstop, since its key comes
        // from the same untrusted blob.
        mac.verify_slice(hmac_bytes).map_err(|_| PairCryptoError {
            code: 401,
            text: "hmac-mismatch",
            source: anyhow::anyhow!("ADV signed-device-identity HMAC verification failed"),
        })?;

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
            .calculate_signature(&msg_to_sign, &mut rand::make_rng::<rand::rngs::StdRng>())
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
                .attr("key-index", key_index)
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

    /// Permissive: accepts legacy 4-field, current 5-field, optional
    /// `https://wa.me/settings/linked_devices#` prefix, trailing FAQ URL,
    /// or any combination (used by e2e replay; WA Web only emits one shape
    /// at a time).
    pub fn parse_qr_code(qr_code: &str) -> Result<(String, [u8; 32], [u8; 32]), anyhow::Error> {
        let body = qr_code
            .strip_prefix(crate::companion_reg::NATIVE_CAMERA_DEEP_LINK_PREFIX)
            .unwrap_or(qr_code);
        let parts: Vec<&str> = body.split(',').collect();
        if parts.len() < 4 {
            return Err(anyhow::anyhow!(
                "Invalid QR code format: expected at least 4 comma-separated fields, got {}",
                parts.len()
            ));
        }
        let pairing_ref = parts[0].to_string();
        let dut_noise_pub_b64 = parts[1];
        let dut_identity_pub_b64 = parts[2];
        if pairing_ref.is_empty()
            || dut_noise_pub_b64.is_empty()
            || dut_identity_pub_b64.is_empty()
            || parts[3].is_empty()
            || parts.iter().skip(4).any(|p| p.is_empty())
        {
            return Err(anyhow::anyhow!(
                "Invalid QR code format: all comma-separated fields must be non-empty"
            ));
        }
        let dut_noise_pub_bytes = BASE64_STANDARD
            .decode(dut_noise_pub_b64)
            .map_err(|e| anyhow::anyhow!("Invalid QR noise public key base64: {e}"))?;
        let dut_identity_pub_bytes = BASE64_STANDARD
            .decode(dut_identity_pub_b64)
            .map_err(|e| anyhow::anyhow!("Invalid QR identity public key base64: {e}"))?;

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

        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(adv_key)
            .map_err(|e| anyhow::anyhow!("Failed to init HMAC for master pairing: {e}"))?;
        mac.update(ADV_PREFIX_ACCOUNT_SIGNATURE);
        mac.update(dut_identity_pub);
        mac.update(master_ephemeral.public_key.public_key_bytes());
        let account_signature = mac.finalize().into_bytes();

        let their_public_key = PublicKey::from_djb_public_key_bytes(dut_noise_pub)?;
        let shared_secret = master_ephemeral
            .private_key
            .calculate_agreement(&their_public_key)?;

        let mut final_message = Vec::with_capacity(64 + 32 + 32);
        final_message.extend_from_slice(&account_signature);
        final_message.extend_from_slice(master_ephemeral.public_key.public_key_bytes());
        final_message.extend_from_slice(identity_key.public_key.public_key_bytes());

        // Encrypt the final message
        let mut encryption_key = [0u8; 32];
        Hkdf::<Sha256>::new(None, &shared_secret)
            .expand(b"WA-Ads-Key", &mut encryption_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        let nonce = [0u8; 12];
        let mut encrypted = Vec::with_capacity(final_message.len() + 16);
        aes_256_gcm_encrypt(
            &encryption_key,
            &nonce,
            pairing_ref.as_bytes(),
            &final_message,
            &mut encrypted,
        )
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

        Ok(encrypted)
    }

    /// Builds pairing IQ for master device
    pub fn build_master_pair_iq(
        master_jid: &Jid,
        encrypted_message: Vec<u8>,
        req_id: String,
    ) -> Node {
        let response_content = NodeBuilder::new("pair-device-sign")
            .attr("jid", master_jid)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    fn dummy_device_state() -> DeviceState {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let mut adv = [0u8; 32];
        rng.fill(&mut adv);
        DeviceState {
            identity_key: KeyPair::generate(&mut rng),
            noise_key: KeyPair::generate(&mut rng),
            adv_secret_key: adv,
        }
    }

    #[test]
    fn make_qr_data_has_five_fields_with_client_type_suffix() {
        let state = dummy_device_state();
        let qr = PairUtils::make_qr_data(&state, "the-ref", CompanionWebClientType::Chrome);
        let parts: Vec<&str> = qr.split(',').collect();
        assert_eq!(parts.len(), 5, "expected 5 fields, got {qr:?}");
        assert_eq!(parts[0], "the-ref");
        assert_eq!(parts[4], "1", "Chrome wire value must be \"1\"");
    }

    #[test]
    fn make_qr_data_renders_each_client_type_wire_byte() {
        let state = dummy_device_state();
        for (ct, wire) in [
            (CompanionWebClientType::Chrome, "1"),
            (CompanionWebClientType::Edge, "2"),
            (CompanionWebClientType::Firefox, "3"),
            (CompanionWebClientType::Ie, "4"),
            (CompanionWebClientType::Opera, "5"),
            (CompanionWebClientType::Safari, "6"),
            (CompanionWebClientType::Electron, "7"),
            (CompanionWebClientType::Uwp, "8"),
            (CompanionWebClientType::OtherWebClient, "9"),
            (CompanionWebClientType::AndroidTablet, "d"),
            (CompanionWebClientType::AndroidPhone, "e"),
            (CompanionWebClientType::AndroidAmbiguous, "f"),
        ] {
            let qr = PairUtils::make_qr_data(&state, "r", ct);
            assert_eq!(qr.rsplit(',').next(), Some(wire), "{ct:?}");
        }
    }

    #[test]
    fn parse_qr_code_accepts_new_five_field_format() {
        let state = dummy_device_state();
        let qr = PairUtils::make_qr_data(&state, "the-ref", CompanionWebClientType::OtherWebClient);
        let (pairing_ref, noise, identity) = PairUtils::parse_qr_code(&qr).unwrap();
        assert_eq!(pairing_ref, "the-ref");
        assert_eq!(noise, *state.noise_key.public_key.public_key_bytes());
        assert_eq!(identity, *state.identity_key.public_key.public_key_bytes());
    }

    #[test]
    fn parse_qr_code_accepts_legacy_four_field_format() {
        let state = dummy_device_state();
        let legacy = [
            "ref".to_string(),
            BASE64_STANDARD.encode(state.noise_key.public_key.public_key_bytes()),
            BASE64_STANDARD.encode(state.identity_key.public_key.public_key_bytes()),
            BASE64_STANDARD.encode(state.adv_secret_key),
        ]
        .join(",");
        let (pairing_ref, noise, identity) = PairUtils::parse_qr_code(&legacy).unwrap();
        assert_eq!(pairing_ref, "ref");
        assert_eq!(noise, *state.noise_key.public_key.public_key_bytes());
        assert_eq!(identity, *state.identity_key.public_key.public_key_bytes());
    }

    #[test]
    fn parse_qr_code_accepts_native_camera_prefix() {
        let state = dummy_device_state();
        let inner = PairUtils::make_qr_data(&state, "r", CompanionWebClientType::Chrome);
        let prefixed = format!("https://wa.me/settings/linked_devices#{inner}");
        let (pairing_ref, _, _) = PairUtils::parse_qr_code(&prefixed).unwrap();
        assert_eq!(pairing_ref, "r");
    }

    #[test]
    fn parse_qr_code_accepts_faq_url_suffix() {
        let state = dummy_device_state();
        let inner = PairUtils::make_qr_data(&state, "r", CompanionWebClientType::Chrome);
        let suffixed = format!("{inner},https://faq.whatsapp.com/r/ld");
        let (pairing_ref, _, _) = PairUtils::parse_qr_code(&suffixed).unwrap();
        assert_eq!(pairing_ref, "r");
    }

    #[test]
    fn parse_qr_code_rejects_too_few_fields() {
        let err = PairUtils::parse_qr_code("a,b,c").unwrap_err();
        assert!(
            err.to_string().contains("at least 4"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_qr_code_rejects_empty_fields() {
        let err = PairUtils::parse_qr_code(",,,,").unwrap_err();
        assert!(
            err.to_string().contains("non-empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_qr_code_rejects_empty_trailing_client_type() {
        let state = dummy_device_state();
        let noise = BASE64_STANDARD.encode(state.noise_key.public_key.public_key_bytes());
        let identity = BASE64_STANDARD.encode(state.identity_key.public_key.public_key_bytes());
        let adv = BASE64_STANDARD.encode(state.adv_secret_key);
        let qr = format!("ref,{noise},{identity},{adv},");
        let err = PairUtils::parse_qr_code(&qr).unwrap_err();
        assert!(
            err.to_string().contains("non-empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_qr_code_rejects_malformed_base64() {
        let err = PairUtils::parse_qr_code("ref,!!notb64!!,!!notb64!!,advsecret").unwrap_err();
        assert!(
            err.to_string().contains("base64"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_qr_code_rejects_wrong_key_length() {
        let state = dummy_device_state();
        let short_noise = BASE64_STANDARD.encode([0u8; 16]);
        let identity = BASE64_STANDARD.encode(state.identity_key.public_key.public_key_bytes());
        let adv = BASE64_STANDARD.encode(state.adv_secret_key);
        let qr = format!("ref,{short_noise},{identity},{adv}");
        let err = PairUtils::parse_qr_code(&qr).unwrap_err();
        assert!(
            err.to_string().contains("length"),
            "unexpected error: {err}"
        );
    }

    /// E2E: DeviceProps → auto-derive → QR wire id matches WA Web.
    #[test]
    fn auto_derive_from_device_props_round_trip() {
        use crate::companion_reg::companion_web_client_type_for_props;
        use waproto::whatsapp as wa;

        let cases = [
            (wa::device_props::PlatformType::Chrome, "1"),
            (wa::device_props::PlatformType::Firefox, "3"),
            (wa::device_props::PlatformType::Safari, "6"),
            (wa::device_props::PlatformType::Edge, "2"),
            (wa::device_props::PlatformType::Desktop, "7"),
            (wa::device_props::PlatformType::Uwp, "8"),
            // Android* maps to Chrome ('1') — what real WA Web on
            // Chrome-Android emits and what the server accepts.
            (wa::device_props::PlatformType::AndroidPhone, "1"),
            (wa::device_props::PlatformType::AndroidTablet, "1"),
            (wa::device_props::PlatformType::AndroidAmbiguous, "1"),
            (wa::device_props::PlatformType::IosPhone, "9"),
            (wa::device_props::PlatformType::Vr, "9"),
            (wa::device_props::PlatformType::Unknown, "9"),
        ];
        let state = dummy_device_state();
        for (pt, expected_wire) in cases {
            let props = wa::DeviceProps {
                platform_type: Some(pt as i32),
                ..Default::default()
            };
            let ct = companion_web_client_type_for_props(&props);
            let qr = PairUtils::make_qr_data(&state, "ref", ct);
            let trailing = qr.rsplit(',').next().unwrap();
            assert_eq!(trailing, expected_wire, "{pt:?}");
        }
    }

    /// Bare `DeviceProps` produces 5-field QR with trailing "9" (catch-all).
    #[test]
    fn auto_derive_default_device_props_yields_other_web_client_nine() {
        use crate::companion_reg::companion_web_client_type_for_props;
        use waproto::whatsapp as wa;

        let state = dummy_device_state();
        let ct = companion_web_client_type_for_props(&wa::DeviceProps::default());
        let qr = PairUtils::make_qr_data(&state, "ref", ct);
        let parts: Vec<&str> = qr.split(',').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[4], "9");
    }

    /// `make_qr_data` output must always round-trip through `parse_qr_code`.
    #[test]
    fn round_trip_make_then_parse_for_every_client_type() {
        let state = dummy_device_state();
        for ct in [
            CompanionWebClientType::Chrome,
            CompanionWebClientType::Edge,
            CompanionWebClientType::Firefox,
            CompanionWebClientType::Ie,
            CompanionWebClientType::Opera,
            CompanionWebClientType::Safari,
            CompanionWebClientType::Electron,
            CompanionWebClientType::Uwp,
            CompanionWebClientType::OtherWebClient,
            CompanionWebClientType::AndroidTablet,
            CompanionWebClientType::AndroidPhone,
            CompanionWebClientType::AndroidAmbiguous,
        ] {
            let qr = PairUtils::make_qr_data(&state, "the-ref", ct);
            let (pairing_ref, noise, identity) = PairUtils::parse_qr_code(&qr)
                .unwrap_or_else(|e| panic!("{ct:?} round-trip failed: {e}"));
            assert_eq!(pairing_ref, "the-ref", "{ct:?}");
            assert_eq!(noise, *state.noise_key.public_key.public_key_bytes());
            assert_eq!(identity, *state.identity_key.public_key.public_key_bytes());
        }
    }

    /// Synthesize a signed pair-success payload whose HMAC is keyed by
    /// `adv_secret_for_hmac`. Mirrors the verifier's hosted/E2EE branching
    /// for both the account signature and the outer HMAC.
    fn build_pair_success_payload(
        state: &DeviceState,
        adv_secret_for_hmac: &[u8; 32],
        is_hosted: bool,
    ) -> Vec<u8> {
        use prost::Message;
        use waproto::whatsapp as wa;

        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let account_kp = KeyPair::generate(&mut rng);
        let account_type_value = if is_hosted { 1 } else { 0 };
        let inner = wa::AdvDeviceIdentity {
            raw_id: Some(1),
            timestamp: Some(0),
            key_index: Some(0),
            account_type: Some(account_type_value),
            device_type: Some(account_type_value),
        }
        .encode_to_vec();
        let account_sig_prefix: &[u8] = if is_hosted {
            ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE
        } else {
            ADV_PREFIX_ACCOUNT_SIGNATURE
        };
        let mut to_sign = Vec::new();
        to_sign.extend_from_slice(account_sig_prefix);
        to_sign.extend_from_slice(&inner);
        to_sign.extend_from_slice(state.identity_key.public_key.public_key_bytes());
        let sig = account_kp
            .private_key
            .calculate_signature(&to_sign, &mut rng)
            .unwrap();
        let signed = wa::AdvSignedDeviceIdentity {
            details: Some(inner),
            account_signature_key: Some(account_kp.public_key.public_key_bytes().to_vec()),
            account_signature: Some(sig.to_vec()),
            device_signature: None,
        }
        .encode_to_vec();
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(adv_secret_for_hmac).unwrap();
        if is_hosted {
            mac.update(ADV_HOSTED_PREFIX_ACCOUNT_SIGNATURE);
        }
        mac.update(&signed);
        let hmac_bytes = mac.finalize().into_bytes().to_vec();
        wa::AdvSignedDeviceIdentityHmac {
            details: Some(signed),
            hmac: Some(hmac_bytes),
            account_type: Some(account_type_value),
        }
        .encode_to_vec()
    }

    #[test]
    fn do_pair_crypto_accepts_matching_hmac() {
        let state = dummy_device_state();
        let payload = build_pair_success_payload(&state, &state.adv_secret_key, false);
        PairUtils::do_pair_crypto(&state, &payload).expect("matching HMAC must verify");
    }

    #[test]
    fn do_pair_crypto_rejects_mismatched_hmac() {
        let state = dummy_device_state();
        // Different secret than the companion holds: tampered/forged pair-success.
        let wrong_secret = [0xCDu8; 32];
        let payload = build_pair_success_payload(&state, &wrong_secret, false);
        let err = PairUtils::do_pair_crypto(&state, &payload)
            .expect_err("mismatched HMAC must abort pairing");
        assert_eq!(err.code, 401, "expected 401 unauthorized, got {}", err.code);
        assert_eq!(err.text, "hmac-mismatch");
    }

    #[test]
    fn do_pair_crypto_accepts_matching_hmac_for_hosted_account() {
        let state = dummy_device_state();
        let payload = build_pair_success_payload(&state, &state.adv_secret_key, true);
        PairUtils::do_pair_crypto(&state, &payload)
            .expect("hosted-account HMAC with matching secret must verify");
    }

    #[test]
    fn do_pair_crypto_rejects_mismatched_hmac_for_hosted_account() {
        let state = dummy_device_state();
        let wrong_secret = [0xCDu8; 32];
        let payload = build_pair_success_payload(&state, &wrong_secret, true);
        let err = PairUtils::do_pair_crypto(&state, &payload)
            .expect_err("hosted-account HMAC with wrong secret must abort pairing");
        assert_eq!(err.code, 401, "expected 401 unauthorized, got {}", err.code);
        assert_eq!(err.text, "hmac-mismatch");
    }

    /// QR trailing field is the wire byte of `companion_platform_id`.
    #[test]
    fn qr_trailing_field_matches_companion_web_client_type_wire_byte() {
        let state = dummy_device_state();
        for ct in [
            CompanionWebClientType::Chrome,
            CompanionWebClientType::OtherWebClient,
            CompanionWebClientType::Uwp,
            CompanionWebClientType::AndroidPhone,
        ] {
            let qr = PairUtils::make_qr_data(&state, "r", ct);
            let trailing = qr.rsplit(',').next().unwrap();
            assert_eq!(trailing, &(ct.wire_byte() as char).to_string());
        }
    }
}
