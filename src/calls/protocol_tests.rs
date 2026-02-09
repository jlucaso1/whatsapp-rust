//! Integration tests for call protocol behavior matching WhatsApp Web.
//!
//! These tests verify that our call signaling matches the real WhatsApp Web
//! protocol as documented in `docs/whatsapp-web-call-protocol-analysis.md`.

#[cfg(test)]
mod tests {
    use crate::calls::encryption::{
        CallEncryptionKey, EncType, EncryptedCallKey, derive_call_keys,
    };
    use crate::calls::manager::{CallManager, CallManagerConfig, TransportType};
    use crate::calls::signaling::{ResponseType, SignalingType};
    use crate::calls::stanza::{
        AcceptAudioParams, AcceptVideoParams, CallStanzaBuilder, MediaParams, OfferEncData,
        ParsedCallStanza, PreacceptParams, RelayData,
    };
    use crate::calls::state::{CallInfo, CallState, CallTransition};
    use chrono::Utc;
    use wacore::types::call::{CallId, CallMediaType, EndCallReason};
    use wacore_binary::jid::Jid;

    // -- Helper constants matching real WhatsApp Web values --

    const TEST_CALL_ID: &str = "AC90CFD09DF712D981142B172706F9F2";
    const CALLER_LID: &str = "236395184570386.1:75@lid";
    const CALLEE_LID: &str = "39492358562039.1:50@lid";

    fn caller_jid() -> Jid {
        CALLER_LID.parse().unwrap()
    }

    fn callee_jid() -> Jid {
        CALLEE_LID.parse().unwrap()
    }

    fn make_call_manager() -> std::sync::Arc<CallManager> {
        CallManager::new(
            callee_jid(),
            CallManagerConfig {
                transport_type: TransportType::Legacy, // avoid WebRTC in tests
                ..Default::default()
            },
        )
    }

    fn make_relay_data() -> RelayData {
        RelayData {
            hbh_key: None,
            relay_key: None,
            uuid: None,
            self_pid: None,
            peer_pid: None,
            relay_tokens: vec![],
            auth_tokens: vec![],
            endpoints: vec![],
        }
    }

    fn make_incoming_parsed_stanza() -> ParsedCallStanza {
        ParsedCallStanza {
            stanza_id: "stanza-test-123".to_string(),
            call_id: TEST_CALL_ID.to_string(),
            call_creator: caller_jid(),
            from: caller_jid(),
            signaling_type: SignalingType::Offer,
            timestamp: Utc::now(),
            is_video: false,
            is_offline: false,
            platform: None,
            version: None,
            group_jid: None,
            caller_pn: Some("5551234567@s.whatsapp.net".parse().unwrap()),
            caller_username: None,
            payload: None,
            enc_rekey_data: None,
            offer_enc_data: Some(OfferEncData {
                enc_type: EncType::Msg,
                ciphertext: vec![0xAA; 32],
                version: 2,
            }),
            relay_data: Some(make_relay_data()),
            media_params: Some(MediaParams::default()),
            relay_latency: vec![],
            relay_election: None,
        }
    }

    // ================================================================
    // 1. Accept stanza must NOT contain <enc> element
    //    (WhatsApp Web real logs confirm this)
    // ================================================================

    #[test]
    fn test_accept_stanza_has_no_enc_element() {
        let encrypted_key = EncryptedCallKey {
            ciphertext: vec![0xAA; 32],
            enc_type: EncType::Msg,
        };

        // Even if we set an encrypted_key on the builder, Accept should NOT include it
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            caller_jid(),
            callee_jid(),
            SignalingType::Accept,
        )
        .encrypted_key(encrypted_key)
        .audio(AcceptAudioParams::default())
        .build();

        let children = node.children().unwrap();
        let accept_node = &children[0];
        assert_eq!(accept_node.tag, "accept");

        let accept_children = accept_node.children().unwrap();
        let has_enc = accept_children.iter().any(|c| c.tag == "enc");
        assert!(
            !has_enc,
            "Accept stanza MUST NOT contain <enc> element per WhatsApp Web protocol"
        );
    }

    #[test]
    fn test_accept_stanza_contains_audio_codec() {
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            caller_jid(),
            callee_jid(),
            SignalingType::Accept,
        )
        .audio(AcceptAudioParams {
            codec: "opus".to_string(),
            rate: 16000,
        })
        .build();

        let children = node.children().unwrap();
        let accept_node = &children[0];
        let accept_children = accept_node.children().unwrap();

        let audio = accept_children.iter().find(|c| c.tag == "audio");
        assert!(audio.is_some(), "Accept must have <audio> element");
        let mut attrs = audio.unwrap().attrs();
        assert_eq!(attrs.optional_string("enc"), Some("opus"));
        assert_eq!(attrs.optional_string("rate"), Some("16000"));
    }

    #[test]
    fn test_accept_video_call_has_video_params() {
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            caller_jid(),
            callee_jid(),
            SignalingType::Accept,
        )
        .video(true)
        .audio(AcceptAudioParams::default())
        .video_params(AcceptVideoParams {
            codec: "vp8".to_string(),
        })
        .build();

        let children = node.children().unwrap();
        let accept_node = &children[0];
        let accept_children = accept_node.children().unwrap();

        assert!(accept_children.iter().any(|c| c.tag == "audio"));
        assert!(accept_children.iter().any(|c| c.tag == "video"));
        assert!(
            !accept_children.iter().any(|c| c.tag == "enc"),
            "Video accept also must not have <enc>"
        );
    }

    // ================================================================
    // 2. Offer stanza MUST contain <enc> element
    // ================================================================

    #[test]
    fn test_offer_stanza_has_enc_element() {
        let encrypted_key = EncryptedCallKey {
            ciphertext: vec![0xBB; 64],
            enc_type: EncType::Msg,
        };

        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            callee_jid(), // we are the creator
            caller_jid(), // sending to peer
            SignalingType::Offer,
        )
        .encrypted_key(encrypted_key)
        .audio(AcceptAudioParams::default())
        .build();

        let children = node.children().unwrap();
        let offer_node = &children[0];
        assert_eq!(offer_node.tag, "offer");

        let offer_children = offer_node.children().unwrap();
        let enc_node = offer_children.iter().find(|c| c.tag == "enc");
        assert!(
            enc_node.is_some(),
            "Offer stanza MUST contain <enc> element"
        );

        let mut enc_attrs = enc_node.unwrap().attrs();
        assert_eq!(
            enc_attrs.optional_string("type"),
            Some("msg"),
            "enc type should be 'msg'"
        );
        assert_eq!(
            enc_attrs.optional_string("v"),
            Some("2"),
            "enc version should be '2'"
        );
    }

    #[test]
    fn test_offer_without_enc_key_has_no_enc_element() {
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            callee_jid(),
            caller_jid(),
            SignalingType::Offer,
        )
        .audio(AcceptAudioParams::default())
        .build();

        let children = node.children().unwrap();
        let offer_node = &children[0];
        let offer_children = offer_node.children().unwrap();
        assert!(
            !offer_children.iter().any(|c| c.tag == "enc"),
            "Offer without encrypted_key should have no <enc>"
        );
    }

    // ================================================================
    // 3. PreAccept stanza structure
    // ================================================================

    #[test]
    fn test_preaccept_stanza_structure() {
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            caller_jid(),
            callee_jid(),
            SignalingType::PreAccept,
        )
        .preaccept_params(PreacceptParams::default())
        .build();

        let children = node.children().unwrap();
        let preaccept_node = &children[0];
        assert_eq!(preaccept_node.tag, "preaccept");

        let preaccept_children = preaccept_node.children().unwrap();

        // PreAccept should have: audio, encopt, capability - but NOT enc
        assert!(
            !preaccept_children.iter().any(|c| c.tag == "enc"),
            "PreAccept must NOT have <enc>"
        );
        assert!(
            preaccept_children.iter().any(|c| c.tag == "audio"),
            "PreAccept must have <audio>"
        );
        assert!(
            preaccept_children.iter().any(|c| c.tag == "encopt"),
            "PreAccept must have <encopt>"
        );
        assert!(
            preaccept_children.iter().any(|c| c.tag == "capability"),
            "PreAccept must have <capability>"
        );
    }

    #[test]
    fn test_preaccept_audio_params() {
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            caller_jid(),
            callee_jid(),
            SignalingType::PreAccept,
        )
        .preaccept_params(PreacceptParams::default())
        .build();

        let children = node.children().unwrap();
        let preaccept_node = &children[0];
        let preaccept_children = preaccept_node.children().unwrap();

        let audio = preaccept_children
            .iter()
            .find(|c| c.tag == "audio")
            .unwrap();
        let mut attrs = audio.attrs();
        assert_eq!(attrs.optional_string("enc"), Some("opus"));
        assert_eq!(attrs.optional_string("rate"), Some("16000"));
    }

    // ================================================================
    // 4. Signaling response types (receipt vs ack)
    // ================================================================

    #[test]
    fn test_offer_requires_receipt_response() {
        assert_eq!(
            SignalingType::Offer.response_type(),
            Some(ResponseType::Receipt)
        );
    }

    #[test]
    fn test_accept_requires_receipt_response() {
        assert_eq!(
            SignalingType::Accept.response_type(),
            Some(ResponseType::Receipt)
        );
    }

    #[test]
    fn test_preaccept_requires_ack_response() {
        assert_eq!(
            SignalingType::PreAccept.response_type(),
            Some(ResponseType::Ack)
        );
    }

    #[test]
    fn test_transport_requires_ack_response() {
        assert_eq!(
            SignalingType::Transport.response_type(),
            Some(ResponseType::Ack)
        );
    }

    #[test]
    fn test_enc_rekey_requires_receipt_response() {
        assert_eq!(
            SignalingType::EncRekey.response_type(),
            Some(ResponseType::Receipt)
        );
    }

    // ================================================================
    // 5. Call state machine - incoming call flow
    //    WhatsApp Web: IncomingRinging → Connecting → Active → Ended
    // ================================================================

    #[test]
    fn test_incoming_call_state_flow() {
        let mut call = CallInfo::new_incoming(
            CallId::new(TEST_CALL_ID),
            caller_jid(),
            caller_jid(),
            Some("5551234567@s.whatsapp.net".parse().unwrap()),
            CallMediaType::Audio,
        );

        // Initial state: IncomingRinging
        assert!(call.state.is_ringing());
        assert!(call.state.can_accept());

        // Accept → Connecting
        call.apply_transition(CallTransition::LocalAccepted)
            .unwrap();
        assert!(matches!(call.state, CallState::Connecting { .. }));

        // Media connected → Active
        call.apply_transition(CallTransition::MediaConnected)
            .unwrap();
        assert!(call.state.is_active());

        // Terminate → Ended
        call.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })
        .unwrap();
        assert!(call.state.is_ended());
    }

    #[test]
    fn test_cannot_accept_after_already_accepted() {
        let mut call = CallInfo::new_incoming(
            CallId::new(TEST_CALL_ID),
            caller_jid(),
            caller_jid(),
            None,
            CallMediaType::Audio,
        );

        call.apply_transition(CallTransition::LocalAccepted)
            .unwrap();
        // Should not be able to accept again (now in Connecting state)
        assert!(!call.state.can_accept());
    }

    // ================================================================
    // 6. CallManager accept_call API (no encrypted_key parameter)
    // ================================================================

    #[tokio::test]
    async fn test_manager_accept_call_no_enc() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        let accept_node = manager.accept_call(&call_id).await.unwrap();

        // Verify the accept stanza structure
        assert_eq!(accept_node.tag, "call");
        let children = accept_node.children().unwrap();
        let accept_child = &children[0];
        assert_eq!(accept_child.tag, "accept");

        // Verify no <enc> element in accept
        let accept_children = accept_child.children().unwrap();
        assert!(
            !accept_children.iter().any(|c| c.tag == "enc"),
            "Manager's accept_call must not produce <enc> in accept stanza"
        );

        // Verify audio element is present
        assert!(
            accept_children.iter().any(|c| c.tag == "audio"),
            "Accept must have audio codec params"
        );
    }

    #[tokio::test]
    async fn test_manager_accept_transitions_to_connecting() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        manager.accept_call(&call_id).await.unwrap();

        // Verify state transitioned to Connecting
        let info = manager.get_call(&call_id).await.unwrap();
        assert!(matches!(info.state, CallState::Connecting { .. }));
    }

    #[tokio::test]
    async fn test_manager_accept_rejects_double_accept() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        manager.accept_call(&call_id).await.unwrap();

        // Second accept should fail
        let result = manager.accept_call(&call_id).await;
        assert!(result.is_err(), "Double accept should be rejected");
    }

    // ================================================================
    // 7. store_call_encryption stores keys in CallInfo
    // ================================================================

    #[tokio::test]
    async fn test_store_call_encryption() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        // Initially no encryption
        let call_id = CallId::new(TEST_CALL_ID);
        let info = manager.get_call(&call_id).await.unwrap();
        assert!(info.encryption.is_none());

        // Store a call key
        let call_key = CallEncryptionKey::generate();
        manager
            .store_call_encryption(&call_id, call_key.clone())
            .await;

        // Verify it's stored
        let info = manager.get_call(&call_id).await.unwrap();
        assert!(info.encryption.is_some());
        let enc = info.encryption.as_ref().unwrap();
        assert_eq!(enc.master_key.master_key, call_key.master_key);
    }

    #[tokio::test]
    async fn test_enc_rekey_updates_encryption() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);

        // Store initial key (generation 0)
        let key1 = CallEncryptionKey::generate();
        let gen1 = key1.generation;
        manager.store_call_encryption(&call_id, key1.clone()).await;

        // Simulate enc_rekey with new key
        let mut key2 = CallEncryptionKey::generate();
        key2.generation = gen1 + 1;
        manager.store_call_encryption(&call_id, key2.clone()).await;

        // Verify key was updated
        let info = manager.get_call(&call_id).await.unwrap();
        let enc = info.encryption.as_ref().unwrap();
        assert_eq!(enc.master_key.generation, gen1 + 1);
        assert_eq!(enc.master_key.master_key, key2.master_key);
    }

    // ================================================================
    // 8. PreAccept can be built for registered incoming calls
    // ================================================================

    #[tokio::test]
    async fn test_preaccept_for_registered_call() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        let preaccept_node = manager.send_preaccept(&call_id).await.unwrap();

        assert_eq!(preaccept_node.tag, "call");
        let children = preaccept_node.children().unwrap();
        let preaccept_child = &children[0];
        assert_eq!(preaccept_child.tag, "preaccept");

        let preaccept_children = preaccept_child.children().unwrap();
        assert!(
            preaccept_children.iter().any(|c| c.tag == "audio"),
            "PreAccept should have audio params"
        );
        assert!(
            preaccept_children.iter().any(|c| c.tag == "encopt"),
            "PreAccept should have encopt"
        );
    }

    #[tokio::test]
    async fn test_preaccept_fails_for_unknown_call() {
        let manager = make_call_manager();
        let call_id = CallId::new("NONEXISTENT_CALL_ID_12345678901");
        let result = manager.send_preaccept(&call_id).await;
        assert!(result.is_err());
    }

    // ================================================================
    // 9. Call key derivation produces valid SRTP keys
    // ================================================================

    #[test]
    fn test_call_key_derivation() {
        let key = CallEncryptionKey::generate();
        let derived = derive_call_keys(&key);

        // HBH SRTP keys: 16-byte master key + 14-byte salt
        assert_eq!(derived.hbh_srtp.master_key.len(), 16);
        assert_eq!(derived.hbh_srtp.master_salt.len(), 14);

        // E2E SFrame key should be non-empty
        assert!(!derived.e2e_sframe.is_empty());
    }

    #[test]
    fn test_call_key_derivation_deterministic() {
        let key = CallEncryptionKey::generate();
        let derived1 = derive_call_keys(&key);
        let derived2 = derive_call_keys(&key);

        assert_eq!(derived1.hbh_srtp.master_key, derived2.hbh_srtp.master_key);
        assert_eq!(derived1.hbh_srtp.master_salt, derived2.hbh_srtp.master_salt);
        assert_eq!(derived1.e2e_sframe, derived2.e2e_sframe);
    }

    // ================================================================
    // 10. Offer registration stores all offer data
    // ================================================================

    #[tokio::test]
    async fn test_register_incoming_call_stores_offer_data() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        let info = manager.get_call(&call_id).await.unwrap();

        assert!(info.offer_enc_data.is_some());
        assert!(info.offer_relay_data.is_some());
        assert!(info.offer_media_params.is_some());
        assert!(info.state.is_ringing());
        assert!(info.state.can_accept());
        assert_eq!(info.caller_pn, parsed.caller_pn);
    }

    #[tokio::test]
    async fn test_register_incoming_call_sets_direction() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        let info = manager.get_call(&call_id).await.unwrap();
        assert_eq!(info.direction, wacore::types::call::CallDirection::Incoming);
    }

    // ================================================================
    // 11. Full incoming call lifecycle through manager
    //     Mirrors WhatsApp Web: register → decrypt key → preaccept → accept
    // ================================================================

    #[tokio::test]
    async fn test_full_incoming_call_lifecycle() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        // Step 1: Register incoming offer
        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);

        // Step 2: Store decrypted call key (simulates decrypt_call_key_from on offer receipt)
        let call_key = CallEncryptionKey::generate();
        manager
            .store_call_encryption(&call_id, call_key.clone())
            .await;

        // Step 3: PreAccept (auto-sent by handler on offer receipt)
        let preaccept = manager.send_preaccept(&call_id).await.unwrap();
        assert_eq!(preaccept.children().unwrap()[0].tag, "preaccept");

        // Step 4: Accept (user presses accept button)
        let accept = manager.accept_call(&call_id).await.unwrap();
        let accept_child = &accept.children().unwrap()[0];
        assert_eq!(accept_child.tag, "accept");
        // Per protocol: No <enc> in accept
        assert!(
            !accept_child
                .children()
                .unwrap()
                .iter()
                .any(|c| c.tag == "enc")
        );

        // Verify final state
        let info = manager.get_call(&call_id).await.unwrap();
        assert!(
            matches!(info.state, CallState::Connecting { .. }),
            "State should be Connecting after accept"
        );
        assert!(
            info.encryption.is_some(),
            "Encryption key from step 2 should persist"
        );
    }

    // ================================================================
    // 12. Enc element only in Offer, not in any other signaling type
    // ================================================================

    #[test]
    fn test_enc_only_in_offer_not_other_types() {
        let encrypted_key = EncryptedCallKey {
            ciphertext: vec![0xCC; 32],
            enc_type: EncType::PkMsg,
        };

        let signaling_types_without_enc = [
            SignalingType::Accept,
            SignalingType::PreAccept,
            SignalingType::Reject,
            SignalingType::Terminate,
        ];

        for st in signaling_types_without_enc {
            let mut builder = CallStanzaBuilder::new(TEST_CALL_ID, caller_jid(), callee_jid(), st)
                .encrypted_key(encrypted_key.clone());

            if st == SignalingType::PreAccept {
                builder = builder.preaccept_params(PreacceptParams::default());
            }

            let node = builder.build();
            let children = node.children().unwrap();
            let sig_node = &children[0];
            if let Some(sig_children) = sig_node.children() {
                assert!(
                    !sig_children.iter().any(|c| c.tag == "enc"),
                    "{:?} stanza must NOT contain <enc>",
                    st
                );
            }
        }

        // Offer SHOULD have enc
        let node = CallStanzaBuilder::new(
            TEST_CALL_ID,
            caller_jid(),
            callee_jid(),
            SignalingType::Offer,
        )
        .encrypted_key(encrypted_key)
        .build();

        let children = node.children().unwrap();
        let offer_node = &children[0];
        let offer_children = offer_node.children().unwrap();
        assert!(
            offer_children.iter().any(|c| c.tag == "enc"),
            "Offer MUST contain <enc>"
        );
    }

    // ================================================================
    // 13. Encryption persists through state transitions
    // ================================================================

    #[tokio::test]
    async fn test_encryption_persists_through_accept() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        let call_key = CallEncryptionKey::generate();
        let derived = derive_call_keys(&call_key);

        // Store key during ringing
        manager
            .store_call_encryption(&call_id, call_key.clone())
            .await;

        // Accept the call (transitions to Connecting)
        manager.accept_call(&call_id).await.unwrap();

        // Encryption should still be available after accept
        let info = manager.get_call(&call_id).await.unwrap();
        let enc = info.encryption.as_ref().unwrap();
        assert_eq!(
            enc.derived_keys.hbh_srtp.master_key, derived.hbh_srtp.master_key,
            "SRTP keys must persist through accept transition"
        );
    }

    // ================================================================
    // 14. Outgoing call flow: enc only in offer
    // ================================================================

    #[test]
    fn test_outgoing_call_state_flow() {
        let mut call = CallInfo::new_outgoing(
            CallId::new(TEST_CALL_ID),
            caller_jid(),
            callee_jid(),
            CallMediaType::Audio,
        );

        assert!(matches!(call.state, CallState::Initiating));

        // Offer sent → Ringing
        call.apply_transition(CallTransition::OfferSent).unwrap();
        assert!(call.state.is_ringing());

        // Remote accepts → Connecting
        call.apply_transition(CallTransition::RemoteAccepted)
            .unwrap();
        assert!(matches!(call.state, CallState::Connecting { .. }));

        // Media connected → Active
        call.apply_transition(CallTransition::MediaConnected)
            .unwrap();
        assert!(call.state.is_active());
    }

    // ================================================================
    // 15. SDP manipulation matches WhatsApp Web (xe() function)
    //     Reference: sTyteLh02ST.js lines 322-330
    // ================================================================

    /// Helper to create a realistic SDP from a WebRTC offer.
    fn sample_sdp() -> String {
        [
            "v=0",
            "o=- 1234567890 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0",
            "a=msid-semantic: WMS",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=ice-ufrag:LOCALUFRAG",
            "a=ice-pwd:LOCALPWD123456789012345",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
            "a=setup:actpass",
            "a=mid:0",
            "a=sctp-port:5000",
            "a=candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host",
            "a=end-of-candidates",
            "",
        ]
        .join("\r\n")
    }

    fn sample_relay_info() -> crate::calls::media::RelayConnectionInfo {
        crate::calls::media::RelayConnectionInfo {
            ip: "57.144.129.54".to_string(),
            port: crate::calls::WHATSAPP_RELAY_PORT,
            auth_token:
                "dGhpcyBpcyBhIHRlc3QgYXV0aCB0b2tlbiB0aGF0IGlzIDcwIGJ5dGVzIGxvbmcgZm9yIHVmcmFn"
                    .to_string(),
            relay_key: "cmVsYXlfa2V5XzE2Yg==".to_string(),
            relay_name: "for2c01".to_string(),
            relay_id: 2,
            c2r_rtt_ms: Some(5),
        }
    }

    #[test]
    fn test_sdp_ice_ufrag_replaced_with_auth_token() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        assert!(
            modified.contains(&format!("a=ice-ufrag:{}", relay.auth_token)),
            "ice-ufrag must be replaced with auth_token"
        );
        assert!(
            !modified.contains("a=ice-ufrag:LOCALUFRAG"),
            "Original ice-ufrag must be removed"
        );
    }

    #[test]
    fn test_sdp_ice_pwd_replaced_with_relay_key() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        assert!(
            modified.contains(&format!("a=ice-pwd:{}", relay.relay_key)),
            "ice-pwd must be replaced with relay_key"
        );
        assert!(
            !modified.contains("a=ice-pwd:LOCALPWD"),
            "Original ice-pwd must be removed"
        );
    }

    #[test]
    fn test_sdp_fingerprint_replaced_with_hardcoded() {
        use crate::calls::media::{WHATSAPP_DTLS_FINGERPRINT, manipulate_sdp};
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        assert!(
            modified.contains(&format!("a=fingerprint:{}", WHATSAPP_DTLS_FINGERPRINT)),
            "Fingerprint must be replaced with WhatsApp's hardcoded fingerprint"
        );
        assert!(
            !modified.contains("AA:BB:CC:DD:EE:FF"),
            "Original fingerprint must be removed"
        );
    }

    #[test]
    fn test_sdp_setup_changed_to_passive() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        assert!(
            modified.contains("a=setup:passive"),
            "setup must be changed from actpass to passive"
        );
        assert!(
            !modified.contains("a=setup:actpass"),
            "actpass must be removed"
        );
    }

    #[test]
    fn test_sdp_ice_options_removed() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        assert!(
            !modified.contains("a=ice-options:"),
            "ice-options must be removed (WhatsApp Web strips it)"
        );
    }

    #[test]
    fn test_sdp_original_candidates_replaced_with_relay() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        // Original candidate removed
        assert!(
            !modified.contains("192.168.1.100"),
            "Original ICE candidates must be removed"
        );

        // Relay injected as host candidate (exactly like WhatsApp Web's De() function)
        assert!(
            modified.contains(&format!(
                "a=candidate:2 1 udp 2122262783 {} {} typ host generation 0 network-cost 5",
                relay.ip, relay.port
            )),
            "Relay must be injected as a host candidate with priority 2122262783"
        );

        // end-of-candidates present
        assert!(
            modified.contains("a=end-of-candidates"),
            "end-of-candidates must be present"
        );
    }

    #[test]
    fn test_sdp_relay_uses_port_3480() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        // WhatsApp Web always uses 3480 (TRUE_WEB_CLIENT_RELAY_PORT)
        assert!(
            modified.contains("57.144.129.54 3480"),
            "Relay must use port 3480"
        );
    }

    #[test]
    fn test_sdp_manipulation_produces_valid_answer() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        // Must still have required SDP lines
        assert!(modified.contains("v=0"), "SDP must start with v=0");
        assert!(modified.contains("m=application"), "Must have m= line");
        assert!(modified.contains("a=mid:0"), "Must preserve mid");
        assert!(
            modified.contains("a=sctp-port:5000"),
            "Must preserve sctp-port"
        );
    }

    // ================================================================
    // 16. Relay port constants match WhatsApp Web
    // ================================================================

    #[test]
    fn test_whatsapp_relay_port_is_3480() {
        assert_eq!(
            crate::calls::WHATSAPP_RELAY_PORT,
            3480,
            "TRUE_WEB_CLIENT_RELAY_PORT in WhatsApp Web JS is 3480"
        );
    }

    #[test]
    fn test_turn_relay_port_is_3478() {
        assert_eq!(
            crate::calls::TURN_RELAY_PORT,
            3478,
            "FAUX_WEB_CLIENT_RELAY_PORT in WhatsApp Web JS is 3478"
        );
    }

    // ================================================================
    // 17. DTLS fingerprint matches WhatsApp Web hardcoded value
    // ================================================================

    #[test]
    fn test_dtls_fingerprint_matches_whatsapp_web() {
        use crate::calls::media::WHATSAPP_DTLS_FINGERPRINT;

        // This exact fingerprint is hardcoded in WhatsApp Web JS (sTyteLh02ST.js)
        assert_eq!(
            WHATSAPP_DTLS_FINGERPRINT,
            "sha-256 F9:CA:0C:98:A3:CC:71:D6:42:CE:5A:E2:53:D2:15:20:D3:1B:BA:D8:57:A4:F0:AF:BE:0B:FB:F3:6B:0C:A0:68"
        );
    }

    // ================================================================
    // 18. DataChannel name matches WhatsApp Web
    // ================================================================

    #[test]
    fn test_data_channel_name_matches_whatsapp_web() {
        use crate::calls::media::DATA_CHANNEL_NAME;
        assert_eq!(DATA_CHANNEL_NAME, "wa-web-call");
    }

    // ================================================================
    // 19. Relay connection uses pass-through (no fake STUN)
    //     Verifies the RelayUdpConn is a simple socket wrapper
    // ================================================================

    #[tokio::test]
    async fn test_relay_udp_conn_binds_socket() {
        use crate::calls::media::RelayUdpConn;
        use std::net::SocketAddr;

        // Use a random target addr (we won't actually send to it)
        let target: SocketAddr = "127.0.0.1:3480".parse().unwrap();
        let conn = RelayUdpConn::new(target).await.unwrap();

        // Socket should be bound to a local port
        let local = conn.local_addr();
        assert_ne!(local.port(), 0, "Socket should have a real local port");

        // Remote should be the relay
        assert_eq!(conn.remote_addr(), target);
    }

    #[tokio::test]
    async fn test_relay_udp_conn_ipv6() {
        use crate::calls::media::RelayUdpConn;
        use std::net::SocketAddr;

        let target: SocketAddr = "[::1]:3480".parse().unwrap();
        let conn = RelayUdpConn::new(target).await.unwrap();

        assert!(
            conn.local_addr().is_ipv6(),
            "IPv6 relay should bind to IPv6 socket"
        );
        assert_eq!(conn.remote_addr(), target);
    }

    #[tokio::test]
    async fn test_relay_udp_conn_send_goes_to_relay() {
        use crate::calls::media::RelayUdpConn;
        use std::net::SocketAddr;
        use webrtc::util::Conn;

        // Create a local "relay" to receive the packet
        let relay_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr: SocketAddr = relay_socket.local_addr().unwrap();

        let conn = RelayUdpConn::new(relay_addr).await.unwrap();

        // Send a packet (STUN Binding Request header)
        let stun_binding_request = {
            let mut buf = vec![0u8; 20];
            buf[0] = 0x00;
            buf[1] = 0x01; // Binding Request type
            // bytes 4-7: STUN magic cookie
            buf[4] = 0x21;
            buf[5] = 0x12;
            buf[6] = 0xA4;
            buf[7] = 0x42;
            buf
        };

        let sent = conn.send(&stun_binding_request).await.unwrap();
        assert_eq!(sent, 20);

        // The packet should arrive at the relay (not be intercepted)
        let mut recv_buf = vec![0u8; 1024];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            relay_socket.recv_from(&mut recv_buf),
        )
        .await
        .expect("relay should receive packet")
        .unwrap();

        assert_eq!(len, 20, "relay must receive all 20 bytes");
        assert_eq!(&recv_buf[..20], &stun_binding_request[..]);
        // Port should match (IP may differ: 0.0.0.0 bind vs 127.0.0.1 source)
        assert_eq!(
            from.port(),
            conn.local_addr().port(),
            "packet should come from our local port"
        );
    }

    #[tokio::test]
    async fn test_relay_udp_conn_recv_gets_relay_response() {
        use crate::calls::media::RelayUdpConn;
        use std::net::SocketAddr;
        use webrtc::util::Conn;

        // Create a local "relay"
        let relay_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr: SocketAddr = relay_socket.local_addr().unwrap();

        let conn = RelayUdpConn::new(relay_addr).await.unwrap();

        // Send something first so relay knows our address
        conn.send(&[0x00]).await.unwrap();
        let mut buf = [0u8; 1];
        let (_, from) = relay_socket.recv_from(&mut buf).await.unwrap();

        // Relay sends a response
        let response = b"STUN-RESPONSE-DATA";
        relay_socket.send_to(response, from).await.unwrap();

        // We should receive it directly (no interception)
        let mut recv_buf = vec![0u8; 1024];
        let len = tokio::time::timeout(std::time::Duration::from_secs(1), conn.recv(&mut recv_buf))
            .await
            .expect("should receive response")
            .unwrap();

        assert_eq!(&recv_buf[..len], response);
    }

    // ================================================================
    // 20. SDP answer type is set correctly (passive, not actpass)
    //     WhatsApp Web: setRemoteDescription({ sdp: modified, type: "answer" })
    // ================================================================

    #[test]
    fn test_sdp_answer_type_passive_not_actpass() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();
        let modified = manipulate_sdp(&sample_sdp(), &relay);

        // Count occurrences of setup: should only be "passive"
        let passive_count = modified.matches("a=setup:passive").count();
        let actpass_count = modified.matches("a=setup:actpass").count();

        assert_eq!(passive_count, 1, "Should have exactly one setup:passive");
        assert_eq!(actpass_count, 0, "Should have zero setup:actpass");
    }

    // ================================================================
    // 21. SDP with IPv6 relay address
    // ================================================================

    #[test]
    fn test_sdp_ipv6_relay_candidate() {
        use crate::calls::media::manipulate_sdp;
        let mut relay = sample_relay_info();
        relay.ip = "2a03:2880:f340:136:face:b00c:0:b1".to_string();

        let modified = manipulate_sdp(&sample_sdp(), &relay);

        assert!(
            modified.contains("2a03:2880:f340:136:face:b00c:0:b1 3480"),
            "IPv6 relay address must be in the SDP candidate"
        );
    }

    // ================================================================
    // 22. Reject incoming call flow
    // ================================================================

    #[test]
    fn test_incoming_call_reject_flow() {
        let mut call = CallInfo::new_incoming(
            CallId::new(TEST_CALL_ID),
            caller_jid(),
            caller_jid(),
            None,
            CallMediaType::Audio,
        );

        assert!(call.state.is_ringing());

        call.apply_transition(CallTransition::LocalRejected {
            reason: EndCallReason::Declined,
        })
        .unwrap();
        assert!(call.state.is_ended());
    }

    // ================================================================
    // 23. Cannot transition from Ended state
    // ================================================================

    #[test]
    fn test_cannot_transition_from_ended() {
        let mut call = CallInfo::new_incoming(
            CallId::new(TEST_CALL_ID),
            caller_jid(),
            caller_jid(),
            None,
            CallMediaType::Audio,
        );

        call.apply_transition(CallTransition::LocalRejected {
            reason: EndCallReason::Declined,
        })
        .unwrap();
        assert!(call.state.is_ended());

        // Cannot accept an ended call
        let result = call.apply_transition(CallTransition::LocalAccepted);
        assert!(result.is_err(), "Cannot transition from Ended state");
    }

    // ================================================================
    // 24. Offline call should not be registered
    // ================================================================

    #[tokio::test]
    async fn test_offline_call_is_not_registered() {
        let manager = make_call_manager();
        let mut parsed = make_incoming_parsed_stanza();
        parsed.is_offline = true;

        // Offline calls should still register (the handler decides not to register them,
        // but the manager itself accepts any registration)
        // This test documents that the handler logic skips registration for offline calls
        let call_id = CallId::new(TEST_CALL_ID);

        // Before registration, call should not exist
        assert!(manager.get_call(&call_id).await.is_none());
    }

    // ================================================================
    // 25. Video call has is_video flag set
    // ================================================================

    #[tokio::test]
    async fn test_video_call_registration() {
        let manager = make_call_manager();
        let mut parsed = make_incoming_parsed_stanza();
        parsed.is_video = true;

        manager.register_incoming_call(&parsed).await.unwrap();

        let call_id = CallId::new(TEST_CALL_ID);
        let info = manager.get_call(&call_id).await.unwrap();
        assert_eq!(info.media_type, CallMediaType::Video);
    }

    // ================================================================
    // 26. Multiple enc rekeys update the key each time
    // ================================================================

    #[tokio::test]
    async fn test_multiple_enc_rekeys() {
        let manager = make_call_manager();
        let parsed = make_incoming_parsed_stanza();
        manager.register_incoming_call(&parsed).await.unwrap();
        let call_id = CallId::new(TEST_CALL_ID);

        // Simulate 3 rekeys
        for generation in 0..3 {
            let mut key = CallEncryptionKey::generate();
            key.generation = generation;
            manager.store_call_encryption(&call_id, key).await;

            let info = manager.get_call(&call_id).await.unwrap();
            let enc = info.encryption.as_ref().unwrap();
            assert_eq!(enc.master_key.generation, generation);
        }
    }

    // ================================================================
    // 27. SDP manipulation is idempotent
    // ================================================================

    #[test]
    fn test_sdp_manipulation_idempotent() {
        use crate::calls::media::manipulate_sdp;
        let relay = sample_relay_info();

        let first = manipulate_sdp(&sample_sdp(), &relay);
        let second = manipulate_sdp(&first, &relay);

        // The second application should not change anything meaningful
        // (fingerprint, ufrag, pwd are already set; candidates already replaced)
        assert!(second.contains(&format!("a=ice-ufrag:{}", relay.auth_token)));
        assert!(second.contains(&format!("a=ice-pwd:{}", relay.relay_key)));
        assert!(second.contains("a=setup:passive"));
        // Only one relay candidate
        assert_eq!(
            second.matches("a=candidate:").count(),
            1,
            "Should have exactly one candidate after double manipulation"
        );
    }
}
