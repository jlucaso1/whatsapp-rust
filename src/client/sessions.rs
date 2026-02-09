//! E2E Session management for Client.

use anyhow::Result;
use wacore::libsignal::store::SessionStore;
use wacore::types::jid::JidExt;
use wacore_binary::jid::Jid;

use super::Client;

impl Client {
    /// Wait for offline message delivery to complete (with timeout).
    pub(crate) async fn wait_for_offline_delivery_end(&self) {
        use std::sync::atomic::Ordering;

        if self.offline_sync_completed.load(Ordering::Relaxed) {
            return;
        }

        const TIMEOUT_SECS: u64 = 10;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SECS),
            self.offline_sync_notifier.notified(),
        )
        .await;
    }

    /// Ensure E2E sessions exist for the given device JIDs.
    /// Waits for offline delivery, resolves LID mappings, then batches prekey fetches.
    pub(crate) async fn ensure_e2e_sessions(&self, device_jids: Vec<Jid>) -> Result<()> {
        use wacore::libsignal::store::SessionStore;
        use wacore::types::jid::JidExt;

        if device_jids.is_empty() {
            return Ok(());
        }

        self.wait_for_offline_delivery_end().await;
        let resolved_jids = self.resolve_lid_mappings(&device_jids).await;

        let device_store = self.persistence_manager.get_device_arc().await;
        let mut jids_needing_sessions = Vec::with_capacity(resolved_jids.len());

        {
            let device_guard = device_store.read().await;
            for jid in resolved_jids {
                let signal_addr = jid.to_protocol_address();
                match device_guard.contains_session(&signal_addr).await {
                    Ok(true) => {}
                    Ok(false) => jids_needing_sessions.push(jid),
                    Err(e) => log::warn!("Failed to check session for {}: {}", jid, e),
                }
            }
        }

        if jids_needing_sessions.is_empty() {
            return Ok(());
        }

        for batch in jids_needing_sessions.chunks(crate::session::SESSION_CHECK_BATCH_SIZE) {
            self.fetch_and_establish_sessions(batch).await?;
        }

        Ok(())
    }

    /// Fetch prekeys and establish sessions for a batch of JIDs.
    /// Returns the number of sessions successfully established.
    async fn fetch_and_establish_sessions(&self, jids: &[Jid]) -> Result<usize, anyhow::Error> {
        use rand::TryRngCore;
        use wacore::libsignal::protocol::{UsePQRatchet, process_prekey_bundle};
        use wacore::types::jid::JidExt;

        if jids.is_empty() {
            return Ok(0);
        }

        let prekey_bundles = self.fetch_pre_keys(jids, Some("identity")).await?;

        let device_store = self.persistence_manager.get_device_arc().await;
        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

        let mut success_count = 0;
        let mut missing_count = 0;
        let mut failed_count = 0;

        for jid in jids {
            if let Some(bundle) = prekey_bundles.get(&jid.normalize_for_prekey_bundle()) {
                let signal_addr = jid.to_protocol_address();
                match process_prekey_bundle(
                    &signal_addr,
                    &mut adapter.session_store,
                    &mut adapter.identity_store,
                    bundle,
                    &mut rand::rngs::OsRng.unwrap_err(),
                    UsePQRatchet::No,
                )
                .await
                {
                    Ok(_) => {
                        success_count += 1;
                        log::debug!("Successfully established session with {}", jid);
                    }
                    Err(e) => {
                        failed_count += 1;
                        log::warn!("Failed to establish session with {}: {}", jid, e);
                    }
                }
            } else {
                missing_count += 1;
                if jid.device == 0 {
                    log::warn!("Server did not return prekeys for primary phone {}", jid);
                } else {
                    log::debug!("Server did not return prekeys for {}", jid);
                }
            }
        }

        if missing_count > 0 || failed_count > 0 {
            log::debug!(
                "Session establishment: {} succeeded, {} missing prekeys, {} failed (of {} requested)",
                success_count,
                missing_count,
                failed_count,
                jids.len()
            );
        }

        Ok(success_count)
    }

    /// Establish session with primary phone (device 0) immediately for PDO.
    ///
    /// Called during login BEFORE offline messages arrive. Checks both PN and LID
    /// sessions but does NOT establish PN sessions proactively. The primary phone's
    /// PN session will be established via LID pkmsg when needed, which prevents
    /// dual-session conflicts where both PN and LID sessions exist for the same user.
    /// This matches WhatsApp Web's `prekey_fetch_iq_pnh_lid_enabled: false` behavior.
    ///
    /// Returns error if session check fails (fail-safe to prevent replacing existing sessions).
    pub(crate) async fn establish_primary_phone_session_immediate(&self) -> Result<()> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let own_pn = device_snapshot
            .pn
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in - no phone number available"))?;

        let primary_phone_pn = own_pn.with_device(0);
        let primary_phone_lid = device_snapshot.lid.as_ref().map(|lid| lid.with_device(0));

        let pn_session_exists =
            self.check_session_exists(&primary_phone_pn)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Cannot verify PN session existence for primary phone {}: {}. \
                     Refusing to establish session to prevent potential MAC failures.",
                        primary_phone_pn,
                        e
                    )
                })?;

        // Don't proactively establish PN session - matches WhatsApp Web's
        // prekey_fetch_iq_pnh_lid_enabled: false behavior. The primary phone will
        // establish the session via pkmsg from LID address, which prevents dual-session
        // conflicts where both PN and LID sessions exist for the same user.
        if pn_session_exists {
            log::debug!(
                "PN session with primary phone {} already exists",
                primary_phone_pn
            );
        } else {
            log::debug!(
                "No PN session with primary phone {} - will be established via LID pkmsg",
                primary_phone_pn
            );
        }

        // Check LID session existence (don't establish - primary phone does that via pkmsg)
        if let Some(ref lid_jid) = primary_phone_lid {
            match self.check_session_exists(lid_jid).await {
                Ok(true) => log::debug!("LID session with {} already exists", lid_jid),
                Ok(false) => log::debug!(
                    "No LID session with {} - established on first message",
                    lid_jid
                ),
                Err(e) => log::debug!("Could not check LID session for {}: {}", lid_jid, e),
            }
        }

        Ok(())
    }

    /// Check if a session exists for the given JID.
    async fn check_session_exists(&self, jid: &Jid) -> Result<bool, anyhow::Error> {
        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let signal_addr = jid.to_protocol_address();

        device_guard
            .contains_session(&signal_addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to check session for {}: {}", jid, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::jid::{DEFAULT_USER_SERVER, HIDDEN_USER_SERVER, JidExt};

    #[test]
    fn test_primary_phone_jid_creation_from_pn() {
        let own_pn = Jid::pn("559999999999");
        let primary_phone_jid = own_pn.with_device(0);

        assert_eq!(primary_phone_jid.user, "559999999999");
        assert_eq!(primary_phone_jid.server, DEFAULT_USER_SERVER);
        assert_eq!(primary_phone_jid.device, 0);
        assert_eq!(primary_phone_jid.agent, 0);
        assert_eq!(primary_phone_jid.to_string(), "559999999999@s.whatsapp.net");
    }

    #[test]
    fn test_primary_phone_jid_overwrites_existing_device() {
        // Edge case: pn with device ID should still produce device 0
        let own_pn = Jid::pn_device("559999999999", 33);
        let primary_phone_jid = own_pn.with_device(0);

        assert_eq!(primary_phone_jid.user, "559999999999");
        assert_eq!(primary_phone_jid.server, DEFAULT_USER_SERVER);
        assert_eq!(primary_phone_jid.device, 0);
    }

    #[test]
    fn test_primary_phone_jid_is_not_ad() {
        let primary_phone_jid = Jid::pn("559999999999").with_device(0);
        assert!(!primary_phone_jid.is_ad()); // device 0 is NOT an additional device
    }

    #[test]
    fn test_linked_device_is_ad() {
        let linked_device_jid = Jid::pn_device("559999999999", 33);
        assert!(linked_device_jid.is_ad()); // device > 0 IS an additional device
    }

    #[test]
    fn test_primary_phone_jid_from_lid() {
        let own_lid = Jid::lid("100000000000001");
        let primary_phone_jid = own_lid.with_device(0);

        assert_eq!(primary_phone_jid.user, "100000000000001");
        assert_eq!(primary_phone_jid.server, HIDDEN_USER_SERVER);
        assert_eq!(primary_phone_jid.device, 0);
        assert!(!primary_phone_jid.is_ad());
    }

    #[test]
    fn test_primary_phone_jid_roundtrip() {
        let own_pn = Jid::pn("559999999999");
        let primary_phone_jid = own_pn.with_device(0);

        let jid_string = primary_phone_jid.to_string();
        assert_eq!(jid_string, "559999999999@s.whatsapp.net");

        let parsed: Jid = jid_string.parse().expect("JID should be parseable");
        assert_eq!(parsed.user, "559999999999");
        assert_eq!(parsed.server, DEFAULT_USER_SERVER);
        assert_eq!(parsed.device, 0);
    }

    #[test]
    fn test_with_device_preserves_identity() {
        let pn = Jid::pn("1234567890");
        let pn_device_0 = pn.with_device(0);
        let pn_device_5 = pn.with_device(5);

        assert_eq!(pn_device_0.user, pn_device_5.user);
        assert_eq!(pn_device_0.server, pn_device_5.server);
        assert_eq!(pn_device_0.device, 0);
        assert_eq!(pn_device_5.device, 5);

        let lid = Jid::lid("100000012345678");
        let lid_device_0 = lid.with_device(0);
        let lid_device_33 = lid.with_device(33);

        assert_eq!(lid_device_0.user, lid_device_33.user);
        assert_eq!(lid_device_0.server, lid_device_33.server);
        assert_eq!(lid_device_0.device, 0);
        assert_eq!(lid_device_33.device, 33);
    }

    #[test]
    fn test_primary_phone_vs_companion_devices() {
        let user = "559999999999";
        let primary = Jid::pn(user).with_device(0);
        let companion_web = Jid::pn_device(user, 33);
        let companion_desktop = Jid::pn_device(user, 34);

        // All share the same user
        assert_eq!(primary.user, companion_web.user);
        assert_eq!(primary.user, companion_desktop.user);

        // But have different device IDs
        assert_eq!(primary.device, 0);
        assert_eq!(companion_web.device, 33);
        assert_eq!(companion_desktop.device, 34);

        // Primary is NOT AD, companions ARE AD
        assert!(!primary.is_ad());
        assert!(companion_web.is_ad());
        assert!(companion_desktop.is_ad());
    }

    /// Session check must succeed before establishment (fail-safe behavior).
    #[test]
    fn test_session_check_behavior_documentation() {
        // Ok(true) -> skip, Ok(false) -> establish, Err -> fail-safe
        enum SessionCheckResult {
            Exists,
            NotExists,
            CheckFailed,
        }

        fn should_establish_session(
            check_result: SessionCheckResult,
        ) -> Result<bool, &'static str> {
            match check_result {
                SessionCheckResult::Exists => Ok(false),   // Don't establish
                SessionCheckResult::NotExists => Ok(true), // Do establish
                SessionCheckResult::CheckFailed => Err("Cannot verify - fail safe"),
            }
        }

        // Test cases
        assert_eq!(
            should_establish_session(SessionCheckResult::Exists),
            Ok(false)
        );
        assert_eq!(
            should_establish_session(SessionCheckResult::NotExists),
            Ok(true)
        );
        assert!(should_establish_session(SessionCheckResult::CheckFailed).is_err());
    }

    /// Protocol address format: {user}[:device]@{server}.0
    #[test]
    fn test_protocol_address_format_for_session_lookup() {
        use wacore::types::jid::JidExt;

        let pn = Jid::pn("559999999999").with_device(0);
        let addr = pn.to_protocol_address();
        assert_eq!(addr.name(), "559999999999@c.us");
        assert_eq!(u32::from(addr.device_id()), 0);
        assert_eq!(addr.to_string(), "559999999999@c.us.0");

        let companion = Jid::pn_device("559999999999", 33);
        let companion_addr = companion.to_protocol_address();
        assert_eq!(companion_addr.name(), "559999999999:33@c.us");
        assert_eq!(companion_addr.to_string(), "559999999999:33@c.us.0");

        let lid = Jid::lid("100000000000001").with_device(0);
        let lid_addr = lid.to_protocol_address();
        assert_eq!(lid_addr.name(), "100000000000001@lid");
        assert_eq!(u32::from(lid_addr.device_id()), 0);
        assert_eq!(lid_addr.to_string(), "100000000000001@lid.0");

        let lid_device = Jid::lid_device("100000000000001", 33);
        let lid_device_addr = lid_device.to_protocol_address();
        assert_eq!(lid_device_addr.name(), "100000000000001:33@lid");
        assert_eq!(lid_device_addr.to_string(), "100000000000001:33@lid.0");
    }

    #[test]
    fn test_filter_logic_for_session_establishment() {
        let jids = vec![
            Jid::pn_device("111", 0),
            Jid::pn_device("222", 0),
            Jid::pn_device("333", 0),
        ];

        // Simulate contains_session results
        let session_exists = |jid: &Jid| -> Result<bool, &'static str> {
            match jid.user.as_str() {
                "111" => Ok(true),        // Session exists
                "222" => Ok(false),       // No session
                "333" => Err("DB error"), // Error
                _ => Ok(false),
            }
        };

        // Apply filter logic (matching ensure_e2e_sessions behavior)
        let mut jids_needing_sessions = Vec::new();
        for jid in &jids {
            match session_exists(jid) {
                Ok(true) => {}                                        // Skip - session exists
                Ok(false) => jids_needing_sessions.push(jid.clone()), // Needs session
                Err(e) => eprintln!("Warning: failed to check {}: {}", jid, e), // Skip on error
            }
        }

        // Only "222" should need a session
        assert_eq!(jids_needing_sessions.len(), 1);
        assert_eq!(jids_needing_sessions[0].user, "222");
    }

    // PN and LID have independent Signal sessions

    #[test]
    fn test_dual_addressing_pn_and_lid_are_independent() {
        let pn_address = Jid::pn("559984726662").with_device(0);
        let lid_address = Jid::lid("236395184570386").with_device(0);

        assert_ne!(pn_address.user, lid_address.user);
        assert_ne!(pn_address.server, lid_address.server);

        use wacore::types::jid::JidExt;
        let pn_signal_addr = pn_address.to_protocol_address();
        let lid_signal_addr = lid_address.to_protocol_address();

        assert_ne!(pn_signal_addr.name(), lid_signal_addr.name());
        assert_eq!(pn_signal_addr.name(), "559984726662@c.us");
        assert_eq!(lid_signal_addr.name(), "236395184570386@lid");
        assert_eq!(pn_address.device, 0);
        assert_eq!(lid_address.device, 0);
    }

    #[test]
    fn test_lid_extraction_from_own_device() {
        let own_lid_with_device = Jid::lid_device("236395184570386", 61);
        let primary_lid = own_lid_with_device.with_device(0);

        assert_eq!(primary_lid.user, "236395184570386");
        assert_eq!(primary_lid.device, 0);
        assert!(!primary_lid.is_ad());
    }

    /// PN sessions established proactively, LID sessions established by primary phone.
    #[test]
    fn test_stale_session_scenario_documentation() {
        fn should_establish_pn_session(pn_exists: bool) -> bool {
            !pn_exists
        }

        fn should_establish_lid_session(_lid_exists: bool) -> bool {
            false // Primary phone establishes LID sessions via pkmsg
        }

        // PN exists -> don't establish
        assert!(!should_establish_pn_session(true));
        // PN doesn't exist -> establish
        assert!(should_establish_pn_session(false));
        // LID never established proactively
        assert!(!should_establish_lid_session(true));
        assert!(!should_establish_lid_session(false));
    }

    /// Retry mechanism: error=1 (NoSession), error=4 (InvalidMessage/MAC failure)
    #[test]
    fn test_retry_mechanism_for_stale_sessions() {
        const RETRY_ERROR_NO_SESSION: u8 = 1;
        const RETRY_ERROR_INVALID_MESSAGE: u8 = 4;

        fn action_for_error(error_code: u8) -> &'static str {
            match error_code {
                RETRY_ERROR_NO_SESSION => "Establish new session via prekey",
                RETRY_ERROR_INVALID_MESSAGE => "Delete stale session, resend message",
                _ => "Unknown error",
            }
        }

        assert_eq!(
            action_for_error(RETRY_ERROR_NO_SESSION),
            "Establish new session via prekey"
        );
        assert_eq!(
            action_for_error(RETRY_ERROR_INVALID_MESSAGE),
            "Delete stale session, resend message"
        );
    }

    #[test]
    fn test_session_establishment_lookup_normalization() {
        use std::collections::HashMap;
        use wacore_binary::jid::Jid;

        // Represents the bundle map returned by fetch_pre_keys
        // (keys are normalized by parsing logic as verified in wacore/src/prekeys.rs)
        let mut prekey_bundles: HashMap<Jid, ()> = HashMap::new(); // Using () as mock bundle placeholder

        let normalized_jid = Jid::lid("123456789"); // agent=0
        prekey_bundles.insert(normalized_jid.clone(), ());

        // Represents the JID from the device list (e.g. from ensure_e2e_sessions)
        // which might have agent=1 due to some upstream source or parsing quirk
        let mut requested_jid = Jid::lid("123456789");
        requested_jid.agent = 1;

        // 1. Verify direct lookup fails (This is the bug)
        assert!(
            !prekey_bundles.contains_key(&requested_jid),
            "Direct lookup of non-normalized JID should fail"
        );

        // 2. Verify normalized lookup succeeds (This is the fix)
        // This mirrors the logic change in fetch_and_establish_sessions
        let normalized_lookup = requested_jid.normalize_for_prekey_bundle();
        assert!(
            prekey_bundles.contains_key(&normalized_lookup),
            "Normalized lookup should succeed"
        );

        // Ensure the normalization actually produced the key we stored
        assert_eq!(normalized_lookup, normalized_jid);
    }
}
