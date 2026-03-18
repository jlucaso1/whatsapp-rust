use super::traits::StanzaHandler;
use crate::client::Client;
use crate::lid_pn_cache::LearningSource;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::sync::Arc;
use wacore::stanza::business::BusinessNotification;
use wacore::stanza::devices::DeviceNotification;
use wacore::stanza::groups::{GroupNotification, GroupNotificationAction};
use wacore::store::traits::{DeviceInfo, DeviceListRecord};
use wacore::types::events::{
    BusinessStatusUpdate, BusinessUpdateType, ContactNumberChanged, ContactSyncRequested,
    ContactUpdated, DeviceListUpdate, DeviceNotificationInfo, GroupUpdate, PictureUpdate,
    UserAboutUpdate,
};
use wacore_binary::jid::{Jid, JidExt};
use wacore_binary::{jid::SERVER_JID, node::Node};

/// Handler for `<notification>` stanzas.
///
/// Processes various notification types including:
/// - Encrypt notifications (key upload requests)
/// - Server sync notifications
/// - Account sync notifications (push name updates)
/// - Device notifications (device add/remove/update)
#[derive(Default)]
pub struct NotificationHandler;

#[async_trait]
impl StanzaHandler for NotificationHandler {
    fn tag(&self) -> &'static str {
        "notification"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        handle_notification_impl(&client, &node).await;
        true
    }
}

async fn handle_notification_impl(client: &Arc<Client>, node: &Node) {
    let notification_type = node.attrs().optional_string("type");
    let notification_type = notification_type.as_deref().unwrap_or_default();

    match notification_type {
        "encrypt" => {
            if node.attrs.get("from").is_some_and(|v| v == SERVER_JID) {
                // Dispatch based on first child tag, matching WA Web's handleEncryptNotification.
                // "count" → handlePreKeyLow, "digest" → handleDigestKey
                let first_child_tag = node
                    .children()
                    .and_then(|c| c.first().map(|n| n.tag.clone()));

                match first_child_tag.as_deref() {
                    Some("count") => {
                        handle_prekey_low(client).await;
                    }
                    Some("digest") => {
                        handle_digest_key(client);
                    }
                    other => {
                        warn!("Unhandled encrypt notification child: {:?}", other);
                    }
                }
            }
        }
        "server_sync" => {
            // Server sync notifications inform us of app state changes from other devices.
            // Matches WhatsApp Web's handleServerSyncNotification which calls
            // markCollectionsForSync() with the parsed collection names.
            use std::str::FromStr;
            use wacore::appstate::patch_decode::WAPatchName;

            let mut collections = Vec::new();
            if let Some(children) = node.children() {
                for collection_node in children.iter().filter(|c| c.tag == "collection") {
                    let name_cow = collection_node.attrs().optional_string("name");
                    let name_str = name_cow.as_deref().unwrap_or("<unknown>");
                    let server_version =
                        collection_node.attrs().optional_u64("version").unwrap_or(0);
                    debug!(
                        target: "Client/AppState",
                        "Received server_sync for collection '{}' version {}",
                        name_str, server_version
                    );
                    if let Ok(patch_name) = WAPatchName::from_str(name_str)
                        && !matches!(patch_name, WAPatchName::Unknown)
                    {
                        collections.push((patch_name, server_version));
                    }
                }
            }

            if !collections.is_empty() {
                let client_clone = client.clone();
                let generation = client
                    .connection_generation
                    .load(std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    // Check if connection was replaced before starting sync
                    if client_clone
                        .connection_generation
                        .load(std::sync::atomic::Ordering::SeqCst)
                        != generation
                    {
                        log::debug!(target: "Client/AppState", "server_sync task cancelled: connection generation changed");
                        return;
                    }

                    // Filter by version comparison before syncing.
                    // Matches WA Web's markCollectionsForSync version comparison filter.
                    let backend = client_clone.persistence_manager.backend();
                    let mut to_sync = Vec::new();
                    for (name, server_version) in collections {
                        if server_version > 0 {
                            match backend.get_version(name.as_str()).await {
                                Ok(state) if state.version >= server_version => {
                                    debug!(
                                        target: "Client/AppState",
                                        "Skipping server_sync for {:?}: local version {} >= server version {}",
                                        name, state.version, server_version
                                    );
                                    continue;
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    warn!(
                                        target: "Client/AppState",
                                        "Failed to get local version for {:?}: {e}, syncing anyway", name
                                    );
                                }
                            }
                        }
                        to_sync.push(name);
                    }

                    if !to_sync.is_empty()
                        && let Err(e) = client_clone.sync_collections_batched(to_sync).await
                    {
                        warn!(
                            target: "Client/AppState",
                            "Failed to batch sync app state from server_sync: {e}"
                        );
                    }
                });
            }
        }
        "account_sync" => {
            // Handle push name updates
            if let Some(new_push_name) = node.attrs().optional_string("pushname") {
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name.to_string())
                    .await;
            }

            // Handle device list updates (when a new device is paired)
            // Matches WhatsApp Web's handleAccountSyncNotification for DEVICES type
            if let Some(devices_node) = node.get_optional_child_by_tag(&["devices"]) {
                handle_account_sync_devices(client, node, devices_node).await;
            }
        }
        "devices" => {
            // Handle device list change notifications (WhatsApp Web: handleDevicesNotification)
            // These are sent when a user adds, removes, or updates a device
            handle_devices_notification(client, node).await;
        }
        "link_code_companion_reg" => {
            // Handle pair code notification (stage 2 of pair code authentication)
            // This is sent when the user enters the code on their phone
            crate::pair_code::handle_pair_code_notification(client, node).await;
        }
        "business" => {
            // Handle business notification (WhatsApp Web: handleBusinessNotification)
            // Notifies about business account status changes: verified name, profile, removal
            handle_business_notification(client, node).await;
        }
        "picture" => {
            // Handle profile picture change notifications (WhatsApp Web: WAWebHandleProfilePicNotification)
            handle_picture_notification(client, node);
        }
        "privacy_token" => {
            // Handle incoming trusted contact privacy token notifications.
            // Matches WhatsApp Web's WAWebHandlePrivacyTokenNotification.
            handle_privacy_token_notification(client, node).await;
        }
        "status" => {
            // Handle status/about text change notifications (WhatsApp Web: WAWebHandleAboutNotification)
            handle_status_notification(client, node);
        }
        "contacts" => {
            handle_contacts_notification(client, node).await;
        }
        "w:gp2" => {
            handle_group_notification(client, node).await;
        }
        "disappearing_mode" => {
            // WA Web: WAWebHandleDisappearingModeNotification →
            // WAWebUpdateDisappearingModeForContact.
            // Parses <disappearing_mode duration="..." t="..."/> child,
            // updates the contact's default ephemeral setting.
            handle_disappearing_mode_notification(client, node);
        }
        "newsletter" => {
            handle_newsletter_notification(client, node);
        }
        _ => {
            debug!("Unhandled notification type '{notification_type}', dispatching raw event");
            client
                .core
                .event_bus
                .dispatch(&Event::Notification(node.clone()));
        }
    }
}

/// Handle encrypt/count notification (PreKey Low).
///
/// Matches WA Web's `WAWebHandlePreKeyLow`:
/// 1. Mark `server_has_prekeys = false`
/// 2. Wait for offline delivery to complete
/// 3. Acquire dedup lock (prevents concurrent uploads)
/// 4. Upload prekeys with Fibonacci retry
async fn handle_prekey_low(client: &Arc<Client>) {
    // Mark server as not having our prekeys
    client
        .server_has_prekeys
        .store(false, std::sync::atomic::Ordering::Relaxed);

    let client_clone = client.clone();
    tokio::spawn(async move {
        // Wait for offline delivery to complete first (matches WA Web's waitForOfflineDeliveryEnd).
        // Done BEFORE acquiring the lock so the lock isn't held during an
        // indefinite wait that could block digest-key or other upload paths.
        client_clone.wait_for_offline_delivery_end().await;

        // Bail if disconnected during offline delivery wait
        if !client_clone
            .is_logged_in
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            debug!("Pre-key upload skipped: disconnected during offline delivery wait");
            return;
        }

        // Serialize upload — prevents concurrent uploads from count + digest paths
        let _guard = client_clone.prekey_upload_lock.lock().await;

        // Dedup: if a previous upload already succeeded, skip
        if client_clone
            .server_has_prekeys
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            debug!("Pre-key upload already completed by another task, skipping");
            return;
        }

        if let Err(e) = client_clone.upload_pre_keys_with_retry(false).await {
            warn!(
                "Failed to upload pre-keys after prekey_low notification: {:?}",
                e
            );
        }
    });
}

/// Handle encrypt/digest notification (Digest Key validation).
///
/// Matches WA Web's `WAWebHandleDigestKey`:
/// Queries server for key bundle digest, validates SHA-1 hash locally,
/// re-uploads if mismatch or missing.
///
/// Acquires `prekey_upload_lock` to serialize with the count-based upload path,
/// preventing concurrent uploads that could race on prekey ID allocation.
fn handle_digest_key(client: &Arc<Client>) {
    let client_clone = client.clone();
    tokio::spawn(async move {
        let _guard = client_clone.prekey_upload_lock.lock().await;
        if let Err(e) = client_clone.validate_digest_key().await {
            warn!("Digest key validation failed: {:?}", e);
        }
    });
}

/// Handle device list change notifications.
/// Matches WhatsApp Web's WAWebHandleDeviceNotification.handleDevicesNotification().
///
/// Device notifications have the structure:
/// ```xml
/// <notification type="devices" from="user@s.whatsapp.net">
///   <add device_hash="..."> or <remove device_hash="..."> or <update hash="...">
///     <device jid="user:device@server"/>
///     <key-index-list ts="..."/>
///   </add/remove/update>
/// </notification>
/// ```
async fn handle_devices_notification(client: &Arc<Client>, node: &Node) {
    // Parse using type-safe struct
    let notification = match DeviceNotification::try_parse(node) {
        Ok(n) => n,
        Err(e) => {
            warn!("Failed to parse device notification: {e}");
            return;
        }
    };

    // Learn LID-PN mapping if present
    if let Some((lid, pn)) = notification.lid_pn_mapping()
        && let Err(e) = client
            .add_lid_pn_mapping(lid, pn, LearningSource::DeviceNotification)
            .await
    {
        warn!("Failed to add LID-PN mapping from device notification: {e}");
    }

    // Process the single operation (per WhatsApp Web: one operation per notification).
    // Granularly patch caches instead of invalidating — matches WA Web's
    // bulkCreateOrReplace pattern and avoids a usync IQ round-trip.
    let op = &notification.operation;
    debug!(
        "Device notification: user={}, type={:?}, devices={:?}",
        notification.user(),
        op.operation_type,
        op.device_ids()
    );

    match op.operation_type {
        wacore::stanza::devices::DeviceNotificationType::Add => {
            for device in &op.devices {
                client
                    .patch_device_add(notification.user(), &notification.from, device)
                    .await;
            }
        }
        wacore::stanza::devices::DeviceNotificationType::Remove => {
            for device in &op.devices {
                client
                    .patch_device_remove(
                        notification.user(),
                        &notification.from,
                        device.device_id(),
                    )
                    .await;
            }
        }
        wacore::stanza::devices::DeviceNotificationType::Update => {
            if op.devices.is_empty() {
                // Hash-only update without device list — fall back to
                // invalidation so the next read rehydrates from the server.
                client.invalidate_device_cache(notification.user()).await;
            } else {
                for device in &op.devices {
                    client
                        .patch_device_update(notification.user(), device)
                        .await;
                }
            }
        }
    }

    // Dispatch event to notify application layer
    let event = Event::DeviceListUpdate(DeviceListUpdate {
        user: notification.from.clone(),
        lid_user: notification.lid_user.clone(),
        update_type: op.operation_type.into(),
        devices: op
            .devices
            .iter()
            .map(|d| DeviceNotificationInfo {
                device_id: d.device_id(),
                key_index: d.key_index,
            })
            .collect(),
        key_index: op.key_index.clone(),
        contact_hash: op.contact_hash.clone(),
    });
    client.core.event_bus.dispatch(&event);
}

/// Parsed device info from account_sync notification
struct AccountSyncDevice {
    jid: Jid,
    key_index: Option<u32>,
}

/// Parse devices from account_sync notification's <devices> child.
///
/// Example structure:
/// ```xml
/// <devices dhash="2:FnEWjS13">
///   <device jid="15551234567@s.whatsapp.net"/>
///   <device jid="15551234567:64@s.whatsapp.net" key-index="2"/>
///   <key-index-list ts="1766612162"><!-- bytes --></key-index-list>
/// </devices>
/// ```
fn parse_account_sync_device_list(devices_node: &Node) -> Vec<AccountSyncDevice> {
    let Some(children) = devices_node.children() else {
        return Vec::new();
    };

    children
        .iter()
        .filter(|n| n.tag == "device")
        .filter_map(|n| {
            let jid = n.attrs().optional_jid("jid")?;
            let key_index = n.attrs().optional_u64("key-index").map(|v| v as u32);
            Some(AccountSyncDevice { jid, key_index })
        })
        .collect()
}

/// Handle account_sync notification with <devices> child.
///
/// This is sent when devices are added/removed from OUR account (e.g., pairing a new WhatsApp Web).
/// Matches WhatsApp Web's `handleAccountSyncNotification` for `AccountSyncType.DEVICES`.
///
/// Key behaviors:
/// 1. Check if notification is for our own account (isSameAccountAndAddressingMode)
/// 2. Parse device list from notification
/// 3. Update device registry with new device list
/// 4. Does NOT trigger app state sync (that's handled by server_sync)
async fn handle_account_sync_devices(client: &Arc<Client>, node: &Node, devices_node: &Node) {
    // Extract the "from" JID - this is the account the notification is about
    let from_jid = match node.attrs().optional_jid("from") {
        Some(jid) => jid,
        None => {
            warn!(target: "Client/AccountSync", "account_sync devices missing 'from' attribute");
            return;
        }
    };

    // Get our own JIDs (PN and LID) to verify this is about our account
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let own_pn = device_snapshot.pn.as_ref();
    let own_lid = device_snapshot.lid.as_ref();

    // Check if notification is about our own account
    // Matches WhatsApp Web's isSameAccountAndAddressingMode check
    let is_own_account = own_pn.is_some_and(|pn| pn.is_same_user_as(&from_jid))
        || own_lid.is_some_and(|lid| lid.is_same_user_as(&from_jid));

    if !is_own_account {
        // WhatsApp Web logs "wid-is-not-self" error in this case
        warn!(
            target: "Client/AccountSync",
            "Received account_sync devices for non-self user: {} (our PN: {:?}, LID: {:?})",
            from_jid,
            own_pn.map(|j| j.user.as_str()),
            own_lid.map(|j| j.user.as_str())
        );
        return;
    }

    // Parse device list from notification
    let devices = parse_account_sync_device_list(devices_node);
    if devices.is_empty() {
        debug!(target: "Client/AccountSync", "account_sync devices list is empty");
        return;
    }

    // Extract dhash (device hash) for cache validation
    let dhash = devices_node
        .attrs()
        .optional_string("dhash")
        .map(|s| s.into_owned());

    // Get timestamp from notification
    let timestamp = node.attrs().optional_u64("t").unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }) as i64;

    // Build DeviceListRecord for storage
    // Note: update_device_list() will automatically store under LID if mapping is known
    let device_list = DeviceListRecord {
        user: from_jid.user.clone(),
        devices: devices
            .iter()
            .map(|d| DeviceInfo {
                device_id: d.jid.device as u32,
                key_index: d.key_index,
            })
            .collect(),
        timestamp,
        phash: dhash,
    };

    if let Err(e) = client.update_device_list(device_list).await {
        warn!(
            target: "Client/AccountSync",
            "Failed to update device list from account_sync: {}",
            e
        );
        return;
    }

    info!(
        target: "Client/AccountSync",
        "Updated own device list from account_sync: {} devices (user: {})",
        devices.len(),
        from_jid.user
    );

    // Log individual devices at debug level
    for device in &devices {
        debug!(
            target: "Client/AccountSync",
            "  Device: {} (key-index: {:?})",
            device.jid,
            device.key_index
        );
    }
}

/// Handle incoming privacy_token notification.
///
/// Stores trusted contact tokens from contacts. Matches WhatsApp Web's
/// `WAWebHandlePrivacyTokenNotification`.
///
/// Structure:
/// ```xml
/// <notification type="privacy_token" from="user@s.whatsapp.net" sender_lid="user@lid">
///   <tokens>
///     <token type="trusted_contact" t="1707000000"><!-- bytes --></token>
///   </tokens>
/// </notification>
/// ```
async fn handle_privacy_token_notification(client: &Arc<Client>, node: &Node) {
    use wacore::iq::tctoken::parse_privacy_token_notification;
    use wacore::store::traits::TcTokenEntry;

    // Resolve the sender to a LID JID for storage.
    // WA Web uses `sender_lid` attr if present, otherwise resolves from `from`.
    let sender_lid = node
        .attrs()
        .optional_jid("sender_lid")
        .map(|j| j.user.clone());

    let sender_lid = match sender_lid {
        Some(lid) if !lid.is_empty() => lid,
        _ => {
            // Fall back to resolving from the `from` JID via LID-PN cache
            let from_jid = match node.attrs().optional_jid("from") {
                Some(jid) => jid,
                None => {
                    warn!(target: "Client/TcToken", "privacy_token notification missing 'from' attribute");
                    return;
                }
            };

            if from_jid.is_lid() {
                from_jid.user.clone()
            } else {
                // Try to resolve phone number to LID
                match client.lid_pn_cache.get_current_lid(&from_jid.user).await {
                    Some(lid) => lid,
                    None => {
                        debug!(
                            target: "Client/TcToken",
                            "Cannot resolve LID for privacy_token sender {}, storing under PN",
                            from_jid
                        );
                        from_jid.user.clone()
                    }
                }
            }
        }
    };

    // Parse the token data from the notification
    let received_tokens = match parse_privacy_token_notification(node) {
        Ok(tokens) => tokens,
        Err(e) => {
            warn!(target: "Client/TcToken", "Failed to parse privacy_token notification: {e}");
            return;
        }
    };

    if received_tokens.is_empty() {
        debug!(target: "Client/TcToken", "privacy_token notification had no trusted_contact tokens");
        return;
    }

    let backend = client.persistence_manager.backend();

    for received in &received_tokens {
        match backend.get_tc_token(&sender_lid).await {
            Ok(Some(existing)) => {
                // Timestamp monotonicity guard: only store if incoming >= existing
                if received.timestamp < existing.token_timestamp {
                    debug!(
                        target: "Client/TcToken",
                        "Skipping older token for {} (incoming={}, existing={})",
                        sender_lid, received.timestamp, existing.token_timestamp
                    );
                    continue;
                }

                // Preserve existing sender_timestamp when updating token
                let entry = TcTokenEntry {
                    token: received.token.clone(),
                    token_timestamp: received.timestamp,
                    sender_timestamp: existing.sender_timestamp,
                };

                if let Err(e) = backend.put_tc_token(&sender_lid, &entry).await {
                    warn!(target: "Client/TcToken", "Failed to update tc_token for {}: {e}", sender_lid);
                } else {
                    debug!(target: "Client/TcToken", "Updated tc_token for {} (t={})", sender_lid, received.timestamp);
                }
            }
            Ok(None) => {
                // New token — no existing entry
                let entry = TcTokenEntry {
                    token: received.token.clone(),
                    token_timestamp: received.timestamp,
                    sender_timestamp: None,
                };

                if let Err(e) = backend.put_tc_token(&sender_lid, &entry).await {
                    warn!(target: "Client/TcToken", "Failed to store tc_token for {}: {e}", sender_lid);
                } else {
                    debug!(target: "Client/TcToken", "Stored new tc_token for {} (t={})", sender_lid, received.timestamp);
                }
            }
            Err(e) => {
                warn!(target: "Client/TcToken", "Failed to read tc_token for {}: {e}, skipping", sender_lid);
            }
        }
    }
}

/// Handle business notification (WhatsApp Web: `WAWebHandleBusinessNotification`).
async fn handle_business_notification(client: &Arc<Client>, node: &Node) {
    let notification = match BusinessNotification::try_parse(node) {
        Ok(n) => n,
        Err(e) => {
            warn!(target: "Client/Business", "Failed to parse business notification: {e}");
            return;
        }
    };

    debug!(
        target: "Client/Business",
        "Business notification: from={}, type={}, jid={:?}",
        notification.from,
        notification.notification_type,
        notification.jid
    );

    let update_type = BusinessUpdateType::from(notification.notification_type.clone());
    let verified_name = notification
        .verified_name
        .as_ref()
        .and_then(|vn| vn.name.clone());

    let event = Event::BusinessStatusUpdate(BusinessStatusUpdate {
        jid: notification.from.clone(),
        update_type,
        timestamp: notification.timestamp,
        target_jid: notification.jid.clone(),
        hash: notification.hash.clone(),
        verified_name,
        product_ids: notification.product_ids.clone(),
        collection_ids: notification.collection_ids.clone(),
        subscriptions: notification.subscriptions.clone(),
    });

    match notification.notification_type {
        wacore::stanza::business::BusinessNotificationType::RemoveJid
        | wacore::stanza::business::BusinessNotificationType::RemoveHash => {
            info!(
                target: "Client/Business",
                "Contact {} is no longer a business account",
                notification.from
            );
        }
        wacore::stanza::business::BusinessNotificationType::VerifiedNameJid
        | wacore::stanza::business::BusinessNotificationType::VerifiedNameHash => {
            if let Some(name) = &notification
                .verified_name
                .as_ref()
                .and_then(|vn| vn.name.as_ref())
            {
                info!(
                    target: "Client/Business",
                    "Contact {} verified business name: {}",
                    notification.from,
                    name
                );
            }
        }
        wacore::stanza::business::BusinessNotificationType::Profile
        | wacore::stanza::business::BusinessNotificationType::ProfileHash => {
            debug!(
                target: "Client/Business",
                "Contact {} business profile updated (hash: {:?})",
                notification.from,
                notification.hash
            );
        }
        _ => {}
    }

    client.core.event_bus.dispatch(&event);
}

/// Handle profile picture change notifications.
///
/// Matches WhatsApp Web's `WAWebHandleProfilePicNotification`.
///
/// Structure:
/// ```xml
/// <notification type="picture" from="user@s.whatsapp.net" t="1234567890" id="...">
///   <set jid="user@s.whatsapp.net" id="pic_id" author="author@s.whatsapp.net"/>
/// </notification>
/// ```
///
/// Or for removal (no child or `<delete>` child):
/// ```xml
/// <notification type="picture" from="user@s.whatsapp.net" t="1234567890" id="...">
///   <delete jid="user@s.whatsapp.net"/>
/// </notification>
/// ```
fn handle_picture_notification(client: &Arc<Client>, node: &Node) {
    let from = match node.attrs().optional_jid("from") {
        Some(jid) => jid,
        None => {
            warn!(target: "Client/Picture", "picture notification missing 'from' attribute");
            return;
        }
    };

    let timestamp = node
        .attrs()
        .optional_u64("t")
        .map(|t| chrono::DateTime::from_timestamp(t as i64, 0).unwrap_or_else(chrono::Utc::now))
        .unwrap_or_else(chrono::Utc::now);

    // Look for <set>, <delete>, or <request> child to determine the action.
    // WhatsApp Web has two formats:
    // - With `jid` attr: direct update for that JID
    // - With `hash` attr (no `jid`): side contact, resolved via contact hash lookup
    let (jid, author, removed, picture_id) = if let Some(set_node) = node.get_optional_child("set")
    {
        let jid = set_node.attrs().optional_jid("jid").unwrap_or_else(|| {
            if set_node.attrs().optional_string("hash").is_some() {
                debug!(
                    target: "Client/Picture",
                    "Hash-based picture notification (no jid), using from={}", from
                );
            }
            from.clone()
        });
        let author = set_node.attrs().optional_jid("author");
        let pic_id = set_node
            .attrs()
            .optional_string("id")
            .map(|s| s.to_string());
        (jid, author, false, pic_id)
    } else if let Some(delete_node) = node.get_optional_child("delete") {
        let jid = delete_node
            .attrs()
            .optional_jid("jid")
            .unwrap_or_else(|| from.clone());
        let author = delete_node.attrs().optional_jid("author");
        (jid, author, true, None)
    } else {
        // No <set> or <delete> child. Check if notification has no children at all,
        // which WhatsApp uses as a deletion signal (bare notification).
        let children = node.children().map(|c| c.len()).unwrap_or(0);
        if children == 0 {
            let jid = node
                .attrs()
                .optional_jid("jid")
                .unwrap_or_else(|| from.clone());
            let author = node.attrs().optional_jid("author");
            (jid, author, true, None)
        } else {
            // Unknown child type (e.g., "request", "set_avatar") — log and skip
            let child_tag = node
                .children()
                .and_then(|c| c.first().map(|n| n.tag.as_ref()));
            debug!(
                target: "Client/Picture",
                "Ignoring picture notification with child {:?} from {}", child_tag, from
            );
            return;
        }
    };

    debug!(
        target: "Client/Picture",
        "Picture {}: jid={}, author={:?}, pic_id={:?}",
        if removed { "removed" } else { "updated" },
        jid, author, picture_id
    );

    let event = Event::PictureUpdate(PictureUpdate {
        jid,
        author,
        timestamp,
        removed,
        picture_id,
    });
    client.core.event_bus.dispatch(&event);
}

/// Handle status/about text change notifications.
///
/// Matches WhatsApp Web's `WAWebHandleAboutNotification`.
///
/// Structure:
/// ```xml
/// <notification type="status" from="user@s.whatsapp.net" t="1234567890" notify="PushName">
///   <set>new status text</set>
/// </notification>
/// ```
fn handle_status_notification(client: &Arc<Client>, node: &Node) {
    let from = match node.attrs().optional_jid("from") {
        Some(jid) => jid,
        None => {
            warn!(target: "Client/Status", "status notification missing 'from' attribute");
            return;
        }
    };

    let timestamp = node
        .attrs()
        .optional_u64("t")
        .map(|t| chrono::DateTime::from_timestamp(t as i64, 0).unwrap_or_else(chrono::Utc::now))
        .unwrap_or_else(chrono::Utc::now);

    if let Some(set_node) = node.get_optional_child("set") {
        let status_text = match &set_node.content {
            Some(wacore_binary::node::NodeContent::String(s)) => s.clone(),
            Some(wacore_binary::node::NodeContent::Bytes(b)) => {
                String::from_utf8_lossy(b).into_owned()
            }
            _ => String::new(),
        };

        debug!(
            target: "Client/Status",
            "Status update from {} (length={})", from, status_text.len()
        );

        let event = Event::UserAboutUpdate(UserAboutUpdate {
            jid: from,
            status: status_text,
            timestamp,
        });
        client.core.event_bus.dispatch(&event);
    } else {
        debug!(
            target: "Client/Status",
            "Status notification from {} without <set> child, ignoring", from
        );
    }
}

fn notification_timestamp(node: &Node) -> chrono::DateTime<chrono::Utc> {
    node.attrs()
        .optional_u64("t")
        .map(|t| chrono::DateTime::from_timestamp(t as i64, 0).unwrap_or_else(chrono::Utc::now))
        .unwrap_or_else(chrono::Utc::now)
}

/// Learn LID-PN mappings from a contacts modify notification.
///
/// WA Web (`WAWebHandleContactNotification` → `WAWebDBCreateLidPnMappings`):
/// The `<modify>` child carries four attributes:
/// - `old` / `new` — old and new PN (phone number) JIDs
/// - `old_lid` / `new_lid` — old and new LID JIDs (optional)
///
/// When both `old_lid` and `new_lid` are present, WA Web creates two mappings:
/// `{ lid: old_lid, pn: old }` and `{ lid: new_lid, pn: new }`.
async fn learn_contact_modify_mappings(
    client: &Arc<Client>,
    old_pn: &Jid,
    new_pn: &Jid,
    old_lid: Option<&Jid>,
    new_lid: Option<&Jid>,
) {
    // WA Web: createLidPnMappings({mappings:[{lid:oldLid,pn:oldJid},{lid:newLid,pn:newJid}]})
    if let (Some(old_lid), Some(new_lid)) = (old_lid, new_lid) {
        for (lid, pn) in [(old_lid, old_pn), (new_lid, new_pn)] {
            if let Err(e) = client
                .add_lid_pn_mapping(&lid.user, &pn.user, LearningSource::DeviceNotification)
                .await
            {
                warn!(
                    target: "Client/Contacts",
                    "Failed to add LID-PN mapping lid={} pn={}: {e}",
                    lid, pn
                );
            }
        }
    } else {
        debug!(
            target: "Client/Contacts",
            "Contacts modify without old_lid/new_lid, skipping LID-PN mapping (old={}, new={})",
            old_pn, new_pn
        );
    }
}

/// Handle contact change notifications.
///
/// WA Web: `WAWebHandleContactNotification`
///
/// These stanzas are sent as `<notification type="contacts">` with a single child action:
/// - `<update jid="..."/>` — contact profile changed. Consumers should
///   invalidate cached presence/profile picture (WA Web resets PresenceCollection
///   and refreshes profile pic thumb).
/// - `<modify old="..." new="..." old_lid="..." new_lid="..."/>` — contact
///   changed phone number. Creates LID-PN mappings when LID attrs present.
/// - `<sync after="..."/>` — server requests full contact re-sync.
/// - `<add .../>` or `<remove .../>` — lightweight roster changes (ACK only).
async fn handle_contacts_notification(client: &Arc<Client>, node: &Node) {
    let timestamp = notification_timestamp(node);

    let Some(child) = node.children().and_then(|children| children.first()) else {
        debug!(
            target: "Client/Contacts",
            "Ignoring contacts notification without child action"
        );
        return;
    };

    match child.tag.as_ref() {
        "update" => {
            let Some(jid) = child.attrs().optional_jid("jid") else {
                // WA Web: when no jid, tries hash-based lookup against local contacts
                // (first 4 chars of contact userhash). If no match, it's a no-op.
                // We don't maintain a userhash index, so just ack and move on.
                debug!(target: "Client/Contacts", "contacts update with hash but no jid, ignoring (hash={:?})",
                    child.attrs().optional_string("hash"));
                return;
            };

            debug!(target: "Client/Contacts", "Contact updated for {}", jid);
            client
                .core
                .event_bus
                .dispatch(&Event::ContactUpdated(ContactUpdated { jid, timestamp }));
        }
        "modify" => {
            // WA Web: old/new are PN JIDs, old_lid/new_lid are optional LID JIDs.
            let mut child_attrs = child.attrs();
            let Some(old_jid) = child_attrs.optional_jid("old") else {
                warn!(target: "Client/Contacts", "contacts modify missing 'old' attribute");
                return;
            };
            let Some(new_jid) = child_attrs.optional_jid("new") else {
                warn!(target: "Client/Contacts", "contacts modify missing 'new' attribute");
                return;
            };
            let old_lid = child_attrs.optional_jid("old_lid");
            let new_lid = child_attrs.optional_jid("new_lid");

            learn_contact_modify_mappings(
                client,
                &old_jid,
                &new_jid,
                old_lid.as_ref(),
                new_lid.as_ref(),
            )
            .await;

            debug!(
                target: "Client/Contacts",
                "Contact number changed: {} -> {} (old_lid={:?}, new_lid={:?})",
                old_jid, new_jid, old_lid, new_lid
            );
            client
                .core
                .event_bus
                .dispatch(&Event::ContactNumberChanged(ContactNumberChanged {
                    old_jid,
                    new_jid,
                    old_lid,
                    new_lid,
                    timestamp,
                }));
        }
        "sync" => {
            let after = child
                .attrs()
                .optional_u64("after")
                .and_then(|after| chrono::DateTime::from_timestamp(after as i64, 0));

            debug!(
                target: "Client/Contacts",
                "Contact sync requested after {:?}",
                after
            );
            client
                .core
                .event_bus
                .dispatch(&Event::ContactSyncRequested(ContactSyncRequested {
                    after,
                    timestamp,
                }));
        }
        "add" | "remove" => {
            debug!(
                target: "Client/Contacts",
                "Contact {} notification handled without extra work",
                child.tag
            );
        }
        other => {
            debug!(
                target: "Client/Contacts",
                "Ignoring unknown contacts notification child {:?}",
                other
            );
        }
    }
}

/// Handle w:gp2 group notifications.
///
/// Parses all child actions (participant changes, setting changes, metadata updates)
/// and dispatches typed `Event::GroupUpdate` events for each.
///
/// Reference: WhatsApp Web `WAWebHandleGroupNotification` (Ri7Gf1BxhsX.js:12556-12962)
async fn handle_group_notification(client: &Arc<Client>, node: &Node) {
    let notification = match GroupNotification::try_from_node(node) {
        Some(n) => n,
        None => {
            warn!(target: "Client/Group", "w:gp2 notification missing 'from' attribute");
            return;
        }
    };

    let timestamp = i64::try_from(notification.timestamp)
        .ok()
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
        .unwrap_or_else(chrono::Utc::now);

    for action in notification.actions {
        // Granularly patch group cache instead of invalidating — matches WA Web's
        // addParticipantInfo / removeParticipantInfo pattern and avoids a
        // group metadata IQ round-trip.
        match &action {
            GroupNotificationAction::Add { participants, .. } => {
                let group_cache = client.get_group_cache().await;
                if let Some(mut info) = group_cache.get(&notification.group_jid).await {
                    let new: Vec<_> = participants
                        .iter()
                        .map(|p| (p.jid.clone(), p.phone_number.clone()))
                        .collect();
                    info.add_participants(&new);
                    group_cache
                        .insert(notification.group_jid.clone(), info)
                        .await;
                    debug!(
                        target: "Client/Group",
                        "Patched group cache for {}: added {} participants",
                        notification.group_jid, participants.len()
                    );
                }
            }
            GroupNotificationAction::Remove { participants, .. } => {
                let group_cache = client.get_group_cache().await;
                if let Some(mut info) = group_cache.get(&notification.group_jid).await {
                    let users: Vec<&str> =
                        participants.iter().map(|p| p.jid.user.as_str()).collect();
                    info.remove_participants(&users);
                    group_cache
                        .insert(notification.group_jid.clone(), info)
                        .await;
                    debug!(
                        target: "Client/Group",
                        "Patched group cache for {}: removed {} participants",
                        notification.group_jid, participants.len()
                    );
                }
            }
            _ => {}
        }

        debug!(
            target: "Client/Group",
            "Group notification: group={}, action={}",
            notification.group_jid, action.tag_name()
        );

        client
            .core
            .event_bus
            .dispatch(&Event::GroupUpdate(GroupUpdate {
                group_jid: notification.group_jid.clone(),
                participant: notification.participant.clone(),
                participant_pn: notification.participant_pn.clone(),
                timestamp,
                is_lid_addressing_mode: notification.is_lid_addressing_mode,
                action,
            }));
    }

    // Also dispatch legacy generic notification for backward compatibility
    client
        .core
        .event_bus
        .dispatch(&Event::Notification(node.clone()));
}

/// Handle `<notification type="newsletter">` — live updates with reaction counts.
///
/// Format:
/// ```xml
/// <notification from="NL_JID" type="newsletter" id="..." t="...">
///   <live_updates>
///     <messages jid="NL_JID" t="...">
///       <message server_id="123" ...>
///         <reactions><reaction code="👍" count="3"/></reactions>
///       </message>
///     </messages>
///   </live_updates>
/// </notification>
/// ```
fn handle_newsletter_notification(client: &Arc<Client>, node: &Node) {
    use wacore::types::events::{
        NewsletterLiveUpdate, NewsletterLiveUpdateMessage, NewsletterLiveUpdateReaction,
    };

    let newsletter_jid = node.attrs().jid("from");

    let Some(live_updates) = node.get_optional_child("live_updates") else {
        debug!(
            "Newsletter notification without <live_updates>, dispatching raw: {}",
            wacore::xml::DisplayableNode(node)
        );
        client
            .core
            .event_bus
            .dispatch(&Event::Notification(node.clone()));
        return;
    };

    let Some(messages_node) = live_updates.get_optional_child("messages") else {
        return;
    };

    let mut messages = Vec::new();
    if let Some(children) = messages_node.children() {
        for msg_node in children.iter().filter(|n| n.tag.as_ref() == "message") {
            let server_id = msg_node
                .attrs
                .get("server_id")
                .map(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            let mut reactions = Vec::new();
            if let Some(reactions_node) = msg_node.get_optional_child("reactions")
                && let Some(reaction_children) = reactions_node.children()
            {
                for r in reaction_children
                    .iter()
                    .filter(|n| n.tag.as_ref() == "reaction")
                {
                    let code = r
                        .attrs
                        .get("code")
                        .map(|v| v.as_str().into_owned())
                        .unwrap_or_default();
                    let count = r
                        .attrs
                        .get("count")
                        .map(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0);
                    reactions.push(NewsletterLiveUpdateReaction { code, count });
                }
            }

            messages.push(NewsletterLiveUpdateMessage {
                server_id,
                reactions,
            });
        }
    }

    if !messages.is_empty() {
        client
            .core
            .event_bus
            .dispatch(&Event::NewsletterLiveUpdate(NewsletterLiveUpdate {
                newsletter_jid,
                messages,
            }));
    }
}

/// Handle `<notification type="disappearing_mode">` — a contact changed
/// their default disappearing messages setting.
///
/// WA Web: `WAWebHandleDisappearingModeNotification` parses the
/// `<disappearing_mode duration="..." t="..."/>` child and calls
/// `WAWebUpdateDisappearingModeForContact` which applies the update only
/// if the new timestamp is newer than the stored one.
///
/// We dispatch `Event::DisappearingModeChanged` and let consumers decide
/// how to persist/apply it.
fn handle_disappearing_mode_notification(client: &Arc<Client>, node: &Node) {
    let mut attrs = node.attrs();
    let from = attrs.jid("from").to_non_ad();

    let Some(dm_node) = node.get_optional_child("disappearing_mode") else {
        warn!(
            "disappearing_mode notification missing <disappearing_mode> child: {}",
            wacore::xml::DisplayableNode(node)
        );
        return;
    };

    let mut dm_attrs = dm_node.attrs();

    // WA Web: `t.attrInt("duration", 0)` — defaults to 0 (disabled).
    let duration = dm_attrs
        .optional_string("duration")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    // WA Web: `t.attrTime("t")` — required, no default.
    let Some(setting_timestamp) = dm_attrs
        .optional_string("t")
        .and_then(|s| s.parse::<u64>().ok())
    else {
        warn!(
            "disappearing_mode notification missing or invalid 't' attribute: {}",
            wacore::xml::DisplayableNode(node)
        );
        return;
    };

    debug!(
        "Disappearing mode changed for {}: duration={}s, t={}",
        from, duration, setting_timestamp
    );

    client
        .core
        .event_bus
        .dispatch(&Event::DisappearingModeChanged(
            wacore::types::events::DisappearingModeChanged {
                from,
                duration,
                setting_timestamp,
            },
        ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_test_client;
    use std::sync::{Arc, Mutex};
    use wacore::stanza::devices::DeviceNotificationType;
    use wacore::types::events::{DeviceListUpdateType, EventHandler};
    use wacore_binary::builder::NodeBuilder;

    #[derive(Default)]
    struct TestEventCollector {
        events: Mutex<Vec<Event>>,
    }

    impl EventHandler for TestEventCollector {
        fn handle_event(&self, event: &Event) {
            self.events
                .lock()
                .expect("collector mutex should not be poisoned")
                .push(event.clone());
        }
    }

    impl TestEventCollector {
        fn events(&self) -> Vec<Event> {
            self.events
                .lock()
                .expect("collector mutex should not be poisoned")
                .clone()
        }
    }

    #[test]
    fn test_parse_device_add_notification() {
        // Per WhatsApp Web: add operation has single device + key-index-list
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("add")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "1234567890:1@s.whatsapp.net")
                        .build(),
                    NodeBuilder::new("key-index-list")
                        .attr("ts", "1000")
                        .bytes(vec![0x01, 0x02, 0x03])
                        .build(),
                ])
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        assert_eq!(parsed.operation.operation_type, DeviceNotificationType::Add);
        assert_eq!(parsed.operation.device_ids(), vec![1]);
        // Verify key index info
        assert!(parsed.operation.key_index.is_some());
        assert_eq!(parsed.operation.key_index.as_ref().unwrap().timestamp, 1000);
    }

    #[test]
    fn test_parse_device_remove_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("remove")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "1234567890:3@s.whatsapp.net")
                        .build(),
                    NodeBuilder::new("key-index-list")
                        .attr("ts", "2000")
                        .build(),
                ])
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        assert_eq!(
            parsed.operation.operation_type,
            DeviceNotificationType::Remove
        );
        assert_eq!(parsed.operation.device_ids(), vec![3]);
    }

    #[test]
    fn test_parse_device_update_notification_with_hash() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("update")
                .attr("hash", "2:abcdef123456")
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        assert_eq!(
            parsed.operation.operation_type,
            DeviceNotificationType::Update
        );
        assert_eq!(
            parsed.operation.contact_hash,
            Some("2:abcdef123456".to_string())
        );
        // Update operations don't have devices (just hash for lookup)
        assert!(parsed.operation.devices.is_empty());
    }

    #[test]
    fn test_parse_empty_device_notification_fails() {
        // Per WhatsApp Web: at least one operation (add/remove/update) is required
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .build();

        let result = DeviceNotification::try_parse(&node);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing required operation")
        );
    }

    #[test]
    fn test_parse_multiple_operations_uses_priority() {
        // Per WhatsApp Web: only ONE operation is processed with priority remove > add > update
        // If both remove and add are present, remove should be processed
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([
                NodeBuilder::new("add")
                    .children([
                        NodeBuilder::new("device")
                            .attr("jid", "1234567890:5@s.whatsapp.net")
                            .build(),
                        NodeBuilder::new("key-index-list")
                            .attr("ts", "3000")
                            .build(),
                    ])
                    .build(),
                NodeBuilder::new("remove")
                    .children([
                        NodeBuilder::new("device")
                            .attr("jid", "1234567890:2@s.whatsapp.net")
                            .build(),
                        NodeBuilder::new("key-index-list")
                            .attr("ts", "3001")
                            .build(),
                    ])
                    .build(),
            ])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        // Should process remove, not add (priority: remove > add > update)
        assert_eq!(
            parsed.operation.operation_type,
            DeviceNotificationType::Remove
        );
        assert_eq!(parsed.operation.device_ids(), vec![2]);
    }

    #[test]
    fn test_device_list_update_type_from_notification_type() {
        assert_eq!(
            DeviceListUpdateType::from(DeviceNotificationType::Add),
            DeviceListUpdateType::Add
        );
        assert_eq!(
            DeviceListUpdateType::from(DeviceNotificationType::Remove),
            DeviceListUpdateType::Remove
        );
        assert_eq!(
            DeviceListUpdateType::from(DeviceNotificationType::Update),
            DeviceListUpdateType::Update
        );
    }

    // Tests for account_sync device parsing

    #[test]
    fn test_parse_account_sync_device_list_basic() {
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:FnEWjS13")
            .children([
                NodeBuilder::new("device")
                    .attr("jid", "15551234567@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "15551234567:64@s.whatsapp.net")
                    .attr("key-index", "2")
                    .build(),
            ])
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        assert_eq!(devices.len(), 2);

        // Primary device (device 0)
        assert_eq!(devices[0].jid.user, "15551234567");
        assert_eq!(devices[0].jid.device, 0);
        assert_eq!(devices[0].key_index, None);

        // Companion device (device 64)
        assert_eq!(devices[1].jid.user, "15551234567");
        assert_eq!(devices[1].jid.device, 64);
        assert_eq!(devices[1].key_index, Some(2));
    }

    #[test]
    fn test_parse_account_sync_device_list_with_key_index_list() {
        // Real-world structure includes <key-index-list> which should be ignored
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:FnEWjS13")
            .children([
                NodeBuilder::new("device")
                    .attr("jid", "15551234567@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "15551234567:77@s.whatsapp.net")
                    .attr("key-index", "15")
                    .build(),
                NodeBuilder::new("key-index-list")
                    .attr("ts", "1766612162")
                    .bytes(vec![0x01, 0x02, 0x03]) // Simulated signed bytes
                    .build(),
            ])
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        // Should only parse <device> tags, not <key-index-list>
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].jid.device, 0);
        assert_eq!(devices[1].jid.device, 77);
        assert_eq!(devices[1].key_index, Some(15));
    }

    #[test]
    fn test_parse_account_sync_device_list_empty() {
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:FnEWjS13")
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        assert!(devices.is_empty());
    }

    #[test]
    fn test_parse_account_sync_device_list_multiple_devices() {
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:XYZ123")
            .children([
                NodeBuilder::new("device")
                    .attr("jid", "1234567890@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "1234567890:1@s.whatsapp.net")
                    .attr("key-index", "1")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "1234567890:2@s.whatsapp.net")
                    .attr("key-index", "5")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "1234567890:3@s.whatsapp.net")
                    .attr("key-index", "10")
                    .build(),
            ])
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        assert_eq!(devices.len(), 4);

        // Verify device IDs are correctly parsed
        assert_eq!(devices[0].jid.device, 0);
        assert_eq!(devices[1].jid.device, 1);
        assert_eq!(devices[2].jid.device, 2);
        assert_eq!(devices[3].jid.device, 3);

        // Verify key indexes
        assert_eq!(devices[0].key_index, None);
        assert_eq!(devices[1].key_index, Some(1));
        assert_eq!(devices[2].key_index, Some(5));
        assert_eq!(devices[3].key_index, Some(10));
    }

    // ── disappearing_mode notification parsing tests ─────────────────────

    /// Helper: parse a disappearing_mode notification node the same way
    /// the handler does, returning `(duration, setting_timestamp)` or `None`
    /// on validation failure.
    fn parse_disappearing_mode(node: &Node) -> Option<(u32, u64)> {
        let dm_node = node.get_optional_child("disappearing_mode")?;
        let mut dm_attrs = dm_node.attrs();
        let duration = dm_attrs
            .optional_string("duration")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let setting_timestamp = dm_attrs
            .optional_string("t")
            .and_then(|s| s.parse::<u64>().ok())?;
        Some((duration, setting_timestamp))
    }

    #[test]
    fn test_parse_disappearing_mode_valid() {
        let node = NodeBuilder::new("notification")
            .attr("from", "5511999999999@s.whatsapp.net")
            .attr("type", "disappearing_mode")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("duration", "86400")
                .attr("t", "1773519041")
                .build()])
            .build();

        let (duration, ts) = parse_disappearing_mode(&node).expect("should parse");
        assert_eq!(duration, 86400);
        assert_eq!(ts, 1773519041);
    }

    #[test]
    fn test_parse_disappearing_mode_disabled() {
        // duration=0 means disappearing messages disabled
        let node = NodeBuilder::new("notification")
            .attr("from", "5511999999999@s.whatsapp.net")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("duration", "0")
                .attr("t", "1773519041")
                .build()])
            .build();

        let (duration, ts) = parse_disappearing_mode(&node).expect("should parse");
        assert_eq!(duration, 0, "duration=0 means disabled");
        assert_eq!(ts, 1773519041);
    }

    #[test]
    fn test_parse_disappearing_mode_missing_child() {
        // No <disappearing_mode> child → returns None
        let node = NodeBuilder::new("notification")
            .attr("from", "5511999999999@s.whatsapp.net")
            .attr("type", "disappearing_mode")
            .build();

        assert!(
            parse_disappearing_mode(&node).is_none(),
            "should return None when child element is missing"
        );
    }

    #[test]
    fn test_parse_disappearing_mode_missing_timestamp() {
        // Missing 't' attribute → returns None (required field)
        let node = NodeBuilder::new("notification")
            .attr("from", "5511999999999@s.whatsapp.net")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("duration", "86400")
                .build()])
            .build();

        assert!(
            parse_disappearing_mode(&node).is_none(),
            "should return None when 't' attribute is missing"
        );
    }

    #[test]
    fn test_parse_disappearing_mode_missing_duration_defaults_to_zero() {
        // Missing duration defaults to 0 (WA Web: attrInt("duration", 0))
        let node = NodeBuilder::new("notification")
            .attr("from", "5511999999999@s.whatsapp.net")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("t", "1773519041")
                .build()])
            .build();

        let (duration, _) = parse_disappearing_mode(&node).expect("should parse");
        assert_eq!(duration, 0, "missing duration should default to 0");
    }

    #[tokio::test]
    async fn test_contacts_update_dispatches_contact_updated_event() {
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        let node = NodeBuilder::new("notification")
            .attr("type", "contacts")
            .attr("from", "s.whatsapp.net")
            .attr("id", "contacts-update-1")
            .attr("t", "1773519041")
            .children([NodeBuilder::new("update")
                .attr("jid", "5511999999999@s.whatsapp.net")
                .build()])
            .build();

        handle_notification_impl(&client, &node).await;

        let events = collector.events();
        assert!(matches!(
            events.as_slice(),
            [Event::ContactUpdated(ContactUpdated { jid, .. })]
            if jid == &Jid::pn("5511999999999")
        ));
    }

    #[tokio::test]
    async fn test_contacts_modify_with_lid_creates_mappings() {
        // WA Web: old/new are PN JIDs, old_lid/new_lid are LID JIDs.
        // Creates two mappings: old_lid→old_pn AND new_lid→new_pn.
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        let node = NodeBuilder::new("notification")
            .attr("type", "contacts")
            .attr("from", "s.whatsapp.net")
            .attr("id", "contacts-modify-1")
            .children([NodeBuilder::new("modify")
                .attr("old", "5511999999999@s.whatsapp.net")
                .attr("new", "5511888888888@s.whatsapp.net")
                .attr("old_lid", "100000011111111@lid")
                .attr("new_lid", "100000022222222@lid")
                .build()])
            .build();

        handle_notification_impl(&client, &node).await;

        // Both LID-PN mappings should be created
        assert_eq!(
            client
                .lid_pn_cache
                .get_phone_number("100000011111111")
                .await,
            Some("5511999999999".to_string()),
            "old_lid should map to old PN"
        );
        assert_eq!(
            client
                .lid_pn_cache
                .get_phone_number("100000022222222")
                .await,
            Some("5511888888888".to_string()),
            "new_lid should map to new PN"
        );

        let events = collector.events();
        assert!(matches!(
            events.as_slice(),
            [Event::ContactNumberChanged(ContactNumberChanged {
                old_jid, new_jid, old_lid, new_lid, ..
            })]
            if old_jid == &Jid::pn("5511999999999")
                && new_jid == &Jid::pn("5511888888888")
                && old_lid.is_some()
                && new_lid.is_some()
        ));
    }

    #[tokio::test]
    async fn test_contacts_modify_without_lid_skips_mapping() {
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        let node = NodeBuilder::new("notification")
            .attr("type", "contacts")
            .attr("from", "s.whatsapp.net")
            .attr("id", "contacts-modify-2")
            .children([NodeBuilder::new("modify")
                .attr("old", "5511999999999@s.whatsapp.net")
                .attr("new", "5511888888888@s.whatsapp.net")
                .build()])
            .build();

        handle_notification_impl(&client, &node).await;

        // Event should still be dispatched, just without LID info
        assert_eq!(collector.events().len(), 1);
    }

    #[tokio::test]
    async fn test_contacts_sync_dispatches_contact_sync_requested_event() {
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        let node = NodeBuilder::new("notification")
            .attr("type", "contacts")
            .attr("from", "s.whatsapp.net")
            .attr("id", "contacts-sync-1")
            .children([NodeBuilder::new("sync").attr("after", "1773519041").build()])
            .build();

        handle_notification_impl(&client, &node).await;

        let events = collector.events();
        assert!(matches!(
            events.as_slice(),
            [Event::ContactSyncRequested(ContactSyncRequested { after, .. })]
            if after.is_some()
        ));
    }

    #[tokio::test]
    async fn test_contacts_add_remove_do_not_dispatch_events() {
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        for tag in ["add", "remove"] {
            let node = NodeBuilder::new("notification")
                .attr("type", "contacts")
                .attr("from", "s.whatsapp.net")
                .attr("id", format!("contacts-{tag}-1"))
                .children([NodeBuilder::new(tag).build()])
                .build();
            handle_notification_impl(&client, &node).await;
        }

        assert!(
            collector.events().is_empty(),
            "add/remove should not dispatch events"
        );
    }

    #[tokio::test]
    async fn test_contacts_empty_notification_ignored() {
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        // No child element
        let node = NodeBuilder::new("notification")
            .attr("type", "contacts")
            .attr("from", "s.whatsapp.net")
            .attr("id", "contacts-empty-1")
            .build();
        handle_notification_impl(&client, &node).await;

        assert!(
            collector.events().is_empty(),
            "empty contacts notification should not dispatch events"
        );
    }

    #[tokio::test]
    async fn test_contacts_update_hash_only_ignored() {
        // WA Web sends <update hash="Quvc"/> without jid when using hash-based lookup.
        // We don't maintain a userhash index, so this should be a no-op.
        let client = create_test_client().await;
        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());

        let node = NodeBuilder::new("notification")
            .attr("type", "contacts")
            .attr("from", "551199887766@s.whatsapp.net")
            .attr("id", "3251801952")
            .attr("t", "1773668072")
            .children([NodeBuilder::new("update").attr("hash", "Quvc").build()])
            .build();
        handle_notification_impl(&client, &node).await;

        assert!(
            collector.events().is_empty(),
            "hash-only update without jid should not dispatch events"
        );
    }
}
