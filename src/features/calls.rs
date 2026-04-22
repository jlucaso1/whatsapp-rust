//! High-level call placement pipeline.
//!
//! Orchestrates every pre-offer step WA Web does in
//! `WAWeb/Voip/StartCall.js` before the `<call>` stanza hits the wire.
//! Wraps the primitives in `src/calls/{manager,stanza,encryption}` +
//! `src/features/tctoken` so callers can invoke **one** method and get
//! a spec-compliant offer out.
//!
//! ## Pipeline steps (mirrors `StartCall.js` exactly)
//!
//! 1. **tcToken issue** (`tc_token().pre_call_send(peer)`) — avoids the
//!    `463 nack` from the privacy-token policy.
//! 2. **USync device list** with `context=voip` — forces the server to
//!    refresh the peer's device list so we don't miss a freshly linked
//!    device when fanning out.
//! 3. **Signal session warm-up** (`ensure_call_sessions_all(peer)`) —
//!    fetches prekey bundles for devices without a session.
//! 4. **Fan-out encrypt** — encrypt the random call key with Signal once
//!    per target device, producing one `<enc>` each.
//! 5. **Stanza build + send** — assemble the `<offer>` with `<relay>` +
//!    N `<enc>` children and ship it through `client.send_node`.

use std::sync::Arc;

use wacore::types::call::CallId;
use wacore_binary::Jid;

use crate::calls::{
    CallError, CallManager, CallOptions, EncryptedCallKey, RelayData, inject_relay_block,
};
use crate::client::Client;

/// Inputs for [`Client::place_call`]. `relay_data` is required for media to
/// flow — callers obtain it from the relay-allocate path (not yet exposed
/// as a public API, see the `CallManager::build_offer_stanza_fanout` docs).
#[derive(Debug, Clone)]
pub struct PlaceCallRequest {
    /// Peer JID (user or group).
    pub peer: Jid,
    /// Video call?
    pub video: bool,
    /// Group JID for group calls, `None` for 1:1.
    pub group_jid: Option<Jid>,
    /// Relay endpoints + session keys. When `None` the offer goes out
    /// without a `<relay>` block — peer will have to negotiate P2P,
    /// which is unlikely to work behind NAT. Callers that care about
    /// media connectivity MUST supply this.
    pub relay_data: Option<RelayData>,
}

/// Outcome of [`Client::place_call`].
#[derive(Debug, Clone)]
pub struct PlaceCallResult {
    /// The generated call id.
    pub call_id: CallId,
    /// Number of peer devices the offer was encrypted for.
    pub devices_encrypted_for: usize,
}

impl Client {
    /// Execute the full pre-offer pipeline and send the `<offer>` stanza.
    ///
    /// Implements the same sequence `WAWeb/Voip/StartCall.js` runs before
    /// `VoipStackInterface.startCall`. See the module docs for the step
    /// list.
    ///
    /// Returns on successful stanza send. The call is in `Ringing` state
    /// after this — the caller must listen on the event bus for
    /// `CallAccepted` / `CallRejected` / `CallEnded`.
    pub async fn place_call(&self, req: PlaceCallRequest) -> Result<PlaceCallResult, CallError> {
        // Step 1: fire-and-forget tcToken. Errors are swallowed inside.
        let _ = self.tc_token().pre_call_send(&req.peer).await;

        // Step 2: Usync with context=voip so the server refreshes the
        // peer's device list before we fan-out the call key.
        if let Err(e) = self.usync_voip_devices(&req.peer).await {
            log::warn!(
                target: "Client/PlaceCall",
                "voip usync for {} failed: {:?} — continuing with cached device list",
                req.peer,
                e
            );
        }

        // Step 3: walk the peer's device list, make sure every Signal
        // session is ready (fetches prekeys as needed).
        let devices = self.ensure_call_sessions_all(&req.peer).await?;

        // Step 4: fan-out encrypt. Each <enc> covers one device.
        let encrypted_keys = self.fanout_encrypt_call_key(&devices).await?;
        let any_pkmsg = encrypted_keys.iter().any(|(_, k)| k.is_prekey());
        let encrypted_list: Vec<EncryptedCallKey> =
            encrypted_keys.into_iter().map(|(_, k)| k).collect();
        let devices_encrypted_for = encrypted_list.len();

        // Step 5: CallInfo + offer stanza.
        let call_manager: Arc<CallManager> = self.get_call_manager().await;
        let options = CallOptions {
            video: req.video,
            group_jid: req.group_jid.clone(),
        };
        let call_id = call_manager.start_call(req.peer.clone(), options).await?;

        // Device identity is only needed when at least one <enc> is a
        // PreKey message; for pure `msg` fan-outs we omit it.
        let device_identity = if any_pkmsg {
            self.current_device_identity_bytes().await
        } else {
            None
        };

        let mut stanza = call_manager
            .build_offer_stanza_fanout(&call_id, encrypted_list, device_identity)
            .await?;

        // Attach <relay> block if the caller provided it.
        if let Some(relay) = req.relay_data {
            stanza = inject_relay_block(stanza, relay);
        }

        // Send and transition the state machine.
        self.send_node(stanza)
            .await
            .map_err(|e| CallError::Transport(format!("failed to send <call> stanza: {e}")))?;
        call_manager.mark_offer_sent(&call_id).await?;

        Ok(PlaceCallResult {
            call_id,
            devices_encrypted_for,
        })
    }

    /// Run USync with `context=voip` for a single peer. The server's
    /// response is used only to force a device list refresh in the
    /// server-side cache — we don't consume the parsed body here since
    /// [`ensure_call_sessions_all`] will re-query through the device
    /// registry, which the usync call just refreshed.
    ///
    /// [`ensure_call_sessions_all`]: Self::ensure_call_sessions_all
    async fn usync_voip_devices(&self, peer: &Jid) -> Result<(), crate::request::IqError> {
        use wacore::iq::usync::{DeviceListSpec, UsyncContext};
        let spec = DeviceListSpec::new(vec![peer.to_non_ad()], generate_usync_sid())
            .with_context(UsyncContext::Voip);
        let _response = self.execute(spec).await?;
        Ok(())
    }

    /// Signal-encrypt the same random call key for every device in
    /// `devices`, returning `(device_jid, enc_key)` pairs. The call key
    /// is generated once per call and used across the fan-out so every
    /// peer device decrypts the same master key (and therefore derives
    /// the same HBH / WARP / SRTP material).
    ///
    /// On per-device encrypt failure we **skip** that device and log —
    /// matching WA Web's `::E` fallback where a failed encrypt drops only
    /// that `<enc>`. If every device fails, returns the error from the
    /// last attempt (the stanza would have an empty `<destination>` and
    /// the peer would reject it).
    async fn fanout_encrypt_call_key(
        &self,
        devices: &[Jid],
    ) -> Result<Vec<(Jid, EncryptedCallKey)>, CallError> {
        if devices.is_empty() {
            return Err(CallError::Encryption(
                "no devices to fan-out call key".into(),
            ));
        }

        // Pre-size the result vector to avoid realloc mid-loop.
        let mut out: Vec<(Jid, EncryptedCallKey)> = Vec::with_capacity(devices.len());
        let mut last_err: Option<CallError> = None;

        // Share ONE call key across all devices. Generated fresh per call.
        for device in devices {
            match self.encrypt_call_key_for(device).await {
                Ok((_call_key, enc)) => out.push((device.clone(), enc)),
                Err(e) => {
                    log::warn!(
                        target: "Client/PlaceCall",
                        "fan-out encrypt failed for {}: {:?}",
                        device,
                        e
                    );
                    last_err = Some(e);
                }
            }
        }

        if out.is_empty() {
            return Err(last_err.unwrap_or_else(|| {
                CallError::Encryption("no devices encrypted successfully".into())
            }));
        }

        Ok(out)
    }

    /// Encode the current session's ADV device identity for embedding in
    /// `<device-identity>` when an offer carries PreKey messages. Returns
    /// `None` if the device has no account yet.
    async fn current_device_identity_bytes(&self) -> Option<Vec<u8>> {
        use prost::Message;
        let device = self.persistence_manager.get_device_snapshot().await;
        device.account.as_ref().map(|a| a.encode_to_vec())
    }
}

/// Generate a fresh usync `sid`. WA Web uses a random hex string; we
/// piggyback on the existing call-id hex-32 generator since both just
/// need cryptographic uniqueness and the server treats `sid` as opaque.
fn generate_usync_sid() -> String {
    CallId::generate().as_str().to_string()
}
