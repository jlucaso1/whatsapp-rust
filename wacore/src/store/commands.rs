use crate::client_profile::ClientProfile;
use crate::store::Device;
use crate::store::device::{CachedServerCertChain, DevicePropsOverride};
use wacore_binary::Jid;
use waproto::whatsapp as wa;

#[derive(Debug, Clone)]
pub enum DeviceCommand {
    SetId(Option<Jid>),
    SetLid(Option<Jid>),
    SetPushName(String),
    SetAccount(Option<wa::AdvSignedDeviceIdentity>),
    SetAppVersion((u32, u32, u32)),
    SetDeviceProps(DevicePropsOverride),
    SetClientProfile(ClientProfile),
    SetPropsHash(Option<String>),
    SetNextPreKeyId(u32),
    SetAdvSecretKey([u8; 32]),
    SetNctSalt(Option<Vec<u8>>),
    SetNctSaltFromHistorySync(Vec<u8>),
    /// Cache the server cert chain extracted from a successful XX (or
    /// XX-fallback) handshake. Enables Noise IK on the next connect.
    SetServerCertChain(CachedServerCertChain),
    /// Drop the cached server cert chain (e.g. after IK fails with a
    /// crypto-fatal error, signalling that the cached `leaf.key` is stale).
    /// Forces XX on the next connect.
    ClearServerCertChain,
}

pub fn apply_command_to_device(device: &mut Device, command: DeviceCommand) {
    match command {
        DeviceCommand::SetId(id) => {
            device.pn = id;
        }
        DeviceCommand::SetLid(lid) => {
            device.lid = lid;
        }
        DeviceCommand::SetPushName(name) => {
            device.push_name = name;
        }
        DeviceCommand::SetAccount(account) => {
            device.account = account;
        }
        DeviceCommand::SetAppVersion((p, s, t)) => {
            device.app_version_primary = p;
            device.app_version_secondary = s;
            device.app_version_tertiary = t;
            device.app_version_last_fetched_ms = crate::time::now_millis();
        }
        DeviceCommand::SetDeviceProps(override_) => {
            device.set_device_props(override_);
        }
        DeviceCommand::SetClientProfile(profile) => {
            device.set_client_profile(profile);
        }
        DeviceCommand::SetPropsHash(hash) => {
            device.props_hash = hash;
        }
        DeviceCommand::SetNextPreKeyId(id) => {
            device.next_pre_key_id = id;
        }
        DeviceCommand::SetAdvSecretKey(key) => {
            device.adv_secret_key = key;
        }
        DeviceCommand::SetNctSalt(salt) => {
            device.nct_salt = salt;
            device.nct_salt_sync_seen = true;
        }
        DeviceCommand::SetNctSaltFromHistorySync(salt) => {
            if !salt.is_empty() && !device.nct_salt_sync_seen && device.nct_salt.is_none() {
                device.nct_salt = Some(salt);
            }
        }
        DeviceCommand::SetServerCertChain(chain) => {
            device.server_cert_chain = Some(chain);
        }
        DeviceCommand::ClearServerCertChain => {
            device.server_cert_chain = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceCommand, apply_command_to_device};
    use crate::store::Device;
    use crate::store::device::{CachedNoiseCert, CachedServerCertChain};

    fn dummy_chain() -> CachedServerCertChain {
        CachedServerCertChain {
            intermediate: CachedNoiseCert {
                key: [0x11; 32],
                not_before: 1_700_000_000,
                not_after: 1_900_000_000,
            },
            leaf: CachedNoiseCert {
                key: [0x22; 32],
                not_before: 1_700_000_100,
                not_after: 1_899_999_900,
            },
        }
    }

    #[test]
    fn set_server_cert_chain_populates_field() {
        let mut device = Device::new();
        assert!(device.server_cert_chain.is_none());

        let chain = dummy_chain();
        apply_command_to_device(
            &mut device,
            DeviceCommand::SetServerCertChain(chain.clone()),
        );
        assert_eq!(device.server_cert_chain, Some(chain));
    }

    #[test]
    fn clear_server_cert_chain_drops_field() {
        let mut device = Device::new();
        device.server_cert_chain = Some(dummy_chain());

        apply_command_to_device(&mut device, DeviceCommand::ClearServerCertChain);
        assert!(device.server_cert_chain.is_none());
    }

    #[test]
    fn set_then_clear_roundtrips() {
        let mut device = Device::new();
        let chain = dummy_chain();
        apply_command_to_device(
            &mut device,
            DeviceCommand::SetServerCertChain(chain.clone()),
        );
        assert_eq!(device.server_cert_chain.as_ref(), Some(&chain));
        apply_command_to_device(&mut device, DeviceCommand::ClearServerCertChain);
        assert!(device.server_cert_chain.is_none());
    }

    #[test]
    fn test_history_sync_salt_backfills_when_no_syncd_mutation_was_seen() {
        let mut device = Device::new();
        let salt = vec![1, 2, 3, 4];

        apply_command_to_device(
            &mut device,
            DeviceCommand::SetNctSaltFromHistorySync(salt.clone()),
        );

        assert_eq!(device.nct_salt, Some(salt));
        assert!(!device.nct_salt_sync_seen);
    }

    #[test]
    fn test_history_sync_salt_does_not_resurrect_after_remove() {
        let mut device = Device::new();

        apply_command_to_device(&mut device, DeviceCommand::SetNctSalt(None));
        apply_command_to_device(
            &mut device,
            DeviceCommand::SetNctSaltFromHistorySync(vec![9, 9, 9]),
        );

        assert_eq!(device.nct_salt, None);
        assert!(device.nct_salt_sync_seen);
    }

    #[test]
    fn test_history_sync_salt_does_not_overwrite_syncd_value() {
        let mut device = Device::new();
        let syncd_salt = vec![7, 8, 9];

        apply_command_to_device(
            &mut device,
            DeviceCommand::SetNctSalt(Some(syncd_salt.clone())),
        );
        apply_command_to_device(
            &mut device,
            DeviceCommand::SetNctSaltFromHistorySync(vec![1, 2, 3]),
        );

        assert_eq!(device.nct_salt, Some(syncd_salt));
        assert!(device.nct_salt_sync_seen);
    }

    #[test]
    fn test_history_sync_empty_salt_is_ignored() {
        let mut device = Device::new();

        apply_command_to_device(
            &mut device,
            DeviceCommand::SetNctSaltFromHistorySync(vec![]),
        );

        assert_eq!(device.nct_salt, None);
        assert!(!device.nct_salt_sync_seen);
    }
}
