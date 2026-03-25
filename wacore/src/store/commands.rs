use crate::store::Device;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

#[derive(Debug, Clone)]
pub enum DeviceCommand {
    SetId(Option<Jid>),
    SetLid(Option<Jid>),
    SetPushName(String),
    SetAccount(Option<wa::AdvSignedDeviceIdentity>),
    SetAppVersion((u32, u32, u32)),
    SetDeviceProps(
        Option<String>,
        Option<wa::device_props::AppVersion>,
        Option<wa::device_props::PlatformType>,
    ),
    SetPropsHash(Option<String>),
    SetNextPreKeyId(u32),
    SetAdvSecretKey([u8; 32]),
    SetNctSalt(Option<Vec<u8>>),
    SetNctSaltFromHistorySync(Vec<u8>),
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
        DeviceCommand::SetDeviceProps(os, version, platform_type) => {
            device.set_device_props(os, version, platform_type);
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
            if !device.nct_salt_sync_seen && device.nct_salt.is_none() {
                device.nct_salt = Some(salt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceCommand, apply_command_to_device};
    use crate::store::Device;

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
}
