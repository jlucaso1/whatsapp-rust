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
            device.app_version_last_fetched_ms = chrono::Utc::now().timestamp_millis();
        }
        DeviceCommand::SetDeviceProps(os, version, platform_type) => {
            device.set_device_props(os, version, platform_type);
        }
        DeviceCommand::SetPropsHash(hash) => {
            device.props_hash = hash;
        }
    }
}
