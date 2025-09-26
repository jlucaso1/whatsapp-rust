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
}

pub fn apply_command_to_device(device: &mut Device, command: DeviceCommand) {
    match command {
        DeviceCommand::SetId(id) => {
            device.snapshot.pn = id.map(|j| j.to_string());
        }
        DeviceCommand::SetLid(lid) => {
            device.snapshot.lid = lid.map(|j| j.to_string());
        }
        DeviceCommand::SetPushName(name) => {
            device.snapshot.push_name = Some(name);
        }
        DeviceCommand::SetAccount(account) => {
            device.snapshot.account = account;
        }
        DeviceCommand::SetAppVersion((p, s, t)) => {
            let app_version = wa::client_payload::user_agent::AppVersion {
                primary: Some(p),
                secondary: Some(s),
                tertiary: Some(t),
                quaternary: None,
                quinary: None,
            };
            device.snapshot.app_version = Some(app_version);
            device.snapshot.app_version_last_fetched_ms =
                Some(chrono::Utc::now().timestamp_millis());
        }
    }
}
