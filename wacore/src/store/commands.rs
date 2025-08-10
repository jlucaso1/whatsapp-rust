use crate::store::Device;
use crate::store::device::ProcessedMessageKey;
use crate::types::jid::Jid;
use waproto::whatsapp as wa;

#[derive(Debug, Clone)]
pub enum DeviceCommand {
    SetId(Option<Jid>),
    SetLid(Option<Jid>),
    SetPushName(String),
    SetAccount(Option<wa::AdvSignedDeviceIdentity>),
    AddProcessedMessage(ProcessedMessageKey),
}

pub fn apply_command_to_device(device: &mut Device, command: DeviceCommand) {
    match command {
        DeviceCommand::SetId(id) => {
            device.id = id;
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
        DeviceCommand::AddProcessedMessage(key) => {
            const MAX_PROCESSED_MESSAGES: usize = 2000;

            device.processed_messages.push_back(key);

            while device.processed_messages.len() > MAX_PROCESSED_MESSAGES {
                device.processed_messages.pop_front();
            }
        }
    }
}
