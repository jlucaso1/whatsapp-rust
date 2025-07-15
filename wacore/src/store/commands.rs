use crate::store::Device;
use crate::store::device::ProcessedMessageKey;
use crate::types::jid::Jid;
use waproto::whatsapp as wa;

// Enum defining all possible commands to modify the Device state
#[derive(Debug, Clone)]
pub enum DeviceCommand {
    SetId(Option<Jid>),
    SetLid(Option<Jid>),
    SetPushName(String),
    SetAccount(Option<wa::AdvSignedDeviceIdentity>),
    AddProcessedMessage(ProcessedMessageKey),
    // Example: A command that takes multiple parameters or needs complex logic
    // CompletePairing {
    //     id: Jid,
    //     lid: Jid,
    //     account: wa::AdvSignedDeviceIdentity,
    //     // Potentially other fields that get updated upon successful pairing
    // },
    // Add more commands as needed for other device mutations
}

// Apply the command to the device.
// This function is intended to be called within PersistenceManager's modify_device context.
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
            
            // Cap the queue at MAX_PROCESSED_MESSAGES entries
            while device.processed_messages.len() > MAX_PROCESSED_MESSAGES {
                device.processed_messages.pop_front();
            }
        }
        // DeviceCommand::CompletePairing { id, lid, account } => {
        //     device.id = Some(id);
        //     device.lid = Some(lid);
        //     device.account = Some(account);
        //     // Potentially update other device fields related to pairing
        // }
    }
}
