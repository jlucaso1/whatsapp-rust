// Re-export commands from core
pub use wacore::store::commands::*;

// Wrapper function to apply commands to our platform-specific Device
pub fn apply_command_to_device(device: &mut crate::store::Device, command: DeviceCommand) {
    wacore::store::commands::apply_command_to_device(&mut device.core, command);
}
