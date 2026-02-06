pub mod context;

use crate::store::Device;
use crate::types::events::CoreEventBus;

/// Core client containing only platform-independent protocol logic
pub struct CoreClient {
    /// Core device data
    pub device: Device,
    pub event_bus: CoreEventBus,
}

impl CoreClient {
    /// Creates a new core client with the given device
    pub fn new(device: Device) -> Self {
        Self {
            device,
            event_bus: CoreEventBus::new(),
        }
    }

    /// Gets the current device state
    pub fn get_device(&self) -> &Device {
        &self.device
    }

    /// Updates device state (pure function)
    pub fn update_device(&mut self, device: Device) {
        self.device = device;
    }
}
