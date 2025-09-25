pub mod commands;
pub mod device_aware_store;
pub mod error;
pub mod generic;
pub mod persistence_manager;
pub mod schema;
pub mod signal;
pub mod signal_adapter;
pub mod sqlite_store;
pub mod traits;

pub use crate::store::traits::*;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[derive(Clone)]
pub struct Device {
    pub core: wacore::store::Device,
    pub backend: Arc<dyn Backend>,
}

impl Deref for Device {
    type Target = wacore::store::Device;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl DerefMut for Device {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

impl Device {
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        let core = wacore::store::Device::new();
        Self { core, backend }
    }

    pub fn to_serializable(&self) -> wacore::store::Device {
        self.core.clone()
    }

    pub fn load_from_serializable(&mut self, loaded: wacore::store::Device) {
        self.core = loaded;
    }
}
