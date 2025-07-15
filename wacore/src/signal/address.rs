use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignalAddress {
    name: String,
    device_id: u32,
}

impl SignalAddress {
    pub fn new(name: String, device_id: u32) -> Self {
        Self { name, device_id }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }
}

impl fmt::Display for SignalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, self.device_id)
    }
}
