use reflect_metadata::TypeDescriptor;
use wacore::types::public::{PublicDeviceStatus, PublicEvent};

/// Metadata exposed to the bindings crate.
pub struct BindingDescriptor {
    pub descriptor: &'static TypeDescriptor,
    pub rust_path: &'static str,
}

/// Returns all type descriptors that should be surfaced in FFI bindings.
pub fn descriptors() -> Vec<BindingDescriptor> {
    vec![
        BindingDescriptor {
            descriptor: <PublicDeviceStatus as reflect_metadata::Reflect>::descriptor(),
            rust_path: "whatsapp_rust::types::public::PublicDeviceStatus",
        },
        BindingDescriptor {
            descriptor: <PublicEvent as reflect_metadata::Reflect>::descriptor(),
            rust_path: "whatsapp_rust::types::public::PublicEvent",
        },
    ]
}
