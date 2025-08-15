use crate::libsignal::protocol::ProtocolAddress;
use wacore_binary::jid::Jid;

pub trait JidExt {
    fn to_protocol_address(&self) -> ProtocolAddress;
}

impl JidExt for Jid {
    fn to_protocol_address(&self) -> ProtocolAddress {
        ProtocolAddress::new(self.user.clone(), (self.device as u32).into())
    }
}
