use crate::libsignal::protocol::ProtocolAddress;
use wacore_binary::jid::Jid;

pub trait JidExt {
    fn to_protocol_address(&self) -> ProtocolAddress;
}

impl JidExt for Jid {
    fn to_protocol_address(&self) -> ProtocolAddress {
        let agent = self.actual_agent();
        let name = if agent != 0 {
            format!("{}_{}", self.user, agent)
        } else {
            self.user.clone()
        };
        ProtocolAddress::new(name, (self.device as u32).into())
    }
}
