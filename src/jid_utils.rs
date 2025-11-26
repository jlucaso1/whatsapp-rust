use std::sync::OnceLock;
use wacore_binary::jid::{Jid, SERVER_JID};

static SERVER_JID_CACHE: OnceLock<Jid> = OnceLock::new();

pub fn server_jid() -> Jid {
    SERVER_JID_CACHE
        .get_or_init(|| {
            SERVER_JID
                .parse()
                .expect("SERVER_JID constant must parse into a valid JID")
        })
        .clone()
}
