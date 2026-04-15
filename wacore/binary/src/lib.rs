#![cfg_attr(feature = "simd", feature(portable_simd))]

pub mod attrs;
pub mod builder;
pub mod consts;
mod decoder;
pub mod encoder;
pub mod error;
pub mod jid;
pub mod marshal;
pub mod node;
pub mod token;
pub mod util;
pub mod zlib_pool;

pub use attrs::{AttrParser, AttrParserRef};
pub use compact_str::CompactString;
pub use error::{BinaryError, Result};
pub use jid::{
    BOT_SERVER, BROADCAST_SERVER, DEFAULT_USER_SERVER, DeviceKey, GROUP_SERVER, HIDDEN_USER_SERVER,
    HOSTED_LID_SERVER, HOSTED_SERVER, INTEROP_SERVER, Jid, JidExt, JidRef, LEGACY_USER_SERVER,
    MESSENGER_SERVER, MessageId, MessageServerId, NEWSLETTER_SERVER, SERVER_JID,
    STATUS_BROADCAST_USER, Server, push_jid_to_compact, push_jid_to_string,
};
pub use marshal::{
    marshal, marshal_auto, marshal_exact, marshal_ref, marshal_ref_auto, marshal_ref_exact,
    marshal_ref_to, marshal_ref_to_vec, marshal_to, marshal_to_vec,
};
pub use node::{
    Attrs, Node, NodeContent, NodeContentRef, NodeRef, NodeStr, NodeValue, OwnedNodeRef,
};
