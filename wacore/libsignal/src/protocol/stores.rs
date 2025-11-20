// Re-exporting structures from waproto to avoid duplication
pub use waproto::whatsapp::{
    IdentityKeyPairStructure, PreKeyRecordStructure, RecordStructure, SenderKeyRecordStructure,
    SenderKeyStateStructure, SessionStructure, SignedPreKeyRecordStructure,
};

pub use waproto::whatsapp::sender_key_state_structure;
pub use waproto::whatsapp::session_structure;
