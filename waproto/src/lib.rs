//! Auto-generated protobuf definitions for the WhatsApp wire format.
//!
//! The Rust source (`whatsapp.rs`) is produced by `build.rs` from the
//! pre-compiled descriptor set `whatsapp.desc`, and written to `OUT_DIR` —
//! not tracked in git. To regenerate the descriptor after editing
//! `whatsapp.proto`, run `scripts/regenerate-proto-desc.sh` (wraps `protoc`).

#![allow(clippy::large_enum_variant)]
pub mod whatsapp {
    #![allow(
        non_camel_case_types,
        non_snake_case,
        unreachable_patterns,
        clippy::derivable_impls,
        clippy::match_single_binding,
        clippy::needless_else
    )]
    #[rustfmt::skip]
    include!(concat!(env!("OUT_DIR"), "/whatsapp.rs"));
}
