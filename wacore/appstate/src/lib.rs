pub mod decode;
pub mod errors;
pub mod hash;
pub mod keys;
pub mod lthash;
pub mod patch_decode;
pub mod processor;

pub use decode::{Mutation, collect_key_ids_from_patch_list, decode_record};
pub use errors::*;
pub use keys::{ExpandedAppStateKeys, expand_app_state_keys};
pub use lthash::{LTHash, WAPATCH_INTEGRITY};
pub use processor::{
    PatchProcessingResult, ProcessedSnapshot, process_patch, process_snapshot, validate_patch_macs,
    validate_snapshot_mac,
};
