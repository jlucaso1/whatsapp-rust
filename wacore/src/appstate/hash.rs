use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashState {
    pub version: u64,
    #[serde(with = "BigArray")]
    pub hash: [u8; 128],
    /// This map stores the index hash (base64) to the value MAC (raw bytes).
    /// Required for LT-Hash algorithm to validate patches and subtract old hashes.
    pub index_value_map: HashMap<String, Vec<u8>>,
}

impl Default for HashState {
    fn default() -> Self {
        Self {
            version: 0,
            hash: [0; 128],
            index_value_map: HashMap::new(),
        }
    }
}

// Placeholder for hash-related functions.
// TODO: Implement LTHash and MAC verification logic as needed.
