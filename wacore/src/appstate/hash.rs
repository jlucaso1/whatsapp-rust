use crate::appstate::AppStateError;
use crate::appstate::lthash::WAPATCH_INTEGRITY;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use waproto::whatsapp as wa;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashState {
    pub version: u64,
    #[serde(with = "BigArray")]
    pub hash: [u8; 128],
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

impl HashState {
    /// Update the running LTHash with a batch of mutations. Mirrors Go (*HashState).updateHash.
    /// get_prev_set_value_mac: given index MAC and current mutation index, returns the value MAC (32 bytes)
    /// of the previous SET operation if present.
    pub fn update_hash<F>(
        &mut self,
        mutations: &[wa::SyncdMutation],
        mut get_prev_set_value_mac: F,
    ) -> (Vec<anyhow::Error>, anyhow::Result<()>)
    where
        F: FnMut(&[u8], usize) -> anyhow::Result<Option<Vec<u8>>>,
    {
        let mut added: Vec<Vec<u8>> = Vec::new();
        let mut removed: Vec<Vec<u8>> = Vec::new();
        let mut warnings: Vec<anyhow::Error> = Vec::new();

        for (i, mutation) in mutations.iter().enumerate() {
            let op = mutation.operation.unwrap_or_default(); // 0 = Set, 1 = Remove
            if op == wa::syncd_mutation::SyncdOperation::Set as i32
                && let Some(record) = &mutation.record
                && let Some(value) = &record.value
            {
                // value.blob contains iv+ciphertext+valuemac? In proto it's just blob field below
                if let Some(blob) = &value.blob
                    && blob.len() >= 32
                {
                    added.push(blob[blob.len() - 32..].to_vec());
                }
            }
            // index MAC for removal lookup
            let index_mac_opt = mutation
                .record
                .as_ref()
                .and_then(|r| r.index.as_ref())
                .and_then(|idx| idx.blob.as_ref());
            if let Some(index_mac) = index_mac_opt {
                match get_prev_set_value_mac(index_mac, i) {
                    Ok(Some(prev)) => removed.push(prev),
                    Ok(None) => {
                        if op == wa::syncd_mutation::SyncdOperation::Remove as i32 {
                            warnings.push(anyhow::anyhow!(
                                AppStateError::MissingPreviousSetValueOperation
                            ));
                        }
                    }
                    Err(e) => return (warnings, Err(anyhow::anyhow!(e))),
                }
            }
        }

        // Apply LTHash (pointwise sum/diff of 64 uint16 words)
        WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut self.hash, &removed, &added);
        (warnings, Ok(()))
    }

    pub fn generate_snapshot_mac(&self, name: &str, key: &[u8]) -> Vec<u8> {
        concat_and_hmac_sha256(
            key,
            &[&self.hash, &u64_to_be(self.version), name.as_bytes()],
        )
    }
}

pub fn generate_patch_mac(patch: &wa::SyncdPatch, name: &str, key: &[u8], version: u64) -> Vec<u8> {
    // data: snapshot_mac, each mutation value MAC, version, name
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if let Some(sm) = &patch.snapshot_mac {
        parts.push(sm.clone());
    }
    for m in &patch.mutations {
        if let Some(record) = &m.record
            && let Some(val) = &record.value
            && let Some(blob) = &val.blob
            && blob.len() >= 32
        {
            parts.push(blob[blob.len() - 32..].to_vec());
        }
    }
    parts.push(u64_to_be(version).to_vec());
    parts.push(name.as_bytes().to_vec());
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    concat_and_hmac_sha256(key, &refs)
}

pub fn generate_content_mac(
    operation: wa::syncd_mutation::SyncdOperation,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let op_byte = [operation as u8 + 1];
    let key_data_length = u64_to_be((key_id.len() + 1) as u64);
    let mac = concat_and_hmac_sha512(key, &[&op_byte, key_id, data, &key_data_length]);
    mac[..32].to_vec()
}

fn u64_to_be(val: u64) -> [u8; 8] {
    val.to_be_bytes()
}

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

fn concat_and_hmac_sha256(key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    for p in data {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

fn concat_and_hmac_sha512(key: &[u8], data: &[&[u8]]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(key).expect("hmac key");
    for p in data {
        mac.update(p);
    }
    mac.finalize().into_bytes().to_vec()
}

pub fn validate_index_mac(
    index_json_bytes: &[u8],
    expected_mac: &[u8],
    key: &[u8; 32],
) -> Result<(), AppStateError> {
    let mut h = HmacSha256::new_from_slice(key).expect("hmac key");
    h.update(index_json_bytes);
    let computed = h.finalize().into_bytes();
    if computed.as_slice() != expected_mac {
        Err(AppStateError::MismatchingIndexMAC)
    } else {
        Ok(())
    }
}
