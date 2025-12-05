use hkdf::Hkdf;
use sha2::Sha256;

/// ExpandedAppStateKeys corresponds 1:1 with whatsmeow's ExpandedAppStateKeys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedAppStateKeys {
    pub index: [u8; 32],
    pub value_encryption: [u8; 32],
    pub value_mac: [u8; 32],
    pub snapshot_mac: [u8; 32],
    pub patch_mac: [u8; 32],
}

/// Expand the 32 byte master app state sync key material into 160 bytes of sub-keys.
/// Go reference: expandAppStateKeys in vendor/whatsmeow/appstate/keys.go
pub fn expand_app_state_keys(key_data: &[u8]) -> ExpandedAppStateKeys {
    // HKDF-SHA256 with info "WhatsApp Mutation Keys" length 160
    const INFO: &[u8] = b"WhatsApp Mutation Keys";
    let hk = Hkdf::<Sha256>::new(None, key_data);
    let mut okm = [0u8; 160];
    hk.expand(INFO, &mut okm).expect("hkdf expand");
    let take32 = |start: usize| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&okm[start..start + 32]);
        arr
    };
    ExpandedAppStateKeys {
        index: take32(0),
        value_encryption: take32(32),
        value_mac: take32(64),
        snapshot_mac: take32(96),
        patch_mac: take32(128),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_deterministic() {
        let key = [7u8; 32];
        let a = expand_app_state_keys(&key);
        let b = expand_app_state_keys(&key);
        assert_eq!(a, b);
    }
}
