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

    /// Test key expansion against known good values from whatsmeow.
    /// These values were verified by running identical Go code.
    #[test]
    fn expansion_matches_whatsmeow() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);

        // Expected values verified against whatsmeow Go implementation
        assert_eq!(
            hex::encode(keys.index),
            "a3c20564c4744dc336223b76a374ac369fb1bc2062969b26bd0104cba5149e7a",
            "Index key mismatch"
        );
        assert_eq!(
            hex::encode(keys.value_encryption),
            "28f9ac3865f5c0d77441c361c8eb0c40435487e1fca973df3828cbe320faa07f",
            "Value encryption key mismatch"
        );
        assert_eq!(
            hex::encode(keys.value_mac),
            "e2b9c9aaebb04ac52b5c04c449a8af48945e63af3e4b8e2b3f8266753675bc3e",
            "Value MAC key mismatch"
        );
        assert_eq!(
            hex::encode(keys.snapshot_mac),
            "c49519c1aa1718c8f1c1f14c546fb2dedfcc58cace2b5fba9de15f9c084bd04b",
            "Snapshot MAC key mismatch"
        );
        assert_eq!(
            hex::encode(keys.patch_mac),
            "3b9efe15c717b5da8b85c45200bb6ce8af59c72d62f4c203909c53749b54cd04",
            "Patch MAC key mismatch"
        );
    }
}
