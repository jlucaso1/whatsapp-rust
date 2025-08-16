use hkdf::Hkdf;
use sha2::Sha256;

/// Summation based hash algorithm maintaining integrity of a sequence of mutations.
/// One-to-one port of whatsmeow/appstate/lthash/lthash.go
#[derive(Clone, Debug)]
pub struct LTHash {
    pub hkdf_info: &'static [u8],
    pub hkdf_size: u8,
}

pub const WAPATCH_INTEGRITY_INFO: &str = "WhatsApp Patch Integrity";
/// LTHash instance used for verifying integrity of WhatsApp app state sync patches.
pub const WAPATCH_INTEGRITY: LTHash = LTHash {
    hkdf_info: WAPATCH_INTEGRITY_INFO.as_bytes(),
    hkdf_size: 128,
};

impl LTHash {
    /// Returns a new buffer that is base with subtract items removed then add items added.
    pub fn subtract_then_add(&self, base: &[u8], subtract: &[Vec<u8>], add: &[Vec<u8>]) -> Vec<u8> {
        let mut output = base.to_vec();
        self.subtract_then_add_in_place(&mut output, subtract, add);
        output
    }

    /// Performs subtract then add in place on base buffer.
    pub fn subtract_then_add_in_place(
        &self,
        base: &mut [u8],
        subtract: &[Vec<u8>],
        add: &[Vec<u8>],
    ) {
        self.multiple_op(base, subtract, true);
        self.multiple_op(base, add, false);
    }

    fn multiple_op(&self, base: &mut [u8], input: &[Vec<u8>], subtract: bool) {
        for item in input {
            let derived = hkdf_sha256(item, None, self.hkdf_info, self.hkdf_size);
            perform_pointwise_with_overflow(base, &derived, subtract);
        }
    }
}

fn perform_pointwise_with_overflow(base: &mut [u8], input: &[u8], subtract: bool) {
    assert_eq!(base.len(), input.len(), "length mismatch");
    let len = base.len();
    let mut i = 0;
    while i < len {
        let x = u16::from_le_bytes([base[i], base[i + 1]]);
        let y = u16::from_le_bytes([input[i], input[i + 1]]);
        let result = if subtract {
            x.wrapping_sub(y)
        } else {
            x.wrapping_add(y)
        };
        let bytes = result.to_le_bytes();
        base[i] = bytes[0];
        base[i + 1] = bytes[1];
        i += 2;
    }
}

fn hkdf_sha256(key: &[u8], salt: Option<&[u8]>, info: &[u8], length: u8) -> Vec<u8> {
    let hk = if let Some(s) = salt {
        Hkdf::<Sha256>::new(Some(s), key)
    } else {
        Hkdf::<Sha256>::new(None, key)
    };
    let mut okm = vec![0u8; length as usize];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointwise_add_and_subtract() {
        let mut base = vec![0u8; 128];
        let item = vec![1u8, 2, 3];
        let lth = WAPATCH_INTEGRITY;
        lth.subtract_then_add_in_place(&mut base, &[], std::slice::from_ref(&item));
        let after_add = base.clone();
        assert_ne!(after_add, vec![0u8; 128]);
        lth.subtract_then_add_in_place(&mut base, &[item], &[]);
        assert_eq!(base, vec![0u8; 128]);
    }
}
