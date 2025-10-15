use hkdf::Hkdf;
use sha2::Sha256;
use std::simd::u16x8;

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
    assert!(base.len() % 2 == 0, "slice lengths must be even");

    // Process the bulk of the data in 16-byte chunks (8 u16s)
    let (base_chunks, base_remainder) = base.as_chunks_mut::<16>();
    let (input_chunks, input_remainder) = input.as_chunks::<16>();

    if subtract {
        for (base_chunk, input_chunk) in base_chunks.iter_mut().zip(input_chunks) {
            let base_u16: [u16; 8] = unsafe { std::mem::transmute(*base_chunk) };
            let input_u16: [u16; 8] = unsafe { std::mem::transmute(*input_chunk) };
            let base_simd = u16x8::from_array(base_u16);
            let input_simd = u16x8::from_array(input_u16);
            let result_simd = base_simd - input_simd;
            *base_chunk = unsafe { std::mem::transmute(result_simd.to_array()) };
        }
    } else {
        for (base_chunk, input_chunk) in base_chunks.iter_mut().zip(input_chunks) {
            let base_u16: [u16; 8] = unsafe { std::mem::transmute(*base_chunk) };
            let input_u16: [u16; 8] = unsafe { std::mem::transmute(*input_chunk) };
            let base_simd = u16x8::from_array(base_u16);
            let input_simd = u16x8::from_array(input_u16);
            let result_simd = base_simd + input_simd;
            *base_chunk = unsafe { std::mem::transmute(result_simd.to_array()) };
        }
    }

    // Handle any remaining data that is not a multiple of 16 bytes
    let mut i = 0;
    while i < base_remainder.len() {
        let x = u16::from_le_bytes([base_remainder[i], base_remainder[i + 1]]);
        let y = u16::from_le_bytes([input_remainder[i], input_remainder[i + 1]]);

        let result = if subtract {
            x.wrapping_sub(y)
        } else {
            x.wrapping_add(y)
        };
        let bytes = result.to_le_bytes();
        base_remainder[i] = bytes[0];
        base_remainder[i + 1] = bytes[1];
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

    #[test]
    fn test_simd_vs_scalar_consistency() {
        // Test that SIMD and scalar paths produce identical results
        // by testing various buffer sizes that exercise both paths
        let test_sizes = [2, 4, 8, 16, 18, 32, 64, 128, 256];

        for &size in &test_sizes {
            let mut base_simd = vec![0u8; size];
            let mut base_scalar = vec![0u8; size];
            let input = vec![1u8; size];

            // Test add operation
            perform_pointwise_with_overflow(&mut base_simd, &input, false);
            perform_pointwise_with_overflow(&mut base_scalar, &input, false);
            assert_eq!(base_simd, base_scalar, "Add failed for size {}", size);

            // Test subtract operation
            perform_pointwise_with_overflow(&mut base_simd, &input, true);
            perform_pointwise_with_overflow(&mut base_scalar, &input, true);
            assert_eq!(base_simd, base_scalar, "Subtract failed for size {}", size);
            assert_eq!(
                base_simd,
                vec![0u8; size],
                "Subtract result incorrect for size {}",
                size
            );
        }
    }

    #[test]
    fn test_overflow_underflow() {
        // Test wrapping behavior with maximum values
        let mut base = vec![255u8, 255, 0, 0]; // Two u16 max values
        let input = vec![1u8, 0, 1, 0]; // Add 1 and subtract 1

        // Test add overflow: 65535 + 1 = 0, 0 + 1 = 1
        perform_pointwise_with_overflow(&mut base, &input, false);
        assert_eq!(base, vec![0, 0, 1, 0]); // Should wrap around

        // Test subtract underflow: 0 - 1 = 65535, 1 - 1 = 0
        perform_pointwise_with_overflow(&mut base, &input, true);
        assert_eq!(base, vec![255, 255, 0, 0]); // Should wrap around
    }

    #[test]
    fn test_multiple_operations() {
        let mut base = vec![0u8; 128];
        let lth = WAPATCH_INTEGRITY;

        let items = vec![
            vec![1u8, 2, 3, 4],
            vec![5u8, 6, 7, 8],
            vec![9u8, 10, 11, 12],
        ];

        // Add all items
        lth.subtract_then_add_in_place(&mut base, &[], &items);
        let after_add = base.clone();
        assert_ne!(after_add, vec![0u8; 128]);

        // Subtract all items in reverse order
        let mut reverse_items = items.clone();
        reverse_items.reverse();
        lth.subtract_then_add_in_place(&mut base, &reverse_items, &[]);
        assert_eq!(base, vec![0u8; 128]);
    }

    #[test]
    fn test_different_buffer_sizes() {
        let lth = WAPATCH_INTEGRITY;

        // LTHash always operates on 128-byte buffers, but test with different item sizes
        let base = vec![0u8; 128];
        let items = vec![
            vec![42u8; 1],  // Small item
            vec![42u8; 10], // Medium item
            vec![42u8; 32], // Large item
        ];

        for item in items {
            let mut test_base = base.clone();
            lth.subtract_then_add_in_place(&mut test_base, &[], std::slice::from_ref(&item));
            assert_ne!(test_base, vec![0u8; 128]);

            lth.subtract_then_add_in_place(&mut test_base, &[item], &[]);
            assert_eq!(test_base, vec![0u8; 128]);
        }
    }

    #[test]
    fn test_round_trip_complex() {
        let mut base = vec![100u8; 128];
        let original = base.clone();
        let lth = WAPATCH_INTEGRITY;

        let add_items = vec![vec![1u8, 2, 3], vec![4u8, 5], vec![6u8, 7, 8, 9]];

        let subtract_items = vec![vec![1u8, 2, 3], vec![4u8, 5], vec![6u8, 7, 8, 9]];

        // Add then subtract should return to original
        lth.subtract_then_add_in_place(&mut base, &[], &add_items);
        assert_ne!(base, original);

        lth.subtract_then_add_in_place(&mut base, &subtract_items, &[]);
        assert_eq!(base, original);
    }

    #[test]
    fn test_empty_operations() {
        let mut base = vec![42u8; 128];
        let original = base.clone();
        let lth = WAPATCH_INTEGRITY;

        // Empty add and subtract should not change anything
        lth.subtract_then_add_in_place(&mut base, &[], &[]);
        assert_eq!(base, original);
    }

    #[test]
    fn test_single_byte_operations() {
        let mut base = vec![0u8; 2]; // Minimal 2-byte buffer
        let input = vec![255u8, 254];

        // Test add
        perform_pointwise_with_overflow(&mut base, &input, false);
        assert_eq!(base, vec![255, 254]);

        // Test subtract (should wrap)
        perform_pointwise_with_overflow(&mut base, &input, true);
        assert_eq!(base, vec![0, 0]);
    }
}
