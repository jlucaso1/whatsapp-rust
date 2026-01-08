use core::simd::u16x8;
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Clone, Debug)]
pub struct LTHash {
    pub hkdf_info: &'static [u8],
    pub hkdf_size: u8,
}

pub const WAPATCH_INTEGRITY_INFO: &str = "WhatsApp Patch Integrity";
pub const WAPATCH_INTEGRITY: LTHash = LTHash {
    hkdf_info: WAPATCH_INTEGRITY_INFO.as_bytes(),
    hkdf_size: 128,
};

impl LTHash {
    pub fn subtract_then_add(&self, base: &[u8], subtract: &[Vec<u8>], add: &[Vec<u8>]) -> Vec<u8> {
        let mut output = base.to_vec();
        self.subtract_then_add_in_place(&mut output, subtract, add);
        output
    }

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
    assert!(base.len().is_multiple_of(2), "slice lengths must be even");

    let (base_chunks, base_remainder) = base.as_chunks_mut::<16>();
    let (input_chunks, input_remainder) = input.as_chunks::<16>();

    for (base_chunk, input_chunk) in base_chunks.iter_mut().zip(input_chunks) {
        let base_simd = u16x8::from_array(bytemuck::cast(*base_chunk));
        let input_simd = u16x8::from_array(bytemuck::cast(*input_chunk));

        let result_simd = if subtract {
            base_simd - input_simd
        } else {
            base_simd + input_simd
        };

        *base_chunk = bytemuck::cast(result_simd.to_array());
    }

    for (base_pair, input_pair) in base_remainder
        .chunks_exact_mut(2)
        .zip(input_remainder.chunks_exact(2))
    {
        let x = u16::from_le_bytes([base_pair[0], base_pair[1]]);
        let y = u16::from_le_bytes([input_pair[0], input_pair[1]]);

        let result = if subtract {
            x.wrapping_sub(y)
        } else {
            x.wrapping_add(y)
        };
        let bytes = result.to_le_bytes();
        base_pair[0] = bytes[0];
        base_pair[1] = bytes[1];
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
    fn test_simd_determinism_and_consistency() {
        let test_sizes = [2, 4, 8, 16, 18, 32, 64, 128, 256];

        for &size in &test_sizes {
            let mut base_simd = vec![0u8; size];
            let mut base_scalar = vec![0u8; size];
            let input = vec![1u8; size];

            perform_pointwise_with_overflow(&mut base_simd, &input, false);
            perform_pointwise_with_overflow(&mut base_scalar, &input, false);
            assert_eq!(base_simd, base_scalar, "Add failed for size {}", size);

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
        let mut base = vec![255u8, 255, 0, 0];
        let input = vec![1u8, 0, 1, 0];

        perform_pointwise_with_overflow(&mut base, &input, false);
        assert_eq!(base, vec![0, 0, 1, 0]);

        perform_pointwise_with_overflow(&mut base, &input, true);
        assert_eq!(base, vec![255, 255, 0, 0]);
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

        lth.subtract_then_add_in_place(&mut base, &[], &items);
        let after_add = base.clone();
        assert_ne!(after_add, vec![0u8; 128]);

        let mut reverse_items = items.clone();
        reverse_items.reverse();
        lth.subtract_then_add_in_place(&mut base, &reverse_items, &[]);
        assert_eq!(base, vec![0u8; 128]);
    }

    #[test]
    fn test_different_buffer_sizes() {
        let lth = WAPATCH_INTEGRITY;

        let base = vec![0u8; 128];
        let items = vec![vec![42u8; 1], vec![42u8; 10], vec![42u8; 32]];

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

        lth.subtract_then_add_in_place(&mut base, &[], &[]);
        assert_eq!(base, original);
    }

    #[test]
    fn test_single_byte_operations() {
        let mut base = vec![0u8; 2];
        let input = vec![255u8, 254];

        perform_pointwise_with_overflow(&mut base, &input, false);
        assert_eq!(base, vec![255, 254]);

        perform_pointwise_with_overflow(&mut base, &input, true);
        assert_eq!(base, vec![0, 0]);
    }
}
