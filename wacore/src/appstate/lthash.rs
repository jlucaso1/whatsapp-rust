use hkdf::Hkdf;
use sha2::Sha256;
use std::convert::TryInto;

pub struct LtHash {
    pub hkdf_info: &'static [u8],
    pub hkdf_size: u8,
}

pub static WA_PATCH_INTEGRITY: LtHash = LtHash {
    hkdf_info: b"WhatsApp Patch Integrity",
    hkdf_size: 128,
};

impl LtHash {
    pub fn subtract_then_add_in_place(
        &self,
        base: &mut [u8; 128],
        subtract: &[&[u8]],
        add: &[&[u8]],
    ) {
        self.multiple_op(base, subtract, true);
        self.multiple_op(base, add, false);
    }

    fn multiple_op(&self, base: &mut [u8; 128], input: &[&[u8]], subtract: bool) {
        for &item in input {
            let hk = Hkdf::<Sha256>::new(None, item);
            let mut expanded = vec![0u8; self.hkdf_size as usize];
            hk.expand(self.hkdf_info, &mut expanded).unwrap();
            perform_pointwise_with_overflow(
                base,
                expanded.as_slice().try_into().unwrap(),
                subtract,
            );
        }
    }
}

fn perform_pointwise_with_overflow(base: &mut [u8; 128], input: &[u8; 128], subtract: bool) {
    for i in (0..128).step_by(2) {
        let x = u16::from_le_bytes(base[i..i + 2].try_into().unwrap());
        let y = u16::from_le_bytes(input[i..i + 2].try_into().unwrap());

        let result = if subtract {
            x.wrapping_sub(y)
        } else {
            x.wrapping_add(y)
        };

        base[i..i + 2].copy_from_slice(&result.to_le_bytes());
    }
}
