use crate::crypto::hkdf;
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
            let expanded = hkdf::sha256(item, None, self.hkdf_info, self.hkdf_size.into()).unwrap();
            perform_pointwise_with_overflow(
                base,
                expanded.as_slice().try_into().unwrap(),
                subtract,
            );
        }
    }
}

fn perform_pointwise_with_overflow(base: &mut [u8; 128], other: &[u8; 128], subtract: bool) {
    let mut carry: u16 = 0;
    for i in 0..128 {
        let mut result = base[i] as u16 + carry;
        if subtract {
            result = result.wrapping_sub(other[i] as u16);
        } else {
            result += other[i] as u16;
        }
        base[i] = (result & 0xff) as u8;
        carry = result >> 8;
    }
}
