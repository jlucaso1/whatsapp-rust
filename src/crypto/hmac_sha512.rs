use crate::proto::whatsapp as wa;
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub fn generate_content_mac(
    operation: wa::syncd_mutation::SyncdOperation,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");

    mac.update(&[(operation as i32 + 1) as u8]);
    mac.update(key_id);
    mac.update(data);
    mac.update(&((key_id.len() + 1) as u64).to_be_bytes());
    let result = mac.finalize().into_bytes();
    result[..32]
        .try_into()
        .expect("Slice with incorrect length")
}
