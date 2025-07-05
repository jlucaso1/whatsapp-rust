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

    // 1. Hash the operation byte. `Set` is 0, so this becomes 1. `Remove` is 1, so this becomes 2.
    mac.update(&[(operation as i32 + 1) as u8]);
    // 2. Hash the key ID itself.
    mac.update(key_id);
    // 3. Hash the main encrypted payload.
    mac.update(data);
    // 4. Hash the length of (key ID + operation byte). The operation is always 1 byte.
    let key_data_length = (key_id.len() + 1) as u64;
    mac.update(&key_data_length.to_be_bytes());
    let final_mac: [u8; 32] = mac.finalize().into_bytes()[..32].try_into().unwrap();

    final_mac
}
