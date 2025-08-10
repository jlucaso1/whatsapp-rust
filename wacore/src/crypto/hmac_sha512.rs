use hmac::{Hmac, Mac};
use sha2::Sha512;
use waproto::whatsapp as wa;

pub fn generate_content_mac(
    operation: wa::syncd_mutation::SyncdOperation,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");

    // 1. Hash the operation byte, which is its enum value + 1.
    let operation_byte = (operation as i32 + 1) as u8;
    mac.update(&[operation_byte]);

    // 2. Hash the key ID itself.
    mac.update(key_id);

    // 3. Hash the main encrypted payload.
    mac.update(data);

    // 4. Hash the 8-byte, big-endian length of (keyID + operation_byte).
    let total_len = (key_id.len() + 1) as u64;
    mac.update(&total_len.to_be_bytes());

    let final_mac: [u8; 32] = mac.finalize().into_bytes()[..32].try_into().unwrap();

    final_mac
}
