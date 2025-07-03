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

    let op_byte_slice = &[(operation as i32 + 1) as u8];
    let key_data_len_bytes = &((key_id.len() + 1) as u64).to_be_bytes();

    // Concatenate all parts into a single buffer before updating the HMAC,
    // mirroring the variadic argument behavior in Go's concatAndHMAC more closely.
    let mut buffer = Vec::with_capacity(
        op_byte_slice.len() + key_id.len() + data.len() + key_data_len_bytes.len(),
    );
    buffer.extend_from_slice(op_byte_slice);
    buffer.extend_from_slice(key_id);
    buffer.extend_from_slice(data);
    buffer.extend_from_slice(key_data_len_bytes);

    mac.update(&buffer);
    let result = mac.finalize().into_bytes();
    result[..32]
        .try_into()
        .expect("Slice with incorrect length")
}
