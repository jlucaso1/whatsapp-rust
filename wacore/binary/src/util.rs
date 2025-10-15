use crate::error::{BinaryError, Result};
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
use std::io::Read;

pub fn unpack(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if data.is_empty() {
        return Err(BinaryError::EmptyData);
    }
    let data_type = data[0];
    let data = &data[1..];

    if (data_type & 2) > 0 {
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BinaryError::Zlib(e.to_string()))?;
        Ok(Cow::Owned(decompressed))
    } else {
        Ok(Cow::Borrowed(data))
    }
}
