//! WebP format utilities.

/// Detects animated WebP by parsing RIFF/VP8X headers.
pub fn is_animated(data: &[u8]) -> bool {
    // Minimum: RIFF(4) + size(4) + WEBP(4) + chunk header(8) = 20
    if data.len() < 20 {
        return false;
    }
    if &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return false;
    }

    let mut offset = 12;
    while offset + 8 <= data.len() {
        let fourcc = &data[offset..offset + 4];
        let chunk_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        if fourcc == b"VP8X" && chunk_size >= 10 && offset + 8 < data.len() {
            if data[offset + 8] & 0x02 != 0 {
                return true;
            }
        }

        if fourcc == b"ANIM" || fourcc == b"ANMF" {
            return true;
        }

        // Each addition checked to prevent overflow on 32-bit
        offset = match offset
            .checked_add(8)
            .and_then(|v| v.checked_add(chunk_size))
            .and_then(|v| v.checked_add(chunk_size & 1))
        {
            Some(next) => next,
            None => break,
        };
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_webp_vp8x(flags: u8) -> Vec<u8> {
        let mut buf = Vec::new();
        // RIFF header
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&0u32.to_le_bytes()); // placeholder file size
        buf.extend_from_slice(b"WEBP");
        // VP8X chunk
        buf.extend_from_slice(b"VP8X");
        buf.extend_from_slice(&10u32.to_le_bytes()); // chunk size
        buf.push(flags);
        buf.extend_from_slice(&[0u8; 9]); // rest of VP8X payload
        // Fix RIFF size
        let riff_size = (buf.len() - 8) as u32;
        buf[4..8].copy_from_slice(&riff_size.to_le_bytes());
        buf
    }

    #[test]
    fn static_webp() {
        let data = make_webp_vp8x(0x00);
        assert!(!is_animated(&data));
    }

    #[test]
    fn animated_webp_via_flag() {
        let data = make_webp_vp8x(0x02);
        assert!(is_animated(&data));
    }

    #[test]
    fn animated_webp_via_anim_chunk() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(b"WEBP");
        // VP8X without animation flag
        buf.extend_from_slice(b"VP8X");
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        // ANIM chunk
        buf.extend_from_slice(b"ANIM");
        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 6]);
        let riff_size = (buf.len() - 8) as u32;
        buf[4..8].copy_from_slice(&riff_size.to_le_bytes());

        assert!(is_animated(&buf));
    }

    #[test]
    fn too_short() {
        assert!(!is_animated(&[0; 10]));
    }

    #[test]
    fn not_webp() {
        assert!(!is_animated(b"NOT A WEBP FILE AT ALL!!"));
    }
}
