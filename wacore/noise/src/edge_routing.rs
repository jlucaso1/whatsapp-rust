use thiserror::Error;
use wacore_binary::consts::WA_CONN_HEADER;

/// Maximum length for edge routing data (3 bytes max = 0xFFFFFF)
pub const MAX_EDGE_ROUTING_LEN: usize = 0xFF_FFFF;

#[derive(Debug, Error)]
pub enum EdgeRoutingError {
    #[error("edge routing info too large (max {MAX_EDGE_ROUTING_LEN} bytes)")]
    RoutingInfoTooLarge,
}

/// Builds the edge routing pre-intro header.
/// Format: `ED\0\1` (4 bytes) + length (3 bytes big-endian) + routing_data
pub fn build_edge_routing_preintro(routing_info: &[u8]) -> Result<Vec<u8>, EdgeRoutingError> {
    let len = routing_info.len();
    if len > MAX_EDGE_ROUTING_LEN {
        return Err(EdgeRoutingError::RoutingInfoTooLarge);
    }

    let mut preintro = Vec::with_capacity(7 + len);
    preintro.extend_from_slice(b"ED\x00\x01");
    preintro.push((len >> 16) as u8);
    preintro.push((len >> 8) as u8);
    preintro.push(len as u8);
    preintro.extend_from_slice(routing_info);
    Ok(preintro)
}

/// Builds the complete handshake connection header.
///
/// If edge routing info is provided and valid, prepends the edge routing pre-intro
/// to the WhatsApp connection header. Otherwise, returns just the connection header.
///
/// Returns `(header, used_edge_routing)` where `used_edge_routing` indicates whether
/// edge routing was successfully applied.
pub fn build_handshake_header(edge_routing_info: Option<&[u8]>) -> (Vec<u8>, bool) {
    let Some(routing_info) = edge_routing_info else {
        return (WA_CONN_HEADER.to_vec(), false);
    };

    match build_edge_routing_preintro(routing_info) {
        Ok(mut header) => {
            header.extend_from_slice(&WA_CONN_HEADER);
            (header, true)
        }
        // Intentional silent fallback: edge routing is optional and failures (e.g., oversized
        // routing info) should not prevent connection. The returned `false` flag allows callers
        // to detect and log this condition if needed.
        Err(_) => (WA_CONN_HEADER.to_vec(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_edge_routing_preintro_basic() {
        let routing_data = vec![0x01, 0x02, 0x03];
        let preintro = build_edge_routing_preintro(&routing_data)
            .expect("valid routing data should build preintro");

        assert_eq!(&preintro[0..4], b"ED\x00\x01");
        assert_eq!(preintro[4], 0x00);
        assert_eq!(preintro[5], 0x00);
        assert_eq!(preintro[6], 0x03);
        assert_eq!(&preintro[7..], &routing_data[..]);
    }

    #[test]
    fn test_build_edge_routing_preintro_empty() {
        let preintro =
            build_edge_routing_preintro(&[]).expect("valid routing data should build preintro");

        assert_eq!(&preintro[0..4], b"ED\x00\x01");
        assert_eq!(preintro[4], 0x00);
        assert_eq!(preintro[5], 0x00);
        assert_eq!(preintro[6], 0x00);
        assert_eq!(preintro.len(), 7);
    }

    #[test]
    fn test_build_edge_routing_preintro_large_length() {
        let routing_data = vec![0xAA; 0x010203];
        let preintro = build_edge_routing_preintro(&routing_data)
            .expect("valid routing data should build preintro");

        assert_eq!(preintro[4], 0x01);
        assert_eq!(preintro[5], 0x02);
        assert_eq!(preintro[6], 0x03);
    }

    #[test]
    fn test_build_edge_routing_preintro_too_large() {
        let routing_data = vec![0x00; MAX_EDGE_ROUTING_LEN + 1];
        let result = build_edge_routing_preintro(&routing_data);

        assert!(matches!(result, Err(EdgeRoutingError::RoutingInfoTooLarge)));
    }

    #[test]
    fn test_build_edge_routing_preintro_max_size() {
        let len = MAX_EDGE_ROUTING_LEN;

        assert_eq!((len >> 16) as u8, 0xFF);
        assert_eq!((len >> 8) as u8, 0xFF);
        assert_eq!(len as u8, 0xFF);
    }

    #[test]
    fn test_build_handshake_header_without_edge_routing() {
        let (header, used) = build_handshake_header(None);
        assert_eq!(header, WA_CONN_HEADER.to_vec());
        assert!(!used);
    }

    #[test]
    fn test_build_handshake_header_with_edge_routing() {
        let routing = vec![0x01, 0x02, 0x03];
        let (header, used) = build_handshake_header(Some(&routing));

        assert!(used);
        assert!(header.starts_with(b"ED\x00\x01"));
        assert!(header.ends_with(&WA_CONN_HEADER));
    }

    #[test]
    fn test_build_handshake_header_with_oversized_routing() {
        let routing = vec![0x00; MAX_EDGE_ROUTING_LEN + 1];
        let (header, used) = build_handshake_header(Some(&routing));

        assert!(!used);
        assert_eq!(header, WA_CONN_HEADER.to_vec());
    }
}
