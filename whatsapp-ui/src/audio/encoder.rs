//! Opus audio encoder for WhatsApp PTT messages
//!
//! Encodes audio to Opus codec in OGG container format.
//! WhatsApp PTT format: 16kHz, mono, 16kbps bitrate.

use std::io::Cursor;

use log::info;
use ogg::writing::PacketWriteEndInfo;
use opus::{Application, Channels, Encoder};

use super::recorder::RecordedAudio;

/// WhatsApp PTT audio settings
const SAMPLE_RATE: u32 = 16000;
const CHANNELS: Channels = Channels::Mono;
const BITRATE: i32 = 16000; // 16 kbps
const FRAME_SIZE_MS: usize = 20; // 20ms frames
const FRAME_SIZE_SAMPLES: usize = (SAMPLE_RATE as usize * FRAME_SIZE_MS) / 1000; // 320 samples at 16kHz
/// Granule positions in OGG Opus must be at 48kHz per RFC 7845
const GRANULE_RATE: u32 = 48000;
const GRANULE_PER_FRAME: u64 = (GRANULE_RATE as u64 * FRAME_SIZE_MS as u64) / 1000; // 960 samples at 48kHz

/// Encode recorded audio to Opus/OGG format
pub fn encode_to_opus_ogg(audio: &RecordedAudio) -> Result<Vec<u8>, EncoderError> {
    // Resample to 16kHz if needed
    let samples = audio.resample_to_16khz();

    if samples.is_empty() {
        return Err(EncoderError::EmptyAudio);
    }

    info!(
        "Encoding {} samples ({:.1}s) to Opus/OGG",
        samples.len(),
        samples.len() as f32 / SAMPLE_RATE as f32
    );

    // Create Opus encoder
    let mut encoder = Encoder::new(SAMPLE_RATE, CHANNELS, Application::Voip)
        .map_err(|e| EncoderError::OpusError(e.to_string()))?;

    encoder
        .set_bitrate(opus::Bitrate::Bits(BITRATE))
        .map_err(|e| EncoderError::OpusError(e.to_string()))?;

    // Prepare OGG writer
    let mut ogg_buffer = Vec::new();
    let serial = rand_serial();

    // Convert samples to i16 for Opus
    let samples_i16: Vec<i16> = samples
        .iter()
        .map(|&s| (s.clamp(-1.0, 1.0) * 32767.0) as i16)
        .collect();

    // Encode frames
    let mut encoded_packets: Vec<Vec<u8>> = Vec::new();

    for chunk in samples_i16.chunks(FRAME_SIZE_SAMPLES) {
        // Pad last frame if needed
        let frame: Vec<i16> = if chunk.len() < FRAME_SIZE_SAMPLES {
            let mut padded = chunk.to_vec();
            padded.resize(FRAME_SIZE_SAMPLES, 0);
            padded
        } else {
            chunk.to_vec()
        };

        // Encode frame
        let mut output = vec![0u8; 4000]; // Max Opus frame size
        let len = encoder
            .encode(&frame, &mut output)
            .map_err(|e| EncoderError::OpusError(e.to_string()))?;

        output.truncate(len);
        encoded_packets.push(output);
    }

    // Write OGG stream
    {
        let cursor = Cursor::new(&mut ogg_buffer);
        let mut writer = ogg::PacketWriter::new(cursor);

        // Write Opus ID header
        let id_header = create_opus_id_header();
        writer
            .write_packet(
                id_header,
                serial,
                PacketWriteEndInfo::EndPage,
                0, // granule_pos for header
            )
            .map_err(|e| EncoderError::OggError(e.to_string()))?;

        // Write Opus Comment header
        let comment_header = create_opus_comment_header();
        writer
            .write_packet(
                comment_header,
                serial,
                PacketWriteEndInfo::EndPage,
                0, // granule_pos for comment
            )
            .map_err(|e| EncoderError::OggError(e.to_string()))?;

        // Write audio packets
        // Granule positions must be at 48kHz per RFC 7845
        let total_packets = encoded_packets.len();
        let mut current_granule: u64 = 0;

        for (i, packet) in encoded_packets.into_iter().enumerate() {
            current_granule += GRANULE_PER_FRAME;
            let is_last = i == total_packets - 1;

            let end_info = if is_last {
                PacketWriteEndInfo::EndStream
            } else {
                PacketWriteEndInfo::NormalPacket
            };

            writer
                .write_packet(packet, serial, end_info, current_granule)
                .map_err(|e| EncoderError::OggError(e.to_string()))?;
        }
    }

    info!("Encoded to {} bytes OGG", ogg_buffer.len());
    Ok(ogg_buffer)
}

/// Create Opus ID header (RFC 7845)
fn create_opus_id_header() -> Vec<u8> {
    let mut header = Vec::with_capacity(19);

    // Magic signature "OpusHead"
    header.extend_from_slice(b"OpusHead");

    // Version (1)
    header.push(1);

    // Channel count (1 = mono)
    header.push(1);

    // Pre-skip (samples to skip at start) - typical value for 16kHz
    let pre_skip: u16 = 312;
    header.extend_from_slice(&pre_skip.to_le_bytes());

    // Input sample rate (original sample rate, for resampler reference)
    header.extend_from_slice(&SAMPLE_RATE.to_le_bytes());

    // Output gain (0 dB)
    header.extend_from_slice(&0u16.to_le_bytes());

    // Channel mapping family (0 = mono/stereo, no mapping table)
    header.push(0);

    header
}

/// Create Opus Comment header (RFC 7845)
fn create_opus_comment_header() -> Vec<u8> {
    let mut header = Vec::new();

    // Magic signature "OpusTags"
    header.extend_from_slice(b"OpusTags");

    // Vendor string
    let vendor = "whatsapp-rust";
    header.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    header.extend_from_slice(vendor.as_bytes());

    // User comment list count (0)
    header.extend_from_slice(&0u32.to_le_bytes());

    header
}

/// Generate a random serial number for the OGG stream
fn rand_serial() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(42);
    // Simple LCG
    seed.wrapping_mul(1103515245).wrapping_add(12345)
}

#[derive(Debug)]
pub enum EncoderError {
    EmptyAudio,
    OpusError(String),
    OggError(String),
}

impl std::fmt::Display for EncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAudio => write!(f, "No audio data to encode"),
            Self::OpusError(e) => write!(f, "Opus encoder error: {}", e),
            Self::OggError(e) => write!(f, "OGG writer error: {}", e),
        }
    }
}

impl std::error::Error for EncoderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opus_id_header() {
        let header = create_opus_id_header();
        assert_eq!(&header[0..8], b"OpusHead");
        assert_eq!(header[8], 1); // version
        assert_eq!(header[9], 1); // channels
    }

    #[test]
    fn test_opus_comment_header() {
        let header = create_opus_comment_header();
        assert_eq!(&header[0..8], b"OpusTags");
    }

    #[test]
    fn test_encode_simple_audio() {
        // Generate 1 second of silence
        let audio = RecordedAudio {
            samples: vec![0.0f32; 16000],
            sample_rate: 16000,
            duration_secs: 1,
        };

        let result = encode_to_opus_ogg(&audio);
        assert!(result.is_ok());

        let ogg_data = result.unwrap();
        // Check OGG magic number
        assert_eq!(&ogg_data[0..4], b"OggS");
    }
}
