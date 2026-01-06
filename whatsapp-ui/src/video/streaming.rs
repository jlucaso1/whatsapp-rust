//! Streaming video decoder with on-demand frame decoding and YUV GPU rendering
//!
//! Memory-efficient video decoder that stores compressed H.264 samples
//! and decodes frames on-demand. Uses GPUI's YUV surface for GPU-accelerated
//! color conversion (no CPU YUV→RGB conversion needed).
//!
//! Memory comparison for a 30-frame 480x848 video:
//! - Old (all frames BGRA): 30 × 1.6MB = 48MB
//! - Streaming BGRA: ~1MB H.264 + 1.6MB current frame = ~3MB
//! - **YUV streaming**: ~1MB H.264 + 0.6MB current frame = ~1.6MB (62% less!)

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use gpui::{YuvFormat, YuvFrameData};
use mp4::{Mp4Reader, TrackType};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;

use super::audio::VideoAudio;

/// NAL unit start code for Annex B format
const NAL_START_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x01];

/// NAL length size in AVCC format (typically 4 bytes for WhatsApp videos)
const NAL_LENGTH_SIZE: usize = 4;

/// A decoded video frame in YUV format (I420)
///
/// Memory efficient: YUV420 uses 1.5 bytes/pixel vs 4 bytes/pixel for BGRA.
/// GPU converts YUV→RGB during rendering via GPUI's surface element.
#[derive(Clone)]
pub struct StreamingFrame {
    /// YUV frame data for GPU rendering
    pub yuv_data: YuvFrameData,
    /// Presentation timestamp
    pub timestamp: Duration,
    /// Frame index
    pub index: usize,
}

/// H.264 sample in Annex B format (ready for decoder)
struct H264Sample {
    /// NAL units in Annex B format
    data: Vec<u8>,
    /// Whether this is a keyframe (IDR)
    is_keyframe: bool,
}

/// Streaming video decoder that decodes frames on-demand
///
/// Instead of pre-decoding all frames, this decoder stores compressed H.264
/// samples and decodes only when a frame is requested. Outputs YUV directly
/// for GPU rendering - no CPU color conversion needed.
///
/// Memory usage: O(compressed_size + yuv_frame_size)
/// - compressed_size: ~1-2MB for typical WhatsApp video
/// - yuv_frame_size: width × height × 1.5 bytes (~0.6MB for 480×848)
pub struct StreamingVideoDecoder {
    /// H.264 samples (Annex B format) - compressed, small
    samples: Vec<H264Sample>,
    /// SPS/PPS NAL units (needed to initialize decoder)
    sps_pps: Vec<u8>,
    /// Video dimensions
    width: u32,
    height: u32,
    /// Frame duration
    frame_duration: Duration,
    /// Total video duration
    duration: Duration,
    /// Current decoder state
    decoder: Decoder,
    /// Index of last decoded frame (-1 if none)
    last_decoded_index: i32,
    /// Currently decoded frame (only 1 in memory)
    current_frame: Option<StreamingFrame>,
    /// Decoded audio from the video
    audio: Option<VideoAudio>,
    /// Reusable buffer for Y plane (avoids allocation per frame)
    y_buffer: Vec<u8>,
    /// Reusable buffer for U plane
    u_buffer: Vec<u8>,
    /// Reusable buffer for V plane
    v_buffer: Vec<u8>,
}

impl StreamingVideoDecoder {
    /// Create a new streaming video decoder from MP4 data
    pub fn new(mp4_data: &[u8]) -> Result<Self> {
        log::info!(
            "StreamingVideoDecoder: parsing MP4 data ({} bytes)",
            mp4_data.len()
        );

        let cursor = Cursor::new(mp4_data);
        let mp4 = Mp4Reader::read_header(cursor, mp4_data.len() as u64)
            .context("Failed to read MP4 header")?;

        // Log all tracks found
        log::info!("MP4 contains {} tracks:", mp4.tracks().len());
        for (id, track) in mp4.tracks() {
            let track_type = track
                .track_type()
                .map(|t| format!("{:?}", t))
                .unwrap_or_else(|_| "Unknown".to_string());
            log::info!(
                "  Track {}: type={}, media_type={:?}, codec={:?}",
                id,
                track_type,
                track.media_type(),
                track
                    .video_profile()
                    .map(|p| format!("{:?}", p))
                    .unwrap_or_else(|_| "N/A".to_string())
            );
        }

        // Find video track
        let video_track = mp4
            .tracks()
            .values()
            .find(|t| matches!(t.track_type(), Ok(TrackType::Video)))
            .ok_or_else(|| anyhow!("No video track found in MP4"))?;

        let track_id = video_track.track_id();
        let duration = video_track.duration();
        let sample_count = video_track.sample_count();

        // Calculate FPS and frame duration
        let fps = if duration.as_secs_f64() > 0.0 {
            sample_count as f64 / duration.as_secs_f64()
        } else {
            30.0
        };
        let frame_duration = Duration::from_secs_f64(1.0 / fps);

        // Get video dimensions
        let width = video_track.width() as u32;
        let height = video_track.height() as u32;

        // Log detailed video track info
        log::info!(
            "Video track {}: {}x{}, {} samples, {:.2} fps, duration: {:.2}s",
            track_id,
            width,
            height,
            sample_count,
            fps,
            duration.as_secs_f64(),
        );
        log::info!(
            "Video track details: timescale={}, bitrate={} kbps",
            video_track.timescale(),
            video_track.bitrate() / 1000,
        );

        // Get SPS and PPS from the track
        let sps = video_track
            .sequence_parameter_set()
            .ok()
            .map(|s| s.to_vec());
        let pps = video_track.picture_parameter_set().ok().map(|s| s.to_vec());

        // Log SPS/PPS info
        log::info!(
            "SPS: {} bytes, PPS: {} bytes",
            sps.as_ref().map(|s| s.len()).unwrap_or(0),
            pps.as_ref().map(|s| s.len()).unwrap_or(0),
        );
        if let Some(ref sps_data) = sps
            && !sps_data.is_empty()
        {
            // Log first few bytes of SPS for debugging
            let preview: Vec<String> = sps_data
                .iter()
                .take(16)
                .map(|b| format!("{:02x}", b))
                .collect();
            log::debug!("SPS data (first 16 bytes): {}", preview.join(" "));

            // Parse H.264 profile from SPS (byte 1 after NAL header)
            // SPS NAL type is 7, so first byte is NAL header, then profile_idc
            if sps_data.len() >= 4 {
                let profile_idc = sps_data[1];
                let constraint_flags = sps_data[2];
                let level_idc = sps_data[3];

                let profile_name = match profile_idc {
                    66 => "Baseline",
                    77 => "Main",
                    88 => "Extended",
                    100 => "High",
                    110 => "High 10",
                    122 => "High 4:2:2",
                    244 => "High 4:4:4 Predictive",
                    _ => "Unknown",
                };

                log::info!(
                    "H.264 Profile: {} (profile_idc={}), Level: {}.{}, Constraints: 0x{:02x}",
                    profile_name,
                    profile_idc,
                    level_idc / 10,
                    level_idc % 10,
                    constraint_flags
                );

                // Warn about potentially problematic profiles
                if profile_idc >= 100 {
                    log::warn!(
                        "Video uses {} profile - OpenH264 may have limited support for advanced features",
                        profile_name
                    );
                }
            }
        }

        // Build SPS/PPS in Annex B format
        let sps_pps = Self::build_sps_pps_annexb(sps.as_deref(), pps.as_deref());
        log::info!("Built SPS/PPS Annex B data: {} bytes", sps_pps.len());

        // Extract H.264 samples (keep compressed)
        let samples = Self::extract_samples(mp4_data, track_id, sample_count)?;

        // Calculate memory savings
        let compressed_size: usize = samples.iter().map(|s| s.data.len()).sum();
        let yuv_frame_size = (width as usize * height as usize * 3) / 2; // YUV420 = 1.5 bytes/pixel
        let bgra_frame_size = width as usize * height as usize * 4;
        log::info!(
            "StreamingVideoDecoder: H.264={} KB, YUV frame={} KB (vs {} KB BGRA, {:.0}% savings)",
            compressed_size / 1024,
            yuv_frame_size / 1024,
            bgra_frame_size / 1024,
            (1.0 - yuv_frame_size as f64 / bgra_frame_size as f64) * 100.0
        );

        // Create decoder
        let decoder = Decoder::new().context("Failed to create H.264 decoder")?;

        // Extract audio
        let audio = Self::extract_audio(mp4_data);

        // Pre-allocate YUV plane buffers (reused for each frame)
        let y_size = (width as usize) * (height as usize);
        let uv_width = (width as usize).div_ceil(2);
        let uv_height = (height as usize).div_ceil(2);
        let uv_size = uv_width * uv_height;

        Ok(Self {
            samples,
            sps_pps,
            width,
            height,
            frame_duration,
            duration,
            decoder,
            last_decoded_index: -1,
            current_frame: None,
            audio,
            y_buffer: Vec::with_capacity(y_size),
            u_buffer: Vec::with_capacity(uv_size),
            v_buffer: Vec::with_capacity(uv_size),
        })
    }

    /// Extract H.264 samples from MP4 without decoding
    fn extract_samples(
        mp4_data: &[u8],
        track_id: u32,
        sample_count: u32,
    ) -> Result<Vec<H264Sample>> {
        let cursor = Cursor::new(mp4_data);
        let mut mp4 = Mp4Reader::read_header(cursor, mp4_data.len() as u64)?;

        let mut samples = Vec::with_capacity(sample_count as usize);
        let mut keyframe_count = 0;
        let mut total_size = 0usize;
        let mut failed_reads = 0;

        for sample_idx in 1..=sample_count {
            match mp4.read_sample(track_id, sample_idx) {
                Ok(Some(sample)) => {
                    // Log first sample's raw data for debugging
                    if sample_idx == 1 {
                        let preview: Vec<String> = sample
                            .bytes
                            .iter()
                            .take(32)
                            .map(|b| format!("{:02x}", b))
                            .collect();
                        log::debug!("First sample raw data (32 bytes): {}", preview.join(" "));
                        log::debug!("First sample size: {} bytes", sample.bytes.len());
                    }

                    // Convert AVCC to Annex B format
                    let annexb_data = Self::avcc_to_annexb(&sample.bytes, NAL_LENGTH_SIZE);

                    // Log NAL unit types in first sample
                    if sample_idx == 1 {
                        let nal_types = Self::get_nal_types(&annexb_data);
                        log::info!("First sample NAL types: {:?}", nal_types);
                    }

                    // Check if this is a keyframe by looking at NAL unit type
                    let is_keyframe = Self::is_keyframe(&annexb_data);
                    if is_keyframe {
                        keyframe_count += 1;
                    }
                    total_size += annexb_data.len();

                    samples.push(H264Sample {
                        data: annexb_data,
                        is_keyframe,
                    });
                }
                Ok(None) => {
                    failed_reads += 1;
                    log::warn!("Sample {} returned None", sample_idx);
                }
                Err(e) => {
                    failed_reads += 1;
                    log::warn!("Failed to read sample {}: {}", sample_idx, e);
                }
            }
        }

        log::info!(
            "Extracted {} samples: {} keyframes, {} failed reads, total size: {} KB",
            samples.len(),
            keyframe_count,
            failed_reads,
            total_size / 1024
        );

        if samples.is_empty() {
            return Err(anyhow!("No video samples could be extracted"));
        }

        // Log keyframe positions if there are issues
        if keyframe_count == 0 {
            log::warn!("No keyframes detected! Video may not decode correctly.");
        }

        Ok(samples)
    }

    /// Get all NAL unit types in the data (for debugging)
    fn get_nal_types(annexb_data: &[u8]) -> Vec<u8> {
        let mut types = Vec::new();
        let mut i = 0;
        while i + 4 < annexb_data.len() {
            if annexb_data[i..i + 4] == [0, 0, 0, 1]
                && let Some(&byte) = annexb_data.get(i + 4)
            {
                types.push(byte & 0x1F);
            }
            i += 1;
        }
        types
    }

    /// Check if NAL units contain an IDR (keyframe)
    fn is_keyframe(annexb_data: &[u8]) -> bool {
        // Look for NAL unit type 5 (IDR slice)
        let mut i = 0;
        while i + 4 < annexb_data.len() {
            if annexb_data[i..i + 4] == [0, 0, 0, 1] {
                let nal_type = annexb_data.get(i + 4).map(|b| b & 0x1F).unwrap_or(0);
                if nal_type == 5 {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    /// Get total number of frames
    pub fn frame_count(&self) -> usize {
        self.samples.len()
    }

    /// Get video duration
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Seek to a specific time and decode that frame
    pub fn seek(&mut self, time: Duration) {
        let target_index = (time.as_secs_f64() / self.frame_duration.as_secs_f64()) as usize;
        let target_index = target_index.min(self.samples.len().saturating_sub(1));
        self.seek_to_frame(target_index);
    }

    /// Seek to a specific frame index
    pub fn seek_to_frame(&mut self, target_index: usize) {
        if target_index >= self.samples.len() {
            return;
        }

        // If we're already at this frame, no need to decode
        if let Some(ref frame) = self.current_frame
            && frame.index == target_index
        {
            return;
        }

        // Determine where to start decoding from
        let start_index = if target_index as i32 > self.last_decoded_index {
            // Moving forward - continue from where we are
            (self.last_decoded_index + 1) as usize
        } else {
            // Moving backward - need to reset decoder and start from beginning
            self.reset_decoder();
            0
        };

        // Decode frames from start_index to target_index
        for idx in start_index..=target_index {
            self.decode_frame(idx, idx == target_index);
        }
    }

    /// Reset decoder state (needed when seeking backward)
    fn reset_decoder(&mut self) {
        // Create new decoder instance
        if let Ok(new_decoder) = Decoder::new() {
            self.decoder = new_decoder;
            self.last_decoded_index = -1;

            // Feed SPS/PPS to initialize
            if !self.sps_pps.is_empty() {
                let _ = self.decoder.decode(&self.sps_pps);
            }
        }
    }

    /// Decode a single frame
    fn decode_frame(&mut self, index: usize, keep_output: bool) {
        if index >= self.samples.len() {
            return;
        }

        let is_keyframe = self.samples[index].is_keyframe;
        let sample_size = self.samples[index].data.len();

        // Log first frame decode attempt
        if index == 0 {
            log::info!(
                "Decoding first frame: keyframe={}, size={} bytes, keep_output={}",
                is_keyframe,
                sample_size,
                keep_output
            );
        }

        // For keyframes, feed SPS/PPS first
        if is_keyframe && !self.sps_pps.is_empty() {
            log::debug!("Feeding SPS/PPS before keyframe {}", index);
            let _ = self.decoder.decode(&self.sps_pps);
        }

        // Decode the sample
        match self.decoder.decode(&self.samples[index].data) {
            Ok(Some(yuv)) => {
                self.last_decoded_index = index as i32;

                let (y_stride, u_stride, v_stride) = yuv.strides();
                let y_len = yuv.y().len();
                let u_len = yuv.u().len();
                let v_len = yuv.v().len();

                // Log first successful decode
                if index == 0 {
                    log::info!(
                        "First frame decoded: strides=({}, {}, {}), plane sizes=({}, {}, {})",
                        y_stride,
                        u_stride,
                        v_stride,
                        y_len,
                        u_len,
                        v_len
                    );
                }

                // Only create YUV frame if we need to keep this frame
                if keep_output {
                    let width = self.width as usize;
                    let height = self.height as usize;
                    let uv_width = width.div_ceil(2);
                    let uv_height = height.div_ceil(2);

                    // Extract planes into reusable buffers (no allocation if capacity sufficient)
                    extract_plane_into(&mut self.y_buffer, yuv.y(), width, height, y_stride);
                    extract_plane_into(&mut self.u_buffer, yuv.u(), uv_width, uv_height, u_stride);
                    extract_plane_into(&mut self.v_buffer, yuv.v(), uv_width, uv_height, v_stride);

                    // Create YuvFrameData - Arc::from copies slice data
                    let yuv_data = YuvFrameData {
                        format: YuvFormat::I420,
                        width: self.width,
                        height: self.height,
                        y_plane: Arc::from(self.y_buffer.as_slice()),
                        u_plane: Arc::from(self.u_buffer.as_slice()),
                        v_plane: Some(Arc::from(self.v_buffer.as_slice())),
                        y_stride: self.width,
                        u_stride: uv_width as u32,
                        v_stride: Some(uv_width as u32),
                    };

                    let timestamp = self.frame_duration * index as u32;
                    self.current_frame = Some(StreamingFrame {
                        yuv_data,
                        timestamp,
                        index,
                    });

                    if index == 0 {
                        log::info!(
                            "First frame YUV created: Y={} bytes, U={} bytes, V={} bytes",
                            self.y_buffer.len(),
                            self.u_buffer.len(),
                            self.v_buffer.len()
                        );
                    }
                }
            }
            Ok(None) => {
                // Decoder needs more data (buffering)
                self.last_decoded_index = index as i32;
                if index == 0 {
                    log::warn!(
                        "First frame returned None (decoder buffering) - may need more data"
                    );
                }
            }
            Err(e) => {
                // Get NAL types for debugging
                let nal_types = Self::get_nal_types(&self.samples[index].data);
                let error_str = format!("{}", e);

                // Parse native error code and provide human-readable explanation
                let error_explanation = if error_str.contains("Native:") {
                    // Extract native code from error string like "Native:16"
                    let native_code = error_str
                        .split("Native:")
                        .nth(1)
                        .and_then(|s| s.split('.').next())
                        .and_then(|s| s.trim().parse::<i32>().ok())
                        .unwrap_or(-1);

                    match native_code {
                        1 => "dsFramePending - decoder needs more data, not enough NAL units",
                        2 => "dsRefLost - reference frame lost, may need to seek to keyframe",
                        3 => "dsBitstreamError - corrupted bitstream or invalid NAL",
                        4 => "dsDepLayerLost - dependency layer lost",
                        5 => "dsNoParamSets - missing SPS/PPS parameter sets",
                        6 => "dsDataErrorConcealed - error concealed, frame may be corrupted",
                        16 => {
                            "dsInvalidArgument - invalid data passed to decoder (possibly wrong NAL format or corrupted frame)"
                        }
                        32 => "dsInitialOptExpected - initialization option expected",
                        64 => "dsOutOfMemory - decoder ran out of memory",
                        _ => "unknown error code",
                    }
                } else {
                    "see error details above"
                };

                log::warn!(
                    "Failed to decode frame {} (keyframe={}, size={} bytes, NAL types={:?}): {} - {}",
                    index,
                    is_keyframe,
                    sample_size,
                    nal_types,
                    e,
                    error_explanation
                );

                // If this is after many consecutive failures, it might indicate a codec issue
                if index > 0 && index.is_multiple_of(100) {
                    log::warn!(
                        "Multiple decode failures - video may use unsupported H.264 features (B-frames, high profile, etc.)"
                    );
                }

                self.last_decoded_index = index as i32;
            }
        }
    }

    /// Get current decoded frame
    pub fn current_frame(&self) -> Option<&StreamingFrame> {
        self.current_frame.as_ref()
    }

    /// Reset to first frame
    pub fn reset(&mut self) {
        self.reset_decoder();
        self.current_frame = None;
        self.seek_to_frame(0);
    }

    /// Take the audio data (consumes it from the decoder)
    pub fn take_audio(&mut self) -> Option<VideoAudio> {
        self.audio.take()
    }

    /// Convert AVCC format NAL units to Annex B format
    fn avcc_to_annexb(avcc_data: &[u8], nal_length_size: usize) -> Vec<u8> {
        let mut annexb = Vec::with_capacity(avcc_data.len() + 128);
        let mut pos = 0;

        while pos + nal_length_size <= avcc_data.len() {
            let mut nal_len: usize = 0;
            for i in 0..nal_length_size {
                nal_len = (nal_len << 8) | (avcc_data[pos + i] as usize);
            }
            pos += nal_length_size;

            if pos + nal_len > avcc_data.len() {
                break;
            }

            annexb.extend_from_slice(NAL_START_CODE);
            annexb.extend_from_slice(&avcc_data[pos..pos + nal_len]);
            pos += nal_len;
        }

        annexb
    }

    /// Build Annex B format data from SPS and PPS
    fn build_sps_pps_annexb(sps: Option<&[u8]>, pps: Option<&[u8]>) -> Vec<u8> {
        let mut annexb = Vec::new();

        if let Some(sps_data) = sps
            && !sps_data.is_empty()
        {
            annexb.extend_from_slice(NAL_START_CODE);
            annexb.extend_from_slice(sps_data);
        }

        if let Some(pps_data) = pps
            && !pps_data.is_empty()
        {
            annexb.extend_from_slice(NAL_START_CODE);
            annexb.extend_from_slice(pps_data);
        }

        annexb
    }

    /// Extract audio from MP4
    fn extract_audio(mp4_data: &[u8]) -> Option<VideoAudio> {
        super::audio::extract_audio_from_mp4(mp4_data)
    }
}

/// Extract a plane from strided buffer into a reusable buffer (no allocation)
fn extract_plane_into(dst: &mut Vec<u8>, src: &[u8], width: usize, height: usize, stride: usize) {
    let expected_size = width * height;
    dst.clear();

    // Ensure capacity without reallocating if already large enough
    if dst.capacity() < expected_size {
        dst.reserve(expected_size - dst.capacity());
    }

    if stride == width {
        // No padding, direct copy
        let end = expected_size.min(src.len());
        dst.extend_from_slice(&src[..end]);
    } else {
        // Has padding, copy row by row
        for row in 0..height {
            let row_start = row * stride;
            let row_end = row_start + width;
            if row_end <= src.len() {
                dst.extend_from_slice(&src[row_start..row_end]);
            }
        }
    }
}
