//! Audio playback using cpal
//!
//! Plays Opus/OGG audio files for PTT voice message playback.

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Stream, StreamConfig};
use log::{error, info, warn};
use ogg::reading::PacketReader;
use opus::{Channels, Decoder as OpusDecoder};
use tokio::sync::oneshot;

/// Audio player for PTT voice messages
pub struct AudioPlayer {
    /// cpal stream handle (kept alive while playing)
    stream: Option<Stream>,
    /// Whether currently playing
    is_playing: Arc<AtomicBool>,
    /// Current playback position in samples
    position: Arc<AtomicU64>,
    /// Total samples in current audio
    total_samples: u64,
    /// Sample rate of output device
    sample_rate: u32,
    /// Sender to notify when playback completes (one-shot)
    completion_tx: Option<oneshot::Sender<()>>,
}

impl Default for AudioPlayer {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioPlayer {
    /// Create a new audio player
    pub fn new() -> Self {
        Self {
            stream: None,
            is_playing: Arc::new(AtomicBool::new(false)),
            position: Arc::new(AtomicU64::new(0)),
            total_samples: 0,
            sample_rate: 48000,
            completion_tx: None,
        }
    }

    /// Subscribe to playback completion.
    /// Returns a receiver that will be notified when playback completes.
    /// Only one subscriber is supported at a time (calling again replaces previous).
    pub fn on_complete(&mut self) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.completion_tx = Some(tx);
        rx
    }

    /// Check if currently playing
    pub fn is_playing(&self) -> bool {
        self.is_playing.load(Ordering::Relaxed)
    }

    /// Play OGG audio data
    pub fn play(&mut self, ogg_data: Vec<u8>) -> Result<(), PlayerError> {
        // Decode the OGG/Opus data
        let samples = decode_ogg(&ogg_data)?;
        if samples.is_empty() {
            return Err(PlayerError::EmptyAudio);
        }

        info!("Decoded {} samples for playback", samples.len());

        // Play the decoded samples
        self.play_samples(samples, 48000)
    }

    /// Play raw f32 PCM samples at the specified sample rate
    pub fn play_samples(
        &mut self,
        samples: Vec<f32>,
        src_sample_rate: u32,
    ) -> Result<(), PlayerError> {
        // Stop any current playback, but preserve the completion sender
        // (it may have been set by on_complete() before this call)
        let saved_completion_tx = self.completion_tx.take();
        self.stop();
        self.completion_tx = saved_completion_tx;

        if samples.is_empty() {
            return Err(PlayerError::EmptyAudio);
        }

        info!(
            "Playing {} samples at {} Hz",
            samples.len(),
            src_sample_rate
        );

        // Get output device
        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or(PlayerError::NoOutputDevice)?;

        info!("Using output device: {}", device.name().unwrap_or_default());

        // Get supported config - prefer 48kHz which matches Opus decoder output
        let supported_configs: Vec<_> = device
            .supported_output_configs()
            .map_err(|e| PlayerError::DeviceError(e.to_string()))?
            .collect();

        if supported_configs.is_empty() {
            return Err(PlayerError::NoSupportedConfig);
        }

        // Find config that supports 48kHz, or fall back to first available
        let config: StreamConfig = supported_configs
            .iter()
            .find(|c| c.min_sample_rate().0 <= 48000 && c.max_sample_rate().0 >= 48000)
            .map(|c| c.with_sample_rate(cpal::SampleRate(48000)))
            .unwrap_or_else(|| {
                // Fall back to minimum sample rate of first config (usually more reasonable)
                let first = &supported_configs[0];
                first.with_sample_rate(first.min_sample_rate())
            })
            .into();
        self.sample_rate = config.sample_rate.0;
        let output_channels = config.channels as usize;

        info!(
            "Output config: {} Hz, {} channels",
            config.sample_rate.0, output_channels
        );

        // Resample if needed
        let resampled =
            resample_audio(&samples, src_sample_rate, self.sample_rate, output_channels);
        self.total_samples = resampled.len() as u64;

        // Setup shared state
        let is_playing = self.is_playing.clone();
        let position = self.position.clone();
        position.store(0, Ordering::Relaxed);
        is_playing.store(true, Ordering::Relaxed);

        // Move completion sender into Arc<Mutex> so callback can take it once
        let completion_tx: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(self.completion_tx.take()));

        // Create audio buffer for playback
        let audio_data = Arc::new(resampled);
        let audio_data_clone = audio_data.clone();

        let stream = device
            .build_output_stream(
                &config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                    let mut pos = position.load(Ordering::Relaxed) as usize;
                    let audio = &audio_data_clone;

                    for sample in data.iter_mut() {
                        if pos < audio.len() {
                            *sample = audio[pos];
                            pos += 1;
                        } else {
                            *sample = 0.0;
                            // Mark as done and notify completion (only once)
                            if is_playing.swap(false, Ordering::Relaxed)
                                && let Ok(mut guard) = completion_tx.lock()
                                && let Some(tx) = guard.take()
                            {
                                let _ = tx.send(());
                            }
                        }
                    }

                    position.store(pos as u64, Ordering::Relaxed);
                },
                move |err| {
                    error!("Audio output error: {}", err);
                },
                None,
            )
            .map_err(|e| PlayerError::StreamError(e.to_string()))?;

        stream
            .play()
            .map_err(|e| PlayerError::StreamError(e.to_string()))?;

        self.stream = Some(stream);
        info!("Audio playback started");

        Ok(())
    }

    /// Stop playback
    pub fn stop(&mut self) {
        if let Some(stream) = self.stream.take() {
            drop(stream);
        }
        self.is_playing.store(false, Ordering::Relaxed);
        self.position.store(0, Ordering::Relaxed);
        self.total_samples = 0;
        // Drop the completion sender to signal cancellation to any waiting task
        // (the receiver will get a Canceled error, which is handled gracefully)
        self.completion_tx = None;
    }

    /// Pause playback
    pub fn pause(&mut self) {
        if let Some(ref stream) = self.stream {
            let _ = stream.pause();
            self.is_playing.store(false, Ordering::Relaxed);
        }
    }

    /// Resume playback
    pub fn resume(&mut self) {
        if let Some(ref stream) = self.stream {
            let _ = stream.play();
            self.is_playing.store(true, Ordering::Relaxed);
        }
    }
}

/// Decode OGG/Opus audio to f32 samples using ogg + opus crates
fn decode_ogg(ogg_data: &[u8]) -> Result<Vec<f32>, PlayerError> {
    let cursor = Cursor::new(ogg_data);
    let mut packet_reader = PacketReader::new(cursor);

    let mut all_samples: Vec<f32> = Vec::new();
    let mut packet_count = 0;
    let mut decoder: Option<OpusDecoder> = None;
    let mut sample_rate = 48000u32; // Default to 48kHz

    // Read all OGG packets
    while let Some(packet) = packet_reader
        .read_packet()
        .map_err(|e| PlayerError::DecodeError(format!("Failed to read OGG packet: {}", e)))?
    {
        packet_count += 1;

        // First packet is OpusHead header
        if packet_count == 1 {
            // Parse OpusHead to get channel count and sample rate
            // Format: "OpusHead" (8 bytes) + version (1) + channels (1) + pre-skip (2) + sample_rate (4) + ...
            if packet.data.len() >= 12 && &packet.data[0..8] == b"OpusHead" {
                let channels = packet.data[9];
                // Input sample rate is at bytes 12-15 (little endian)
                if packet.data.len() >= 16 {
                    sample_rate = u32::from_le_bytes([
                        packet.data[12],
                        packet.data[13],
                        packet.data[14],
                        packet.data[15],
                    ]);
                }
                info!(
                    "OpusHead: {} channel(s), {} Hz input sample rate",
                    channels, sample_rate
                );

                // Opus decoder always works at 48kHz internally
                // Use mono or stereo based on header
                let opus_channels = if channels > 1 {
                    Channels::Stereo
                } else {
                    Channels::Mono
                };

                decoder = Some(OpusDecoder::new(48000, opus_channels).map_err(|e| {
                    PlayerError::DecodeError(format!("Failed to create Opus decoder: {}", e))
                })?);
            }
            continue;
        }

        // Second packet is OpusTags - skip it
        if packet_count == 2 {
            continue;
        }

        // Ensure decoder is initialized (create default if header wasn't parsed)
        if decoder.is_none() {
            decoder = Some(OpusDecoder::new(48000, Channels::Mono).map_err(|e| {
                PlayerError::DecodeError(format!("Failed to create Opus decoder: {}", e))
            })?);
        }
        let Some(dec) = decoder.as_mut() else {
            // This should be unreachable since we just ensured decoder is Some
            return Err(PlayerError::DecodeError(
                "Opus decoder initialization failed".to_string(),
            ));
        };

        // Decode Opus packet to f32 samples
        // Max frame size at 48kHz is 5760 samples (120ms)
        let mut output = vec![0.0f32; 5760 * 2]; // *2 for potential stereo
        match dec.decode_float(&packet.data, &mut output, false) {
            Ok(samples_decoded) => {
                output.truncate(samples_decoded);
                all_samples.extend_from_slice(&output);
            }
            Err(e) => {
                warn!("Error decoding Opus packet {}: {}", packet_count, e);
                // Continue with other packets
            }
        }
    }

    info!(
        "Decoded {} Opus packets, {} total samples",
        packet_count,
        all_samples.len()
    );

    if all_samples.is_empty() {
        return Err(PlayerError::DecodeError(
            "No audio samples decoded".to_string(),
        ));
    }

    Ok(all_samples)
}

/// Resample audio from source rate to target rate
fn resample_audio(samples: &[f32], src_rate: u32, dst_rate: u32, channels: usize) -> Vec<f32> {
    // Guard against invalid sample rates
    if src_rate == 0 || dst_rate == 0 {
        return samples.to_vec();
    }

    if src_rate == dst_rate && channels == 1 {
        return samples.to_vec();
    }

    let ratio = dst_rate as f32 / src_rate as f32;
    let output_len = (samples.len() as f32 * ratio) as usize;
    let mut output = Vec::with_capacity(output_len * channels);

    for i in 0..output_len {
        let src_idx = (i as f32 / ratio) as usize;
        let sample = if src_idx < samples.len() {
            samples[src_idx]
        } else {
            0.0
        };

        // Duplicate for all output channels
        for _ in 0..channels {
            output.push(sample);
        }
    }

    output
}

#[derive(Debug)]
pub enum PlayerError {
    NoOutputDevice,
    NoSupportedConfig,
    EmptyAudio,
    DeviceError(String),
    StreamError(String),
    DecodeError(String),
}

impl std::fmt::Display for PlayerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoOutputDevice => write!(f, "No audio output device found"),
            Self::NoSupportedConfig => write!(f, "No supported audio configuration"),
            Self::EmptyAudio => write!(f, "No audio data to play"),
            Self::DeviceError(e) => write!(f, "Audio device error: {}", e),
            Self::StreamError(e) => write!(f, "Audio stream error: {}", e),
            Self::DecodeError(e) => write!(f, "Audio decode error: {}", e),
        }
    }
}

impl std::error::Error for PlayerError {}
