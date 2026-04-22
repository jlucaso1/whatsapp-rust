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

/// Audio player for PTT voice messages.
pub struct AudioPlayer {
    stream: Option<Stream>,
    is_playing: Arc<AtomicBool>,
    position: Arc<AtomicU64>,
    total_samples: u64,
    sample_rate: u32,
    completion_tx: Option<oneshot::Sender<()>>,
}

impl Default for AudioPlayer {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioPlayer {
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

    /// Returns a receiver that fires when playback completes.
    pub fn on_complete(&mut self) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.completion_tx = Some(tx);
        rx
    }

    pub fn is_playing(&self) -> bool {
        self.is_playing.load(Ordering::Relaxed)
    }

    pub fn play(&mut self, ogg_data: Vec<u8>) -> Result<(), PlayerError> {
        let samples = decode_ogg(&ogg_data)?;
        if samples.is_empty() {
            return Err(PlayerError::EmptyAudio);
        }

        info!("Decoded {} samples for playback", samples.len());
        self.play_samples(samples, 48000)
    }

    /// Play raw f32 PCM samples at the specified sample rate.
    pub fn play_samples(
        &mut self,
        samples: Vec<f32>,
        src_sample_rate: u32,
    ) -> Result<(), PlayerError> {
        // Preserve completion sender through stop() since it may have been set by on_complete()
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

        let host = cpal::default_host();
        let device = host
            .default_output_device()
            .ok_or(PlayerError::NoOutputDevice)?;

        info!("Using output device: {}", device.name().unwrap_or_default());

        let supported_configs: Vec<_> = device
            .supported_output_configs()
            .map_err(|e| PlayerError::DeviceError(e.to_string()))?
            .collect();

        if supported_configs.is_empty() {
            return Err(PlayerError::NoSupportedConfig);
        }

        let config: StreamConfig = supported_configs
            .iter()
            .find(|c| c.min_sample_rate().0 <= 48000 && c.max_sample_rate().0 >= 48000)
            .map(|c| c.with_sample_rate(cpal::SampleRate(48000)))
            .unwrap_or_else(|| {
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

        let resampled =
            resample_audio(&samples, src_sample_rate, self.sample_rate, output_channels);
        self.total_samples = resampled.len() as u64;

        let is_playing = self.is_playing.clone();
        let position = self.position.clone();
        position.store(0, Ordering::Relaxed);
        is_playing.store(true, Ordering::Relaxed);

        let completion_tx: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(self.completion_tx.take()));
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

    pub fn stop(&mut self) {
        self.stream.take();
        self.is_playing.store(false, Ordering::Relaxed);
        self.position.store(0, Ordering::Relaxed);
        self.total_samples = 0;
        self.completion_tx = None;
    }

    pub fn pause(&mut self) {
        if let Some(ref stream) = self.stream {
            let _ = stream.pause();
            self.is_playing.store(false, Ordering::Relaxed);
        }
    }

    pub fn resume(&mut self) {
        if let Some(ref stream) = self.stream {
            let _ = stream.play();
            self.is_playing.store(true, Ordering::Relaxed);
        }
    }
}

fn decode_ogg(ogg_data: &[u8]) -> Result<Vec<f32>, PlayerError> {
    let cursor = Cursor::new(ogg_data);
    let mut packet_reader = PacketReader::new(cursor);
    let mut all_samples: Vec<f32> = Vec::new();
    let mut packet_count = 0;
    let mut decoder: Option<OpusDecoder> = None;

    while let Some(packet) = packet_reader
        .read_packet()
        .map_err(|e| PlayerError::DecodeError(format!("OGG read error: {}", e)))?
    {
        packet_count += 1;

        // First packet: OpusHead header, second packet: OpusTags (skip both)
        if packet_count == 1 {
            if packet.data.len() >= 12 && &packet.data[0..8] == b"OpusHead" {
                let channels = packet.data[9];
                let opus_channels = if channels > 1 {
                    Channels::Stereo
                } else {
                    Channels::Mono
                };
                decoder =
                    Some(OpusDecoder::new(48000, opus_channels).map_err(|e| {
                        PlayerError::DecodeError(format!("Opus decoder init: {}", e))
                    })?);
            }
            continue;
        }
        if packet_count == 2 {
            continue;
        }

        // Create default decoder if header wasn't parsed
        let dec = decoder.get_or_insert_with(|| {
            OpusDecoder::new(48000, Channels::Mono).expect("default decoder")
        });

        let mut output = vec![0.0f32; 5760 * 2];
        match dec.decode_float(&packet.data, &mut output, false) {
            Ok(n) => {
                output.truncate(n);
                all_samples.extend_from_slice(&output);
            }
            Err(e) => warn!("Opus decode error (packet {}): {}", packet_count, e),
        }
    }

    info!(
        "Decoded {} packets, {} samples",
        packet_count,
        all_samples.len()
    );

    if all_samples.is_empty() {
        return Err(PlayerError::DecodeError("No samples decoded".to_string()));
    }

    Ok(all_samples)
}

fn resample_audio(samples: &[f32], src_rate: u32, dst_rate: u32, channels: usize) -> Vec<f32> {
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
        let sample = samples.get(src_idx).copied().unwrap_or(0.0);
        output.extend(std::iter::repeat_n(sample, channels));
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
