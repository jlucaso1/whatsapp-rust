//! Real-time audio handling for VoIP calls
//!
//! This module provides streaming audio capture and playback for calls,
//! different from PTT which uses OGG container files.
//!
//! Architecture: Audio runs on a dedicated thread since cpal::Stream is !Send.
//! Communication happens via channels.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleRate, StreamConfig};
use log::{error, info, warn};
use opus::{Application, Channels, Decoder as OpusDecoder, Encoder as OpusEncoder};
use tokio::sync::mpsc;

/// Audio sample rate for WhatsApp calls (16kHz)
const CALL_SAMPLE_RATE: u32 = 16000;

/// Opus frame size in samples (20ms at 16kHz = 320 samples)
const FRAME_SIZE_SAMPLES: usize = 320;

/// Maximum Opus frame size in bytes
const MAX_OPUS_FRAME_SIZE: usize = 256;

/// Handle to a running audio capture session.
/// Drop this to stop capture.
pub struct AudioCaptureHandle {
    /// Stop signal
    stop_signal: Arc<AtomicBool>,
    /// Thread handle
    _thread: JoinHandle<()>,
}

impl AudioCaptureHandle {
    /// Stop the capture
    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

impl Drop for AudioCaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Result of starting audio capture.
pub struct AudioCaptureResult {
    /// Handle to control the capture thread.
    pub handle: AudioCaptureHandle,
    /// Receiver for Opus-encoded frames.
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// Start audio capture on a dedicated thread.
/// Returns a result containing the handle and a receiver for Opus-encoded frames.
pub fn start_audio_capture() -> Result<AudioCaptureResult, CallAudioError> {
    let (tx, rx) = mpsc::unbounded_channel();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = stop_signal.clone();

    let thread = std::thread::spawn(move || {
        if let Err(e) = run_audio_capture(tx, stop_signal_clone) {
            error!("Audio capture thread error: {}", e);
        }
    });

    Ok(AudioCaptureResult {
        handle: AudioCaptureHandle {
            stop_signal,
            _thread: thread,
        },
        rx,
    })
}

fn run_audio_capture(
    tx: mpsc::UnboundedSender<Vec<u8>>,
    stop_signal: Arc<AtomicBool>,
) -> Result<(), CallAudioError> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or(CallAudioError::NoInputDevice)?;

    info!(
        "Call audio input device: {}",
        device.name().unwrap_or_default()
    );

    // Find a config that supports our sample rate
    let supported = device
        .supported_input_configs()
        .map_err(|e| CallAudioError::DeviceError(e.to_string()))?;

    // Find a config that supports our sample rate
    // Accept mono or stereo (will downmix stereo to mono)
    let mut best_config = None;
    for cfg in supported {
        let sample_rate_ok = cfg.min_sample_rate().0 <= CALL_SAMPLE_RATE
            && cfg.max_sample_rate().0 >= CALL_SAMPLE_RATE;
        let channels_ok = cfg.channels() <= 2; // Mono or stereo

        if sample_rate_ok && channels_ok {
            // Prefer mono if available, but accept stereo
            if cfg.channels() == 1 || best_config.is_none() {
                best_config = Some(cfg.with_sample_rate(SampleRate(CALL_SAMPLE_RATE)));
                if cfg.channels() == 1 {
                    break; // Found ideal mono config
                }
            }
        }
    }

    let config: StreamConfig = best_config.ok_or(CallAudioError::NoSupportedConfig)?.into();

    info!(
        "Call audio capture config: {} Hz, {} channel(s)",
        config.sample_rate.0, config.channels
    );

    // Create Opus encoder
    let mut encoder = OpusEncoder::new(CALL_SAMPLE_RATE, Channels::Mono, Application::Voip)
        .map_err(|e| CallAudioError::EncoderError(e.to_string()))?;
    encoder
        .set_bitrate(opus::Bitrate::Bits(24000))
        .map_err(|e| CallAudioError::EncoderError(e.to_string()))?;

    // Sample buffer
    let sample_buffer = Arc::new(std::sync::Mutex::new(Vec::with_capacity(
        FRAME_SIZE_SAMPLES * 2,
    )));
    let sample_buffer_clone = sample_buffer.clone();
    let channels = config.channels as usize;

    // Build input stream
    let stream = device
        .build_input_stream(
            &config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                let mut buffer = sample_buffer_clone.lock().unwrap();
                if channels == 1 {
                    buffer.extend_from_slice(data);
                } else {
                    for chunk in data.chunks(channels) {
                        let mono: f32 = chunk.iter().sum::<f32>() / channels as f32;
                        buffer.push(mono);
                    }
                }
            },
            move |err| {
                error!("Call audio input error: {}", err);
            },
            None,
        )
        .map_err(|e| CallAudioError::StreamError(e.to_string()))?;

    stream
        .play()
        .map_err(|e| CallAudioError::StreamError(e.to_string()))?;

    info!("Audio capture started");

    // Encoding loop
    let mut opus_buffer = vec![0u8; MAX_OPUS_FRAME_SIZE];
    while !stop_signal.load(Ordering::Relaxed) {
        let samples_to_encode: Option<Vec<i16>> = {
            let mut buffer = sample_buffer.lock().unwrap();
            if buffer.len() >= FRAME_SIZE_SAMPLES {
                let samples: Vec<f32> = buffer.drain(..FRAME_SIZE_SAMPLES).collect();
                Some(
                    samples
                        .iter()
                        .map(|&s| (s.clamp(-1.0, 1.0) * 32767.0) as i16)
                        .collect(),
                )
            } else {
                None
            }
        };

        if let Some(samples) = samples_to_encode {
            match encoder.encode(&samples, &mut opus_buffer) {
                Ok(len) => {
                    let frame = opus_buffer[..len].to_vec();
                    if tx.send(frame).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("Opus encode error: {}", e);
                }
            }
        } else {
            // Sleep less to be more responsive - at 16kHz with 20ms frames,
            // we need to process 50 frames/second. 1ms sleep gives us
            // good responsiveness without burning CPU.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    drop(stream);
    info!("Audio capture stopped");
    Ok(())
}

/// Handle to a running audio playback session.
/// Drop this to stop playback.
pub struct AudioPlaybackHandle {
    /// Stop signal
    stop_signal: Arc<AtomicBool>,
    /// Thread handle
    _thread: JoinHandle<()>,
}

impl AudioPlaybackHandle {
    /// Stop the playback
    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

impl Drop for AudioPlaybackHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Result of starting audio playback.
pub struct AudioPlaybackResult {
    /// Handle to control the playback thread.
    pub handle: AudioPlaybackHandle,
    /// Sender for Opus-encoded frames.
    pub tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Start audio playback on a dedicated thread.
/// Returns a result containing the handle and a sender for Opus-encoded frames.
pub fn start_audio_playback() -> Result<AudioPlaybackResult, CallAudioError> {
    let (tx, rx) = mpsc::unbounded_channel();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = stop_signal.clone();

    let thread = std::thread::spawn(move || {
        if let Err(e) = run_audio_playback(rx, stop_signal_clone) {
            error!("Audio playback thread error: {}", e);
        }
    });

    Ok(AudioPlaybackResult {
        handle: AudioPlaybackHandle {
            stop_signal,
            _thread: thread,
        },
        tx,
    })
}

fn run_audio_playback(
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    stop_signal: Arc<AtomicBool>,
) -> Result<(), CallAudioError> {
    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or(CallAudioError::NoOutputDevice)?;

    info!(
        "Call audio output device: {}",
        device.name().unwrap_or_default()
    );

    let supported = device
        .supported_output_configs()
        .map_err(|e| CallAudioError::DeviceError(e.to_string()))?;

    let mut best_config = None;
    for cfg in supported {
        if cfg.min_sample_rate().0 <= CALL_SAMPLE_RATE
            && cfg.max_sample_rate().0 >= CALL_SAMPLE_RATE
        {
            best_config = Some(cfg.with_sample_rate(SampleRate(CALL_SAMPLE_RATE)));
            break;
        }
    }

    let config: StreamConfig = best_config.ok_or(CallAudioError::NoSupportedConfig)?.into();
    let output_channels = config.channels as usize;

    info!(
        "Call audio playback config: {} Hz, {} channel(s)",
        config.sample_rate.0, output_channels
    );

    // Create Opus decoder
    let mut decoder = OpusDecoder::new(CALL_SAMPLE_RATE, Channels::Mono)
        .map_err(|e| CallAudioError::EncoderError(e.to_string()))?;

    // Audio buffer for playback
    let audio_buffer = Arc::new(std::sync::Mutex::new(Vec::with_capacity(
        FRAME_SIZE_SAMPLES * 4,
    )));
    let audio_buffer_clone = audio_buffer.clone();

    // Build output stream
    let stream = device
        .build_output_stream(
            &config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                let mut buffer = audio_buffer_clone.lock().unwrap();
                let samples_needed = data.len() / output_channels;

                for (i, sample) in data.iter_mut().enumerate() {
                    let sample_idx = i / output_channels;
                    *sample = if sample_idx < buffer.len() {
                        buffer[sample_idx]
                    } else {
                        0.0
                    };
                }

                // Remove consumed samples
                let consumed = samples_needed.min(buffer.len());
                buffer.drain(..consumed);
            },
            move |err| {
                error!("Call audio output error: {}", err);
            },
            None,
        )
        .map_err(|e| CallAudioError::StreamError(e.to_string()))?;

    stream
        .play()
        .map_err(|e| CallAudioError::StreamError(e.to_string()))?;

    info!("Audio playback started");

    // Decoding loop
    let mut output = vec![0.0f32; FRAME_SIZE_SAMPLES];
    while !stop_signal.load(Ordering::Relaxed) {
        match rx.try_recv() {
            Ok(opus_frame) => match decoder.decode_float(&opus_frame, &mut output, false) {
                Ok(samples) => {
                    let mut buffer = audio_buffer.lock().unwrap();
                    buffer.extend_from_slice(&output[..samples]);
                }
                Err(e) => {
                    warn!("Opus decode error: {}", e);
                }
            },
            Err(mpsc::error::TryRecvError::Empty) => {
                // 1ms sleep for responsive packet processing
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }

    drop(stream);
    info!("Audio playback stopped");
    Ok(())
}

#[derive(Debug)]
pub enum CallAudioError {
    NoInputDevice,
    NoOutputDevice,
    NoSupportedConfig,
    DeviceError(String),
    StreamError(String),
    EncoderError(String),
}

impl std::fmt::Display for CallAudioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoInputDevice => write!(f, "No audio input device found"),
            Self::NoOutputDevice => write!(f, "No audio output device found"),
            Self::NoSupportedConfig => write!(f, "No supported audio configuration"),
            Self::DeviceError(e) => write!(f, "Audio device error: {}", e),
            Self::StreamError(e) => write!(f, "Audio stream error: {}", e),
            Self::EncoderError(e) => write!(f, "Opus encoder error: {}", e),
        }
    }
}

impl std::error::Error for CallAudioError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_size() {
        // 20ms at 16kHz = 320 samples
        assert_eq!(FRAME_SIZE_SAMPLES, 320);
    }
}
