//! Audio module for PTT voice message recording and encoding
//!
//! This module provides:
//! - Audio capture using cpal
//! - Opus encoding to OGG container
//! - Waveform generation for WhatsApp PTT messages
//! - Audio playback for received voice messages
//! - Real-time audio for VoIP calls

mod call_audio;
mod encoder;
mod player;
mod recorder;
mod waveform;

pub use call_audio::{
    AudioCaptureHandle, AudioPlaybackHandle, start_audio_capture, start_audio_playback,
};
pub use encoder::encode_to_opus_ogg;
pub use player::AudioPlayer;
pub use recorder::AudioRecorder;
pub use waveform::generate_waveform;
