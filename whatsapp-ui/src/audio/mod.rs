//! Audio module for PTT voice message recording and encoding
//!
//! This module provides:
//! - Audio capture using cpal
//! - Opus encoding to OGG container
//! - Waveform generation for WhatsApp PTT messages
//! - Audio playback for received voice messages
//! - Real-time audio for VoIP calls
//! - Complete call media pipeline with SRTP/RTP

mod call_audio;
mod call_media_pipeline;
mod encoder;
mod player;
mod recorder;
mod waveform;

pub use call_audio::{
    AudioCaptureHandle, AudioPlaybackHandle, start_audio_capture, start_audio_playback,
};
pub use call_media_pipeline::{
    CallMediaPipelineConfig, CallMediaPipelineHandle, start_call_media_pipeline,
};
pub use encoder::encode_to_opus_ogg;
pub use player::AudioPlayer;
pub use recorder::AudioRecorder;
pub use waveform::generate_waveform;
