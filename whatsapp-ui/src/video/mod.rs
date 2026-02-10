//! Video module for video message playback
//!
//! This module provides:
//! - MP4 demuxing and H.264 software decoding via OpenH264
//! - Memory-efficient streaming decoder (on-demand frame decoding, ~16x less memory)
//! - Video player state management
//! - Audio extraction from video files (for video audio track playback)

mod audio;
mod player;
mod streaming;

// Memory-efficient streaming decoder (on-demand decoding, ~3MB vs ~48MB)
pub use streaming::StreamingVideoDecoder;

// Video player state machine
pub use player::{VideoPlayer, VideoPlayerState};
