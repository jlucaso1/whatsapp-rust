//! Video player state management

use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::YuvFrameData;
use tokio::sync::oneshot;

use super::audio::VideoAudio;
use super::streaming::StreamingVideoDecoder;

/// Video player state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoPlayerState {
    /// Player is idle, showing thumbnail
    Idle,
    /// Video is being downloaded
    Downloading,
    /// Video is being decoded
    Decoding,
    /// Video is playing
    Playing,
    /// Video is paused
    Paused,
    /// Error occurred
    Error,
}

impl VideoPlayerState {
    /// Check if video is currently playing
    pub fn is_playing(self) -> bool {
        self == Self::Playing
    }

    /// Check if video is paused
    pub fn is_paused(self) -> bool {
        self == Self::Paused
    }

    /// Check if video is loading (downloading or decoding)
    pub fn is_loading(self) -> bool {
        matches!(self, Self::Downloading | Self::Decoding)
    }

    /// Check if video is in error state
    pub fn is_error(self) -> bool {
        self == Self::Error
    }
}

/// Video player for managing video playback
///
/// Uses StreamingVideoDecoder for memory-efficient on-demand frame decoding.
/// Outputs YUV frames for GPU-accelerated rendering (~62% less memory than BGRA).
pub struct VideoPlayer {
    /// Current state
    state: VideoPlayerState,
    /// Streaming video decoder (decodes frames on-demand)
    decoder: Option<StreamingVideoDecoder>,
    /// Playback start time
    playback_start: Option<Instant>,
    /// Paused position
    paused_at: Option<Duration>,
    /// Error message if any
    error: Option<String>,
    /// Current frame YUV data for rendering
    current_frame: Option<YuvFrameData>,
    /// Current frame timestamp
    current_timestamp: Duration,
    /// Stored audio data for replay
    audio: Option<Arc<VideoAudio>>,
    /// Whether audio needs to be started on next play
    needs_audio_start: bool,
    /// Sender to notify when playback completes naturally
    completion_tx: Option<oneshot::Sender<()>>,
}

impl Default for VideoPlayer {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoPlayer {
    /// Create a new video player
    pub fn new() -> Self {
        Self {
            state: VideoPlayerState::Idle,
            decoder: None,
            playback_start: None,
            paused_at: None,
            error: None,
            current_frame: None,
            current_timestamp: Duration::ZERO,
            audio: None,
            needs_audio_start: false,
            completion_tx: None,
        }
    }

    /// Subscribe to playback completion.
    /// Returns a receiver that will be notified when playback completes naturally.
    /// Only one subscriber is supported at a time (calling again replaces previous).
    pub fn on_complete(&mut self) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.completion_tx = Some(tx);
        rx
    }

    /// Get current state
    pub fn state(&self) -> VideoPlayerState {
        self.state
    }

    /// Set state to downloading
    pub fn set_downloading(&mut self) {
        self.state = VideoPlayerState::Downloading;
        self.error = None;
    }

    /// Set state to decoding
    pub fn set_decoding(&mut self) {
        self.state = VideoPlayerState::Decoding;
    }

    /// Load video with streaming decoder (memory-efficient)
    pub fn load(&mut self, mut decoder: StreamingVideoDecoder) {
        log::info!(
            "VideoPlayer::load - frames: {}, duration: {:?}",
            decoder.frame_count(),
            decoder.duration()
        );
        // Seek to first frame to have something to display
        decoder.seek_to_frame(0);
        self.decoder = Some(decoder);
        self.state = VideoPlayerState::Paused;
        self.paused_at = Some(Duration::ZERO);
        let frame_updated = self.update_current_frame();
        log::info!(
            "VideoPlayer::load - frame_updated: {}, current_frame.is_some: {}",
            frame_updated,
            self.current_frame.is_some()
        );
    }

    /// Set error state
    pub fn set_error(&mut self, error: String) {
        self.state = VideoPlayerState::Error;
        self.error = Some(error);
    }

    /// Start or resume playback
    /// Returns true if audio needs to be started
    pub fn play(&mut self) -> bool {
        if self.decoder.is_some() {
            let offset = self.paused_at.unwrap_or(Duration::ZERO);
            self.playback_start = Some(Instant::now() - offset);
            self.paused_at = None;
            self.state = VideoPlayerState::Playing;

            // Check if we need to start audio (replay from beginning)
            if self.needs_audio_start {
                self.needs_audio_start = false;
                return self.audio.is_some();
            }
        }
        false
    }

    /// Store audio data for replay
    pub fn set_audio(&mut self, audio: VideoAudio) {
        self.audio = Some(Arc::new(audio));
        self.needs_audio_start = true; // Need to start audio when play() is called
    }

    /// Get stored audio for playback
    pub fn get_audio(&self) -> Option<&VideoAudio> {
        self.audio.as_ref().map(|a| a.as_ref())
    }

    /// Pause playback
    pub fn pause(&mut self) {
        if self.state == VideoPlayerState::Playing {
            self.paused_at = Some(self.current_time());
            self.playback_start = None;
            self.state = VideoPlayerState::Paused;
        }
    }

    /// Stop playback and reset
    pub fn stop(&mut self) {
        self.playback_start = None;
        self.paused_at = Some(Duration::ZERO);
        self.state = VideoPlayerState::Paused;
        if let Some(decoder) = &mut self.decoder {
            decoder.reset();
        }
        self.update_current_frame();
        // Mark that audio needs to be restarted on next play
        self.needs_audio_start = true;
        // Drop the completion sender to signal cancellation to the update task
        self.completion_tx = None;
    }

    /// Get current playback time
    pub fn current_time(&self) -> Duration {
        if let Some(start) = self.playback_start {
            start.elapsed()
        } else {
            self.paused_at.unwrap_or(Duration::ZERO)
        }
    }

    /// Update the current frame based on playback time
    /// Returns true if frame changed
    pub fn update(&mut self) -> bool {
        if self.state != VideoPlayerState::Playing {
            return false;
        }

        if self.decoder.is_none() {
            return false;
        }

        // Get current time before mutable borrow
        let current_time = self.current_time();

        // Check if video ended
        let duration = self.decoder.as_ref().map(|d| d.duration());
        if let Some(dur) = duration
            && current_time >= dur
        {
            self.stop();
            // Notify completion (video ended naturally)
            if let Some(tx) = self.completion_tx.take() {
                let _ = tx.send(());
            }
            return true;
        }

        // Seek to current time and update frame
        if let Some(decoder) = &mut self.decoder {
            decoder.seek(current_time);
        }
        self.update_current_frame()
    }

    /// Update the current frame from decoder
    fn update_current_frame(&mut self) -> bool {
        if let Some(decoder) = &self.decoder
            && let Some(frame) = decoder.current_frame()
        {
            let changed = self.current_timestamp != frame.timestamp;
            if changed {
                log::debug!(
                    "VideoPlayer: frame {} -> {}, YUV sizes: Y={} U={} V={}",
                    self.current_timestamp.as_millis(),
                    frame.timestamp.as_millis(),
                    frame.yuv_data.y_plane.len(),
                    frame.yuv_data.u_plane.len(),
                    frame
                        .yuv_data
                        .v_plane
                        .as_ref()
                        .map(|v| v.len())
                        .unwrap_or(0)
                );
            }
            // Clone the YuvFrameData - uses Arc internally, cheap
            self.current_frame = Some(frame.yuv_data.clone());
            self.current_timestamp = frame.timestamp;
            return changed;
        }
        false
    }

    /// Get current frame for rendering (YUV format for GPU conversion)
    pub fn current_frame(&self) -> Option<&YuvFrameData> {
        self.current_frame.as_ref()
    }
}
