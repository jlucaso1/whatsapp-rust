//! Video player state management

use std::sync::Arc;
use std::time::{Duration, Instant};

use gpui::YuvFrameData;
use tokio::sync::oneshot;

use super::audio::VideoAudio;
use super::streaming::StreamingVideoDecoder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoPlayerState {
    Idle,
    Downloading,
    Decoding,
    Playing,
    Paused,
    Error,
}

impl VideoPlayerState {
    pub fn is_playing(self) -> bool {
        self == Self::Playing
    }

    pub fn is_paused(self) -> bool {
        self == Self::Paused
    }

    pub fn is_loading(self) -> bool {
        matches!(self, Self::Downloading | Self::Decoding)
    }

    pub fn is_error(self) -> bool {
        self == Self::Error
    }
}

/// Video player using StreamingVideoDecoder for memory-efficient on-demand frame decoding.
pub struct VideoPlayer {
    state: VideoPlayerState,
    decoder: Option<StreamingVideoDecoder>,
    playback_start: Option<Instant>,
    paused_at: Option<Duration>,
    error: Option<String>,
    current_frame: Option<YuvFrameData>,
    current_timestamp: Duration,
    audio: Option<Arc<VideoAudio>>,
    needs_audio_start: bool,
    completion_tx: Option<oneshot::Sender<()>>,
}

impl Default for VideoPlayer {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoPlayer {
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

    /// Subscribe to playback completion (only one subscriber supported at a time).
    pub fn on_complete(&mut self) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.completion_tx = Some(tx);
        rx
    }

    pub fn state(&self) -> VideoPlayerState {
        self.state
    }

    pub fn set_downloading(&mut self) {
        self.state = VideoPlayerState::Downloading;
        self.error = None;
    }

    pub fn set_decoding(&mut self) {
        self.state = VideoPlayerState::Decoding;
    }

    pub fn load(&mut self, mut decoder: StreamingVideoDecoder) {
        log::info!(
            "VideoPlayer::load - frames: {}, duration: {:?}",
            decoder.frame_count(),
            decoder.duration()
        );
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

    pub fn set_error(&mut self, error: String) {
        self.state = VideoPlayerState::Error;
        self.error = Some(error);
    }

    /// Start or resume playback. Returns true if audio needs to be started.
    pub fn play(&mut self) -> bool {
        let Some(_) = self.decoder.as_ref() else {
            return false;
        };

        let offset = self.paused_at.unwrap_or(Duration::ZERO);
        self.playback_start = Some(Instant::now() - offset);
        self.paused_at = None;
        self.state = VideoPlayerState::Playing;

        if self.needs_audio_start {
            self.needs_audio_start = false;
            return self.audio.is_some();
        }
        false
    }

    pub fn set_audio(&mut self, audio: VideoAudio) {
        self.audio = Some(Arc::new(audio));
        self.needs_audio_start = true;
    }

    pub fn get_audio(&self) -> Option<&VideoAudio> {
        self.audio.as_deref()
    }

    pub fn pause(&mut self) {
        if self.state == VideoPlayerState::Playing {
            self.paused_at = Some(self.current_time());
            self.playback_start = None;
            self.state = VideoPlayerState::Paused;
        }
    }

    pub fn stop(&mut self) {
        self.playback_start = None;
        self.paused_at = Some(Duration::ZERO);
        self.state = VideoPlayerState::Paused;
        if let Some(decoder) = &mut self.decoder {
            decoder.reset();
        }
        self.update_current_frame();
        self.needs_audio_start = true;
        self.completion_tx = None;
    }

    pub fn current_time(&self) -> Duration {
        self.playback_start
            .map(|start| start.elapsed())
            .or(self.paused_at)
            .unwrap_or(Duration::ZERO)
    }

    /// Update the current frame based on playback time. Returns true if frame changed.
    pub fn update(&mut self) -> bool {
        let Some(decoder) = &self.decoder else {
            return false;
        };
        if self.state != VideoPlayerState::Playing {
            return false;
        }

        let current_time = self.current_time();

        if current_time >= decoder.duration() {
            self.stop();
            if let Some(tx) = self.completion_tx.take() {
                let _ = tx.send(());
            }
            return true;
        }

        if let Some(decoder) = &mut self.decoder {
            decoder.seek(current_time);
        }
        self.update_current_frame()
    }

    fn update_current_frame(&mut self) -> bool {
        let Some(decoder) = &self.decoder else {
            return false;
        };
        let Some(frame) = decoder.current_frame() else {
            return false;
        };

        let changed = self.current_timestamp != frame.timestamp;
        if changed {
            log::debug!(
                "VideoPlayer: frame {} -> {}, YUV sizes: Y={} U={} V={}",
                self.current_timestamp.as_millis(),
                frame.timestamp.as_millis(),
                frame.yuv_data.y_plane.len(),
                frame.yuv_data.u_plane.len(),
                frame.yuv_data.v_plane.as_ref().map_or(0, |v| v.len())
            );
        }
        self.current_frame = Some(frame.yuv_data.clone());
        self.current_timestamp = frame.timestamp;
        changed
    }

    pub fn current_frame(&self) -> Option<&YuvFrameData> {
        self.current_frame.as_ref()
    }
}
