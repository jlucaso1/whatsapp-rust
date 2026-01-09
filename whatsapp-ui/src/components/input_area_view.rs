//! Isolated input area component with its own Entity and render cycle.
//!
//! This component is designed for performance: when the user types,
//! only this component re-renders, NOT the parent app.

use std::time::{Duration, Instant};

use gpui::{Entity, EventEmitter, Task, WeakEntity, Window, div, prelude::*, px, rgb};
use gpui_component::{
    ActiveTheme, Icon, IconName,
    button::{Button, ButtonVariants},
    input::{Input, InputEvent, InputState},
};

use crate::theme::{colors, layout};

/// Events emitted by the input area to communicate with the parent app.
#[derive(Clone, Debug)]
pub enum InputAreaEvent {
    /// User wants to send the current message
    SendMessage(String),
    /// User started PTT recording
    StartRecording,
    /// User stopped PTT recording (send the audio)
    StopRecording,
    /// Typing indicator: user started typing
    StartedTyping,
    /// Typing indicator: user stopped typing (timeout)
    StoppedTyping,
}

/// Typing indicator state with debouncing.
#[derive(Default)]
enum TypingState {
    #[default]
    Idle,
    /// Currently typing - stores the instant of the last keystroke
    Composing(Instant),
}

/// Timeout before sending "paused" after typing stops (matches WhatsApp Web)
const TYPING_PAUSED_TIMEOUT: Duration = Duration::from_millis(2500);
/// How often the typing monitor checks for timeout
const TYPING_MONITOR_INTERVAL: Duration = Duration::from_millis(500);

/// Isolated input area view with its own render cycle.
/// When the user types, only this component re-renders.
pub struct InputAreaView {
    /// The input state entity
    input: Entity<InputState>,
    /// Whether PTT recording is active
    is_recording: bool,
    /// Typing indicator state
    typing_state: TypingState,
    /// Task that monitors typing state
    #[allow(dead_code)]
    typing_monitor_task: Option<Task<()>>,
}

impl EventEmitter<InputAreaEvent> for InputAreaView {}

impl InputAreaView {
    /// Create a new input area view
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("Type a message"));

        // Subscribe to input events (for Enter key to send, etc.)
        cx.subscribe_in(&input, window, Self::handle_input_event)
            .detach();

        Self {
            input,
            is_recording: false,
            typing_state: TypingState::default(),
            typing_monitor_task: None,
        }
    }

    /// Handle input events (Enter, Change, etc.)
    fn handle_input_event(
        &mut self,
        input: &Entity<InputState>,
        event: &InputEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            InputEvent::PressEnter { .. } => {
                // Get the text and send if not empty
                let text = input.read(cx).text().to_string();
                if !text.trim().is_empty() {
                    // Clear the input
                    input.update(cx, |state, cx| {
                        state.set_value("", window, cx);
                    });
                    // Stop typing indicator
                    self.stop_typing_internal(cx);
                    // Emit event to parent
                    cx.emit(InputAreaEvent::SendMessage(text));
                }
            }
            InputEvent::Change => {
                // Handle typing indicator - minimal work, no notify
                self.on_keystroke(cx);
            }
            _ => {}
        }
    }

    /// Handle a keystroke - updates typing state
    /// Does NOT call cx.notify() to avoid triggering parent re-renders
    fn on_keystroke(&mut self, cx: &mut Context<Self>) {
        let now = Instant::now();

        match self.typing_state {
            TypingState::Idle => {
                // First keystroke - start typing
                self.typing_state = TypingState::Composing(now);
                // Emit event to parent (they handle their own notification)
                cx.emit(InputAreaEvent::StartedTyping);
                self.start_typing_monitor(cx);
            }
            TypingState::Composing(_) => {
                // Already typing - just update the timestamp (O(1), no allocations)
                // NO notification needed - just internal state update
                self.typing_state = TypingState::Composing(now);
            }
        }
    }

    /// Start the typing monitor task
    fn start_typing_monitor(&mut self, cx: &mut Context<Self>) {
        self.typing_monitor_task = None;

        self.typing_monitor_task = Some(cx.spawn(async move |entity: WeakEntity<Self>, cx| {
            loop {
                smol::Timer::after(TYPING_MONITOR_INTERVAL).await;

                let should_stop = entity
                    .update(cx, |view, cx| {
                        let TypingState::Composing(last_keystroke) = view.typing_state else {
                            return true;
                        };
                        if last_keystroke.elapsed() >= TYPING_PAUSED_TIMEOUT {
                            view.stop_typing_internal(cx);
                            return true;
                        }
                        false
                    })
                    .unwrap_or(true);

                if should_stop {
                    break;
                }
            }
        }));
    }

    fn stop_typing_internal(&mut self, cx: &mut Context<Self>) {
        if matches!(self.typing_state, TypingState::Composing(_)) {
            cx.emit(InputAreaEvent::StoppedTyping);
        }
        self.typing_state = TypingState::Idle;
        self.typing_monitor_task = None;
    }

    /// Set recording state (called by parent)
    pub fn set_recording(&mut self, is_recording: bool) {
        self.is_recording = is_recording;
    }

    /// Toggle PTT recording
    fn toggle_recording(&mut self, cx: &mut Context<Self>) {
        if self.is_recording {
            cx.emit(InputAreaEvent::StopRecording);
        } else {
            cx.emit(InputAreaEvent::StartRecording);
        }
    }
}

impl Render for InputAreaView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let is_recording = self.is_recording;
        let entity = cx.entity().clone();

        let muted_fg = cx.theme().muted_foreground;

        div()
            .h(px(layout::INPUT_AREA_HEIGHT))
            .flex()
            .items_center()
            .px_4()
            .gap_3()
            .bg(cx.theme().background)
            .border_t_1()
            .border_color(cx.theme().border)
            .child(div().flex_1().child(Input::new(&self.input).w_full()))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("ptt")
                            .icon(if is_recording {
                                Icon::default()
                                    .path("icons/stop.svg")
                                    .text_color(rgb(colors::WHITE))
                            } else {
                                Icon::default().path("icons/mic.svg").text_color(muted_fg)
                            })
                            .when(is_recording, |btn| btn.danger())
                            .when(!is_recording, |btn| btn.ghost())
                            .on_click({
                                let entity = entity.clone();
                                move |_, _window, cx| {
                                    entity.update(cx, |view, cx| {
                                        view.toggle_recording(cx);
                                    });
                                }
                            }),
                    )
                    .child(
                        Button::new("send")
                            .icon(IconName::ArrowRight)
                            .primary()
                            .on_click({
                                move |_, window, cx| {
                                    entity.update(cx, |view, cx| {
                                        let text = view.input.read(cx).text().to_string();
                                        if !text.trim().is_empty() {
                                            view.input.update(cx, |state, cx| {
                                                state.set_value("", window, cx);
                                            });
                                            view.stop_typing_internal(cx);
                                            cx.emit(InputAreaEvent::SendMessage(text));
                                        }
                                    });
                                }
                            }),
                    ),
            )
    }
}
