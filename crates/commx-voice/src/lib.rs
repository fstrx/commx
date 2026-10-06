//! commx voice engine, shared by the TUI and the Android app: Opus (hard
//! CBR), resampling, jitter buffering, mixing, and live audio via cpal
//! (CoreAudio, WASAPI, ALSA/PulseAudio, AAudio on Android).

pub mod codec;
pub mod dsp;
mod engine;

pub use engine::{list_devices, DeviceChoice, VoiceEngine};
