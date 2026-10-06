//! Live audio for calls: microphone → Opus → daemon, daemon → jitter buffer →
//! Opus → mixer → speakers.
//!
//! Both directions are clocked by the sound card, not timers: the capture
//! callback emits a frame per 20 ms of microphone input (muted or not, so the
//! stream is constant-rate), and the playback callback decodes exactly as many
//! frames as the speakers consume.

use anyhow::{anyhow, Context, Result};
use commx_core::voice::{FRAME_SAMPLES, SAMPLE_RATE};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, Stream, StreamConfig};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::codec::{Decoder, Encoder};
use crate::dsp::{mix, JitterBuffer, Resampler, Slot};

struct Sender {
    jitter: JitterBuffer,
    decoder: Decoder,
    /// Last time this sender's decoded audio was above the speech threshold.
    last_loud: Option<Instant>,
}

/// RMS above this (≈ -34 dBFS) counts as talking. Computed locally from the
/// decoded audio, so the indicator costs nothing on the wire and leaks nothing.
const SPEAKING_RMS: f32 = 0.02;
const SPEAKING_HOLD: Duration = Duration::from_millis(300);

fn rms(pcm: &[i16]) -> f32 {
    let sum: f64 = pcm.iter().map(|s| (*s as f64 / 32768.0).powi(2)).sum();
    (sum / pcm.len().max(1) as f64).sqrt() as f32
}

/// Which devices to open; `None` means the system default.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct DeviceChoice {
    pub mic: Option<String>,
    pub speaker: Option<String>,
}

fn device_name(d: &cpal::Device) -> String {
    d.description().map(|x| x.name().to_string()).unwrap_or_else(|_| "?".into())
}

/// (microphones, speakers), names as the OS reports them.
pub fn list_devices() -> (Vec<String>, Vec<String>) {
    let host = cpal::default_host();
    let ins = host.input_devices().map(|d| d.map(|x| device_name(&x)).collect()).unwrap_or_default();
    let outs = host.output_devices().map(|d| d.map(|x| device_name(&x)).collect()).unwrap_or_default();
    (ins, outs)
}

fn pick(
    mut devices: impl Iterator<Item = cpal::Device>,
    want: &Option<String>,
    default: Option<cpal::Device>,
) -> Option<cpal::Device> {
    match want {
        Some(name) => devices.find(|d| device_name(d) == *name),
        None => default,
    }
}

struct Playback {
    senders: HashMap<String, Sender>,
    /// Mono samples at the device rate, ready for the speakers.
    ring: VecDeque<f32>,
    resampler: Resampler,
}

impl Playback {
    /// Mix one 20 ms slot from everyone and queue it for output.
    fn produce(&mut self) {
        let frames: Vec<[i16; FRAME_SAMPLES]> = self
            .senders
            .values_mut()
            .filter_map(|s| {
                let pcm = match s.jitter.pop() {
                    Slot::Silence => return None,
                    Slot::Frame(f) => s.decoder.decode(Some(&f)),
                    Slot::Lost => s.decoder.decode(None),
                };
                if rms(&pcm) > SPEAKING_RMS {
                    s.last_loud = Some(Instant::now());
                }
                Some(pcm)
            })
            .collect();
        let mixed = mix(&frames);
        let mut out = Vec::with_capacity(FRAME_SAMPLES * 2);
        self.resampler.process(&mixed, &mut out);
        self.ring.extend(out);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct VoiceEngine {
    _input: Stream,
    _output: Stream,
    playback: Arc<Mutex<Playback>>,
    muted: Arc<AtomicBool>,
    /// RMS of the latest microphone frame (f32 bits), before muting.
    level: Arc<AtomicU32>,
    pub devices: DeviceChoice,
}

impl VoiceEngine {
    /// Open the default microphone and speakers. Encoded frames go to `mic`.
    pub fn start(mic: mpsc::UnboundedSender<Vec<u8>>, muted: bool, devices: DeviceChoice) -> Result<Self> {
        let host = cpal::default_host();
        let input = pick(host.input_devices()?, &devices.mic, host.default_input_device())
            .ok_or_else(|| anyhow!("microphone not found: {}", devices.mic.as_deref().unwrap_or("default")))?;
        let output = pick(host.output_devices()?, &devices.speaker, host.default_output_device())
            .ok_or_else(|| anyhow!("speakers not found: {}", devices.speaker.as_deref().unwrap_or("default")))?;
        let in_cfg = input.default_input_config().context("microphone config")?;
        let out_cfg = output.default_output_config().context("speaker config")?;

        let muted = Arc::new(AtomicBool::new(muted));
        let playback = Arc::new(Mutex::new(Playback {
            senders: HashMap::new(),
            ring: VecDeque::new(),
            resampler: Resampler::new(SAMPLE_RATE, out_cfg.sample_rate()),
        }));

        let level = Arc::new(AtomicU32::new(0));
        let input_stream =
            build_input(&input, in_cfg.config(), in_cfg.sample_format(), mic, muted.clone(), level.clone())?;
        let output_stream = build_output(&output, out_cfg.config(), out_cfg.sample_format(), playback.clone())?;
        input_stream.play().context("start microphone (check OS microphone permission for your terminal)")?;
        output_stream.play().context("start speakers")?;
        Ok(Self { _input: input_stream, _output: output_stream, playback, muted, level, devices })
    }

    /// Microphone level 0..1 (for the meter), measured before muting.
    pub fn mic_level(&self) -> f32 {
        f32::from_bits(self.level.load(Ordering::Relaxed))
    }

    /// Who's audibly talking right now, by sender name.
    pub fn speaking(&self) -> Vec<String> {
        let pb = lock(&self.playback);
        let mut v: Vec<String> = pb
            .senders
            .iter()
            .filter(|(_, s)| s.last_loud.is_some_and(|t| t.elapsed() < SPEAKING_HOLD))
            .map(|(n, _)| n.clone())
            .collect();
        v.sort();
        v
    }

    pub fn push(&self, from: &str, seq: u64, opus: Vec<u8>) {
        let mut pb = lock(&self.playback);
        if !pb.senders.contains_key(from) {
            let Ok(decoder) = Decoder::new() else { return };
            pb.senders.insert(from.to_string(), Sender { jitter: JitterBuffer::default(), decoder, last_loud: None });
        }
        if let Some(s) = pb.senders.get_mut(from) {
            s.jitter.push(seq, opus);
        }
    }

    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }
}

/// Capture: downmix → resample to 48 kHz → 20 ms frames → Opus.
struct Capture {
    channels: usize,
    resampler: Resampler,
    pending: Vec<f32>,
    mono: Vec<f32>,
    encoder: Encoder,
    mic: mpsc::UnboundedSender<Vec<u8>>,
    muted: Arc<AtomicBool>,
    level: Arc<AtomicU32>,
}

impl Capture {
    fn feed(&mut self, samples: impl Iterator<Item = f32>) {
        self.mono.clear();
        let mut acc = 0f32;
        for (i, s) in samples.enumerate() {
            acc += s;
            if (i + 1) % self.channels == 0 {
                self.mono.push(acc / self.channels as f32);
                acc = 0.0;
            }
        }
        let mono = std::mem::take(&mut self.mono);
        self.resampler.process(&mono, &mut self.pending);
        self.mono = mono;
        while self.pending.len() >= FRAME_SAMPLES {
            let sum: f32 = self.pending[..FRAME_SAMPLES].iter().map(|s| s * s).sum();
            self.level.store((sum / FRAME_SAMPLES as f32).sqrt().to_bits(), Ordering::Relaxed);
            let muted = self.muted.load(Ordering::Relaxed);
            let pcm: [i16; FRAME_SAMPLES] = std::array::from_fn(|i| {
                if muted {
                    0
                } else {
                    (self.pending[i].clamp(-1.0, 1.0) * 32767.0) as i16
                }
            });
            self.pending.drain(..FRAME_SAMPLES);
            if let Ok(pkt) = self.encoder.encode(&pcm) {
                let _ = self.mic.send(pkt);
            }
        }
    }
}

fn build_input(
    dev: &cpal::Device,
    cfg: StreamConfig,
    fmt: SampleFormat,
    mic: mpsc::UnboundedSender<Vec<u8>>,
    muted: Arc<AtomicBool>,
    level: Arc<AtomicU32>,
) -> Result<Stream> {
    let mut cap = Capture {
        channels: cfg.channels.max(1) as usize,
        resampler: Resampler::new(cfg.sample_rate, SAMPLE_RATE),
        pending: Vec::new(),
        mono: Vec::new(),
        encoder: Encoder::new()?,
        mic,
        muted,
        level,
    };
    let err = |_| {};
    let stream = match fmt {
        SampleFormat::F32 => dev.build_input_stream::<f32, _, _>(cfg, move |d, _| cap.feed(d.iter().copied()), err, None),
        SampleFormat::I16 => dev.build_input_stream::<i16, _, _>(
            cfg,
            move |d, _| cap.feed(d.iter().map(|s| *s as f32 / 32768.0)),
            err,
            None,
        ),
        other => return Err(anyhow!("unsupported microphone sample format {other:?}")),
    };
    stream.context("open microphone")
}

fn build_output(dev: &cpal::Device, cfg: StreamConfig, fmt: SampleFormat, pb: Arc<Mutex<Playback>>) -> Result<Stream> {
    let channels = cfg.channels.max(1) as usize;
    // Pull exactly what the speakers need, decoding more 20 ms slots on demand.
    let fill = move |frames: usize| -> Vec<f32> {
        let mut p = lock(&pb);
        while p.ring.len() < frames {
            p.produce();
        }
        p.ring.drain(..frames).collect()
    };
    let err = |_| {};
    let stream = match fmt {
        SampleFormat::F32 => dev.build_output_stream::<f32, _, _>(
            cfg,
            move |d: &mut [f32], _| {
                let mono = fill(d.len() / channels);
                for (frame, s) in d.chunks_mut(channels).zip(mono) {
                    frame.fill(s);
                }
            },
            err,
            None,
        ),
        SampleFormat::I16 => dev.build_output_stream::<i16, _, _>(
            cfg,
            move |d: &mut [i16], _| {
                let mono = fill(d.len() / channels);
                for (frame, s) in d.chunks_mut(channels).zip(mono) {
                    frame.fill((s * 32767.0) as i16);
                }
            },
            err,
            None,
        ),
        other => return Err(anyhow!("unsupported speaker sample format {other:?}")),
    };
    stream.context("open speakers")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything after the network and before the sound card: encoded frames
    /// → jitter buffer → decode → speaking detection → mix → resample.
    #[test]
    fn playback_pipeline_mixes_and_detects_speech() {
        let mut pb = Playback { senders: HashMap::new(), ring: VecDeque::new(), resampler: Resampler::new(SAMPLE_RATE, 44_100) };
        let mut enc = Encoder::new().unwrap();
        for name in ["talker", "quiet"] {
            pb.senders.insert(name.into(), Sender { jitter: JitterBuffer::default(), decoder: Decoder::new().unwrap(), last_loud: None });
        }
        for seq in 0..25u64 {
            let tone: [i16; FRAME_SAMPLES] = std::array::from_fn(|n| {
                let t = (seq as usize * FRAME_SAMPLES + n) as f32 / SAMPLE_RATE as f32;
                ((t * 300.0 * std::f32::consts::TAU).sin() * 9000.0) as i16
            });
            let loud = enc.encode(&tone).unwrap();
            pb.senders.get_mut("talker").unwrap().jitter.push(seq, loud);
        }
        let mut enc2 = Encoder::new().unwrap();
        for seq in 0..25u64 {
            let silent = enc2.encode(&[0; FRAME_SAMPLES]).unwrap();
            pb.senders.get_mut("quiet").unwrap().jitter.push(seq, silent);
        }
        for _ in 0..20 {
            pb.produce();
        }
        // 20 frames of 20 ms at 44.1 kHz
        assert!((pb.ring.len() as i64 - 17_640).abs() < 10, "{}", pb.ring.len());
        assert!(pb.ring.iter().map(|s| s.abs()).fold(0.0, f32::max) > 0.1, "audio reached the output ring");
        assert!(pb.senders["talker"].last_loud.is_some(), "talker detected");
        assert!(pb.senders["quiet"].last_loud.is_none(), "silence not flagged as speech");
    }
}
