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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::codec::{Decoder, Encoder};
use crate::dsp::{mix, JitterBuffer, Resampler, Slot};

struct Sender {
    jitter: JitterBuffer,
    decoder: Decoder,
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
            .filter_map(|s| match s.jitter.pop() {
                Slot::Silence => None,
                Slot::Frame(f) => Some(s.decoder.decode(Some(&f))),
                Slot::Lost => Some(s.decoder.decode(None)),
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
}

impl VoiceEngine {
    /// Open the default microphone and speakers. Encoded frames go to `mic`.
    pub fn start(mic: mpsc::UnboundedSender<Vec<u8>>, muted: bool) -> Result<Self> {
        let host = cpal::default_host();
        let input = host.default_input_device().ok_or_else(|| anyhow!("no microphone found"))?;
        let output = host.default_output_device().ok_or_else(|| anyhow!("no speakers found"))?;
        let in_cfg = input.default_input_config().context("microphone config")?;
        let out_cfg = output.default_output_config().context("speaker config")?;

        let muted = Arc::new(AtomicBool::new(muted));
        let playback = Arc::new(Mutex::new(Playback {
            senders: HashMap::new(),
            ring: VecDeque::new(),
            resampler: Resampler::new(SAMPLE_RATE, out_cfg.sample_rate()),
        }));

        let input_stream = build_input(&input, in_cfg.config(), in_cfg.sample_format(), mic, muted.clone())?;
        let output_stream = build_output(&output, out_cfg.config(), out_cfg.sample_format(), playback.clone())?;
        input_stream.play().context("start microphone (check OS microphone permission for your terminal)")?;
        output_stream.play().context("start speakers")?;
        Ok(Self { _input: input_stream, _output: output_stream, playback, muted })
    }

    pub fn push(&self, from: &str, seq: u64, opus: Vec<u8>) {
        let mut pb = lock(&self.playback);
        if !pb.senders.contains_key(from) {
            let Ok(decoder) = Decoder::new() else { return };
            pb.senders.insert(from.to_string(), Sender { jitter: JitterBuffer::default(), decoder });
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
) -> Result<Stream> {
    let mut cap = Capture {
        channels: cfg.channels.max(1) as usize,
        resampler: Resampler::new(cfg.sample_rate, SAMPLE_RATE),
        pending: Vec::new(),
        mono: Vec::new(),
        encoder: Encoder::new()?,
        mic,
        muted,
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
