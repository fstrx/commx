//! Small audio helpers: resampling, jitter buffering, mixing.

use std::collections::BTreeMap;

/// Streaming linear-interpolation resampler. Plenty for speech.
pub struct Resampler {
    /// Input samples consumed per output sample.
    step: f64,
    /// Read position into `[prev] ++ input`.
    t: f64,
    prev: f32,
}

impl Resampler {
    pub fn new(from_hz: u32, to_hz: u32) -> Self {
        Self { step: from_hz as f64 / to_hz as f64, t: 0.0, prev: 0.0 }
    }

    pub fn process(&mut self, input: &[f32], out: &mut Vec<f32>) {
        if input.is_empty() {
            return;
        }
        if self.step == 1.0 {
            out.extend_from_slice(input);
            return;
        }
        let n = input.len() as f64;
        let at = |i: usize| if i == 0 { self.prev } else { input[i - 1] };
        while self.t < n {
            let i = self.t as usize;
            let f = (self.t - i as f64) as f32;
            out.push(at(i) * (1.0 - f) + at(i + 1) * f);
            self.t += self.step;
        }
        self.t -= n;
        self.prev = *input.last().unwrap();
    }
}

/// What the playout clock should do for one 20 ms slot.
#[derive(Debug, PartialEq)]
pub enum Slot {
    /// Not playing (buffering or idle): output silence.
    Silence,
    Frame(Vec<u8>),
    /// Expected frame missing: let the decoder conceal it.
    Lost,
}

/// Per-sender reorder/jitter buffer. Starts playout once `target` frames are
/// queued, grows `target` after underruns (Tor jitter), and skips ahead if it
/// falls too far behind.
pub struct JitterBuffer {
    frames: BTreeMap<u64, Vec<u8>>,
    next: u64,
    playing: bool,
    pub target: usize,
    misses: usize,
}

const MIN_TARGET: usize = 3; // 60 ms
const MAX_TARGET: usize = 25; // 500 ms
const MAX_DEPTH: usize = 50; // 1 s

impl Default for JitterBuffer {
    fn default() -> Self {
        Self { frames: BTreeMap::new(), next: 0, playing: false, target: MIN_TARGET, misses: 0 }
    }
}

impl JitterBuffer {
    pub fn push(&mut self, seq: u64, frame: Vec<u8>) {
        if self.playing && seq < self.next {
            return; // too late
        }
        self.frames.insert(seq, frame);
        if self.frames.len() > MAX_DEPTH {
            // Fell behind (e.g. after a stall): jump to near-live.
            let keep_from = *self.frames.keys().rev().nth(self.target).unwrap();
            self.frames = self.frames.split_off(&keep_from);
            self.next = keep_from;
        }
    }

    pub fn pop(&mut self) -> Slot {
        if !self.playing {
            if self.frames.len() < self.target {
                return Slot::Silence;
            }
            self.playing = true;
            self.next = *self.frames.keys().next().unwrap();
        }
        if let Some(f) = self.frames.remove(&self.next) {
            self.next += 1;
            self.misses = 0;
            return Slot::Frame(f);
        }
        self.next += 1;
        self.misses += 1;
        if self.frames.is_empty() && self.misses > 5 {
            // Sender stopped or link stalled: rebuffer a bit deeper.
            self.playing = false;
            self.target = (self.target + 2).min(MAX_TARGET);
            return Slot::Silence;
        }
        Slot::Lost
    }
}

/// Mix 16-bit frames into f32 [-1, 1] with a soft limit.
pub fn mix(frames: &[[i16; commx_core::voice::FRAME_SAMPLES]]) -> Vec<f32> {
    let mut out = vec![0f32; commx_core::voice::FRAME_SAMPLES];
    for f in frames {
        for (o, s) in out.iter_mut().zip(f.iter()) {
            *o += *s as f32 / 32768.0;
        }
    }
    for o in &mut out {
        *o = o.tanh();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resampler_ratio() {
        let mut r = Resampler::new(44_100, 48_000);
        let mut out = Vec::new();
        for _ in 0..100 {
            r.process(&[0.5; 441], &mut out);
        }
        assert!((out.len() as i64 - 48_000).abs() <= 2, "{}", out.len());
        assert!(out[100..].iter().all(|s| (s - 0.5).abs() < 1e-6));
    }

    #[test]
    fn jitter_buffer_reorders_conceals_and_rebuffers() {
        let mut jb = JitterBuffer::default();
        jb.push(11, vec![11]);
        assert_eq!(jb.pop(), Slot::Silence, "buffering");
        jb.push(10, vec![10]);
        jb.push(13, vec![13]);
        assert_eq!(jb.pop(), Slot::Frame(vec![10]));
        assert_eq!(jb.pop(), Slot::Frame(vec![11]));
        assert_eq!(jb.pop(), Slot::Lost, "12 missing → conceal");
        jb.push(12, vec![12]);
        assert_eq!(jb.pop(), Slot::Frame(vec![13]), "12 arrived too late, dropped");
        for _ in 0..6 {
            jb.pop();
        }
        assert_eq!(jb.pop(), Slot::Silence, "underrun → rebuffer");
        assert!(jb.target > MIN_TARGET);
    }

    #[test]
    fn jitter_buffer_skips_ahead_when_flooded() {
        let mut jb = JitterBuffer::default();
        for s in 0..200 {
            jb.push(s, vec![]);
        }
        assert!(jb.frames.len() <= MAX_DEPTH);
        assert!(matches!(jb.pop(), Slot::Frame(_)));
        assert!(jb.next > 150);
    }
}
