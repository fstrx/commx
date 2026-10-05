//! Minimal safe wrapper over libopus (vendored, statically linked).

use anyhow::{bail, Result};
use commx_core::voice::{BITRATE, FRAME_SAMPLES, SAMPLE_RATE};
use opus_head_sys as ffi;
use std::os::raw::c_int;

pub struct Encoder(*mut ffi::OpusEncoder);
pub struct Decoder(*mut ffi::OpusDecoder);

// libopus state has no thread affinity; we only ever use it from one thread at a time.
unsafe impl Send for Encoder {}
unsafe impl Send for Decoder {}

impl Encoder {
    /// Mono VoIP encoder in *hard* CBR with DTX off: every 20 ms packet has the
    /// same size and silence is still sent, so packet sizes and timing leak
    /// nothing about speech. In-band FEC softens packet loss.
    pub fn new() -> Result<Self> {
        let mut err: c_int = 0;
        let st = unsafe {
            ffi::opus_encoder_create(SAMPLE_RATE as i32, 1, ffi::OPUS_APPLICATION_VOIP as c_int, &mut err)
        };
        if st.is_null() || err != 0 {
            bail!("opus encoder init failed ({err})");
        }
        let enc = Self(st);
        for (req, val) in [
            (ffi::OPUS_SET_BITRATE_REQUEST, BITRATE),
            (ffi::OPUS_SET_VBR_REQUEST, 0),
            (ffi::OPUS_SET_DTX_REQUEST, 0),
            (ffi::OPUS_SET_INBAND_FEC_REQUEST, 1),
            (ffi::OPUS_SET_PACKET_LOSS_PERC_REQUEST, 10),
        ] {
            let r = unsafe { ffi::opus_encoder_ctl(enc.0, req as c_int, val as c_int) };
            if r != 0 {
                bail!("opus ctl {req} failed ({r})");
            }
        }
        Ok(enc)
    }

    pub fn encode(&mut self, pcm: &[i16; FRAME_SAMPLES]) -> Result<Vec<u8>> {
        let mut out = [0u8; 256];
        let n = unsafe {
            ffi::opus_encode(self.0, pcm.as_ptr(), FRAME_SAMPLES as c_int, out.as_mut_ptr(), out.len() as i32)
        };
        if n < 0 {
            bail!("opus encode failed ({n})");
        }
        Ok(out[..n as usize].to_vec())
    }
}

impl Decoder {
    pub fn new() -> Result<Self> {
        let mut err: c_int = 0;
        let st = unsafe { ffi::opus_decoder_create(SAMPLE_RATE as i32, 1, &mut err) };
        if st.is_null() || err != 0 {
            bail!("opus decoder init failed ({err})");
        }
        Ok(Self(st))
    }

    /// Decode one frame; `None` runs packet-loss concealment.
    pub fn decode(&mut self, packet: Option<&[u8]>) -> [i16; FRAME_SAMPLES] {
        let mut pcm = [0i16; FRAME_SAMPLES];
        let (ptr, len) = match packet {
            Some(p) => (p.as_ptr(), p.len() as i32),
            None => (std::ptr::null(), 0),
        };
        let n = unsafe { ffi::opus_decode(self.0, ptr, len, pcm.as_mut_ptr(), FRAME_SAMPLES as c_int, 0) };
        if n < 0 {
            pcm = [0; FRAME_SAMPLES];
        }
        pcm
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        unsafe { ffi::opus_encoder_destroy(self.0) }
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe { ffi::opus_decoder_destroy(self.0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(i: usize, hz: f32) -> [i16; FRAME_SAMPLES] {
        std::array::from_fn(|n| {
            let t = (i * FRAME_SAMPLES + n) as f32 / SAMPLE_RATE as f32;
            ((t * hz * std::f32::consts::TAU).sin() * 8000.0) as i16
        })
    }

    #[test]
    fn hard_cbr_packets_are_constant_size() {
        let mut enc = Encoder::new().unwrap();
        let mut sizes = std::collections::BTreeSet::new();
        for i in 0..50 {
            let pcm = if i % 10 < 5 { tone(i, 440.0) } else { [0; FRAME_SAMPLES] };
            sizes.insert(enc.encode(&pcm).unwrap().len());
        }
        assert_eq!(sizes.len(), 1, "sizes vary: {sizes:?}");
        assert_eq!(*sizes.first().unwrap(), (BITRATE as usize / 8) * 20 / 1000);
    }

    #[test]
    fn roundtrip_preserves_signal() {
        let (mut enc, mut dec) = (Encoder::new().unwrap(), Decoder::new().unwrap());
        let mut energy = 0f64;
        for i in 0..30 {
            let out = dec.decode(Some(&enc.encode(&tone(i, 440.0)).unwrap()));
            if i > 5 {
                energy += out.iter().map(|s| (*s as f64).powi(2)).sum::<f64>();
            }
        }
        let rms = (energy / (24.0 * FRAME_SAMPLES as f64)).sqrt();
        assert!(rms > 2000.0, "decoded signal too weak: rms {rms}");
        // Concealment produces a frame instead of failing.
        assert_eq!(dec.decode(None).len(), FRAME_SAMPLES);
    }
}
