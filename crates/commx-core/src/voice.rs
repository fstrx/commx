//! Voice frames: Opus packets sealed under a per-call key.
//!
//! Every frame on the wire has the same size (Opus runs in hard CBR, and the
//! plaintext is padded to a fixed length), and clients send frames
//! continuously while in a call, silence included. A network observer, or the
//! relaying host, learns neither what was said (VBR packet sizes leak
//! phonemes) nor when anyone was talking.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{aead_decrypt, aead_encrypt};
use crate::RoomId;

pub const SAMPLE_RATE: u32 = 48_000;
/// 20 ms of mono audio at 48 kHz.
pub const FRAME_SAMPLES: usize = 960;
pub const FRAME_MS: u64 = 20;
/// Hard-CBR bitrate: 24 kb/s → exactly 60 bytes per 20 ms packet.
pub const BITRATE: i32 = 24_000;
/// Fixed plaintext size per frame: 2-byte length + Opus packet + zero pad.
pub const PADDED_FRAME: usize = 128;
/// Accept at most this many frames per second from one sender (50 expected).
pub const MAX_FPS: u32 = 60;

/// Sealed into the chain when a call starts; the key never leaves RAM.
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct CallMeta {
    pub key: [u8; 32],
}

fn aad(room_id: &RoomId, call_id: &[u8; 16], from: &[u8; 32], seq: u64) -> Vec<u8> {
    let mut v = b"commx-voice".to_vec();
    v.extend_from_slice(room_id);
    v.extend_from_slice(call_id);
    v.extend_from_slice(from);
    v.extend_from_slice(&seq.to_be_bytes());
    v
}

pub fn seal_frame(
    key: &[u8; 32],
    room_id: &RoomId,
    call_id: &[u8; 16],
    from: &[u8; 32],
    seq: u64,
    opus: &[u8],
) -> Result<([u8; 24], Vec<u8>)> {
    if opus.len() > PADDED_FRAME - 2 {
        bail!("opus packet too large ({} bytes)", opus.len());
    }
    let mut plain = Zeroizing::new([0u8; PADDED_FRAME]);
    plain[..2].copy_from_slice(&(opus.len() as u16).to_le_bytes());
    plain[2..2 + opus.len()].copy_from_slice(opus);
    aead_encrypt(key, &plain[..], &aad(room_id, call_id, from, seq))
}

pub fn open_frame(
    key: &[u8; 32],
    room_id: &RoomId,
    call_id: &[u8; 16],
    from: &[u8; 32],
    seq: u64,
    nonce: &[u8; 24],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plain = aead_decrypt(key, nonce, ct, &aad(room_id, call_id, from, seq))?;
    if plain.len() != PADDED_FRAME {
        bail!("bad frame size");
    }
    let len = u16::from_le_bytes([plain[0], plain[1]]) as usize;
    if len > PADDED_FRAME - 2 {
        bail!("bad frame length");
    }
    Ok(Zeroizing::new(plain[2..2 + len].to_vec()))
}

/// Sliding-window replay filter (like IPsec/DTLS): accepts each sequence
/// number once, tolerates reordering within the last 64.
#[derive(Default)]
pub struct ReplayWindow {
    top: u64,
    bits: u64,
    seen_any: bool,
}

impl ReplayWindow {
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.top = seq;
            self.bits = 1;
            return true;
        }
        if seq > self.top {
            let shift = seq - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = seq;
            true
        } else {
            let back = self.top - seq;
            if back >= 64 || self.bits & (1 << back) != 0 {
                return false;
            }
            self.bits |= 1 << back;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_constant_size_and_bound() {
        let key = [7u8; 32];
        let (room, call, me) = ([1u8; 16], [2u8; 16], [3u8; 32]);
        let (n1, short) = seal_frame(&key, &room, &call, &me, 1, &[9; 10]).unwrap();
        let (_, long) = seal_frame(&key, &room, &call, &me, 2, &[9; 120]).unwrap();
        assert_eq!(short.len(), long.len(), "size must not depend on content");
        assert_eq!(&**open_frame(&key, &room, &call, &me, 1, &n1, &short).unwrap(), &[9; 10]);
        // wrong seq / sender / call → rejected
        assert!(open_frame(&key, &room, &call, &me, 2, &n1, &short).is_err());
        assert!(open_frame(&key, &room, &call, &[4; 32], 1, &n1, &short).is_err());
        assert!(open_frame(&key, &room, &[5; 16], &me, 1, &n1, &short).is_err());
        assert!(seal_frame(&key, &room, &call, &me, 3, &[0; 127]).is_err());
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(10));
        assert!(!w.accept(10));
        assert!(w.accept(12));
        assert!(w.accept(11), "late but in window");
        assert!(!w.accept(11));
        assert!(w.accept(200));
        assert!(!w.accept(100), "too old");
        assert!(w.accept(199));
    }
}
