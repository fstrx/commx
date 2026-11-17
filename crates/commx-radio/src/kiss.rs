//! KISS framing and the RNode host protocol, for LoRa radios on USB serial.
//!
//! An RNode takes its modulation settings from the host, then carries raw
//! LoRa payloads in `CMD_DATA` frames both ways. Command values follow the
//! RNode firmware (as used by Reticulum's `RNodeInterface`).

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

pub const CMD_DATA: u8 = 0x00;
pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_ERROR: u8 = 0x90;
pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;
pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_OFF: u8 = 0x00;

/// One KISS frame: `FEND cmd escaped(data) FEND`.
pub fn frame(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 4);
    v.push(FEND);
    v.push(cmd);
    for &b in data {
        match b {
            FEND => v.extend_from_slice(&[FESC, TFEND]),
            FESC => v.extend_from_slice(&[FESC, TFESC]),
            b => v.push(b),
        }
    }
    v.push(FEND);
    v
}

/// Reassembles frames from a serial byte stream.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    in_frame: bool,
    esc: bool,
}

impl Deframer {
    /// Bytes longer than this are never a valid frame; drop and resync.
    const MAX: usize = 1024;

    /// Feed one byte; returns `(cmd, data)` when a frame completes.
    pub fn push(&mut self, b: u8) -> Option<(u8, Vec<u8>)> {
        if b == FEND {
            let done = (self.in_frame && !self.buf.is_empty()).then(|| {
                let cmd = self.buf[0];
                (cmd, self.buf[1..].to_vec())
            });
            self.buf.clear();
            self.in_frame = true;
            self.esc = false;
            return done;
        }
        if !self.in_frame {
            return None;
        }
        let b = if self.esc {
            self.esc = false;
            match b {
                TFEND => FEND,
                TFESC => FESC,
                _ => {
                    // Broken escape: drop the frame.
                    self.buf.clear();
                    self.in_frame = false;
                    return None;
                }
            }
        } else if b == FESC {
            self.esc = true;
            return None;
        } else {
            b
        };
        if self.buf.len() >= Self::MAX {
            self.buf.clear();
            self.in_frame = false;
            return None;
        }
        self.buf.push(b);
        None
    }
}

/// RNode radio settings sent by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RnodeConfig {
    pub freq_hz: u32,
    pub bw_hz: u32,
    pub sf: u8,
    pub cr: u8,
    pub txp_dbm: u8,
}

/// Bytes that detect the RNode, set its modulation and turn the radio on.
pub fn rnode_setup(c: &RnodeConfig) -> Vec<u8> {
    let mut v = frame(CMD_DETECT, &[DETECT_REQ]);
    v.extend(frame(CMD_FREQUENCY, &c.freq_hz.to_be_bytes()));
    v.extend(frame(CMD_BANDWIDTH, &c.bw_hz.to_be_bytes()));
    v.extend(frame(CMD_TXPOWER, &[c.txp_dbm]));
    v.extend(frame(CMD_SF, &[c.sf]));
    v.extend(frame(CMD_CR, &[c.cr]));
    v.extend(frame(CMD_RADIO_STATE, &[RADIO_STATE_ON]));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_with_escapes() {
        let data = [1, FEND, 2, FESC, 3, FEND, FESC];
        let mut wire = vec![0x55, 0x66]; // line noise before the first FEND
        wire.extend(frame(CMD_DATA, &data));
        wire.extend(frame(CMD_DATA, b"second"));
        let mut d = Deframer::default();
        let got: Vec<_> = wire.iter().filter_map(|&b| d.push(b)).collect();
        assert_eq!(got, vec![(CMD_DATA, data.to_vec()), (CMD_DATA, b"second".to_vec())]);
    }

    #[test]
    fn setup_frames_parse_back() {
        let c = RnodeConfig { freq_hz: 869_525_000, bw_hz: 125_000, sf: 9, cr: 5, txp_dbm: 14 };
        let mut d = Deframer::default();
        let got: Vec<_> = rnode_setup(&c).iter().filter_map(|&b| d.push(b)).collect();
        assert_eq!(got[1], (CMD_FREQUENCY, 869_525_000u32.to_be_bytes().to_vec()));
        assert_eq!(got.last().unwrap(), &(CMD_RADIO_STATE, vec![RADIO_STATE_ON]));
    }
}
