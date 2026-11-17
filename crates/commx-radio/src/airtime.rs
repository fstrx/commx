//! LoRa time on air, and the airtime budget a radio must stay under.

use std::collections::VecDeque;

/// LoRa modulation settings that decide how long a packet occupies the air.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoRa {
    /// Spreading factor, 7–12.
    pub sf: u8,
    /// Bandwidth in Hz (125 000, 250 000, ...).
    pub bw_hz: u32,
    /// Coding rate denominator: 5 means 4/5, up to 8 (4/8).
    pub cr: u8,
}

impl Default for LoRa {
    fn default() -> Self {
        Self { sf: 9, bw_hz: 125_000, cr: 5 }
    }
}

impl LoRa {
    pub fn valid(&self) -> bool {
        (7..=12).contains(&self.sf) && (5..=8).contains(&self.cr) && self.bw_hz >= 7_800 && self.bw_hz <= 500_000
    }

    /// Time on air of one packet, in milliseconds. Semtech AN1200.13, with an
    /// 8-symbol preamble, explicit header and CRC on.
    pub fn airtime_ms(&self, len: usize) -> f64 {
        let sf = self.sf as f64;
        let t_sym = (1u64 << self.sf) as f64 / self.bw_hz as f64 * 1000.0;
        // Low data rate optimisation is mandated once a symbol exceeds 16 ms.
        let de = if t_sym > 16.0 { 1.0 } else { 0.0 };
        let preamble = (8.0 + 4.25) * t_sym;
        let num = 8.0 * len as f64 - 4.0 * sf + 28.0 + 16.0;
        let den = 4.0 * (sf - 2.0 * de);
        let payload_syms = 8.0 + ((num / den).ceil() * self.cr as f64).max(0.0);
        preamble + payload_syms * t_sym
    }
}

const HOUR_MS: u64 = 3_600_000;

/// Sliding one-hour window of airtime used, against a duty-cycle fraction
/// (0.01 for the EU's 1%).
pub struct Budget {
    fraction: f64,
    sent: VecDeque<(u64, f64)>,
    used: f64,
}

impl Budget {
    pub fn new(fraction: f64) -> Self {
        Self { fraction: fraction.clamp(0.0, 1.0), sent: VecDeque::new(), used: 0.0 }
    }

    fn expire(&mut self, now: u64) {
        while let Some(&(t, ms)) = self.sent.front() {
            if now.saturating_sub(t) < HOUR_MS {
                break;
            }
            self.used -= ms;
            self.sent.pop_front();
        }
        if self.sent.is_empty() {
            self.used = 0.0;
        }
    }

    pub fn allows(&mut self, now: u64, ms: f64) -> bool {
        self.expire(now);
        self.used + ms <= self.fraction * HOUR_MS as f64
    }

    pub fn spend(&mut self, now: u64, ms: f64) {
        self.expire(now);
        self.sent.push_back((now, ms));
        self.used += ms;
    }

    /// Airtime left in the current window, in milliseconds.
    pub fn left_ms(&mut self, now: u64) -> f64 {
        self.expire(now);
        (self.fraction * HOUR_MS as f64 - self.used).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_spec_table() {
        let at = |sf, len| LoRa { sf, bw_hz: 125_000, cr: 5 }.airtime_ms(len);
        assert!((at(7, 230) - 360.0).abs() < 15.0, "{}", at(7, 230));
        assert!((at(9, 230) - 1150.0).abs() < 15.0, "{}", at(9, 230));
        assert!((at(12, 230) - 8200.0).abs() < 100.0, "{}", at(12, 230));
        assert!((at(9, 40) - 290.0).abs() < 15.0, "{}", at(9, 40));
    }

    #[test]
    fn budget_is_a_sliding_hour() {
        let mut b = Budget::new(0.01); // 36 s per hour
        for i in 0..36 {
            assert!(b.allows(i * 1000, 1000.0));
            b.spend(i * 1000, 1000.0);
        }
        assert!(!b.allows(36_000, 1000.0));
        assert!(b.allows(HOUR_MS, 1000.0), "the first packet left the window");
    }
}
