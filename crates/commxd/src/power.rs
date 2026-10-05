//! Keep the machine awake while rooms are live, and notice when it slept anyway.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

pub struct Power {
    enabled: bool,
    child: Option<Child>,
    last_mono: Instant,
    last_wall: SystemTime,
    battery: Option<(Instant, bool)>,
}

/// How long the machine was suspended between two ticks. The monotonic clock
/// (`Instant`) stops during sleep on macOS and Linux; the wall clock doesn't.
pub fn sleep_gap(mono_elapsed: Duration, wall_elapsed: Duration) -> Duration {
    let gap = wall_elapsed.saturating_sub(mono_elapsed);
    // Ignore small NTP slews.
    if gap < Duration::from_secs(2) {
        Duration::ZERO
    } else {
        gap
    }
}

impl Power {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            child: None,
            last_mono: Instant::now(),
            last_wall: SystemTime::now(),
            battery: None,
        }
    }

    /// Hold the sleep inhibitor iff some room is live.
    pub fn set_active(&mut self, active: bool) {
        if let Some(c) = &mut self.child {
            if !matches!(c.try_wait(), Ok(None)) {
                self.child = None;
            }
        }
        if active && self.enabled && self.child.is_none() {
            self.child = spawn_inhibitor();
        } else if !active {
            self.release();
        }
    }

    fn release(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Returns how long we were asleep since the previous tick (zero normally).
    pub fn tick(&mut self) -> Duration {
        let mono = Instant::now();
        let wall = SystemTime::now();
        let gap = sleep_gap(
            mono.duration_since(self.last_mono),
            wall.duration_since(self.last_wall).unwrap_or_default(),
        );
        self.last_mono = mono;
        self.last_wall = wall;
        gap
    }

    pub fn label(&mut self) -> String {
        if !self.enabled {
            return "keep-awake off".into();
        }
        if self.child.is_none() {
            return "keep-awake idle".into();
        }
        if self.on_battery() {
            "keep-awake on · battery: lid close will still sleep".into()
        } else {
            "keep-awake on".into()
        }
    }

    fn on_battery(&mut self) -> bool {
        if let Some((at, v)) = self.battery {
            if at.elapsed() < Duration::from_secs(30) {
                return v;
            }
        }
        let v = cfg!(target_os = "macos")
            && Command::new("pmset")
                .args(["-g", "batt"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("Battery Power"))
                .unwrap_or(false);
        self.battery = Some((Instant::now(), v));
        v
    }
}

impl Drop for Power {
    fn drop(&mut self) {
        self.release();
    }
}

fn spawn_inhibitor() -> Option<Child> {
    let pid = std::process::id().to_string();
    let mut cmd = if cfg!(target_os = "macos") {
        // -i idle sleep, -s system sleep on AC, -w exit when we exit.
        let mut c = Command::new("caffeinate");
        c.args(["-i", "-s", "-w", &pid]);
        c
    } else if cfg!(target_os = "linux") {
        let mut c = Command::new("systemd-inhibit");
        c.args([
            "--what=sleep:idle",
            "--who=commxd",
            "--why=active commx rooms",
            "--mode=block",
            "sh",
            "-c",
            &format!("while kill -0 {pid} 2>/dev/null; do sleep 5; done"),
        ]);
        c
    } else {
        return None;
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sleep_gap() {
        let s = Duration::from_secs;
        assert_eq!(sleep_gap(s(1), s(1)), Duration::ZERO);
        assert_eq!(sleep_gap(s(1), Duration::from_millis(2500)), Duration::ZERO);
        assert_eq!(sleep_gap(s(1), s(61)), s(60));
        // wall clock stepped backwards
        assert_eq!(sleep_gap(s(5), s(0)), Duration::ZERO);
    }
}
