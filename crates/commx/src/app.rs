//! Client state: mirrors what the daemon tells us. Holds nothing the daemon
//! doesn't already have, and forgets a room's lines the moment it's nuked.

use commx_core::ipc::{CallInfo, ChatLine, IpcEvent, IpcRequest, RoomSummary};
use commx_core::secmem::SealedLog;
use crate::voice::DeviceChoice;
use std::collections::{HashMap, HashSet};

const HISTORY: usize = 500;

use crate::commands::{self, Command};

fn human_size(n: u64) -> String {
    match n {
        n if n >= 1 << 20 => format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KiB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

/// `~/x` → absolute path; the daemon doesn't know about `~`.
fn expand_path(p: &str) -> String {
    let home = directories::UserDirs::new().map(|u| u.home_dir().to_path_buf());
    match (p.strip_prefix("~/").or(if p == "~" { Some("") } else { None }), home) {
        (Some(rest), Some(h)) => h.join(rest).to_string_lossy().into_owned(),
        _ => std::path::absolute(p).map(|a| a.to_string_lossy().into_owned()).unwrap_or_else(|_| p.to_string()),
    }
}

fn default_download_dir() -> String {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|d| d.to_path_buf()).or_else(|| Some(u.home_dir().to_path_buf())))
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".into())
}

enum CmdKind {
    Mic,
    Other,
}

/// Author tag for lines only this client shows (invite codes, file lists).
pub const LOCAL: &str = "~";

pub enum Secret {
    Unlock,
    NewAlias(String),
}

#[derive(Default)]
pub struct Status {
    pub alias: Option<String>,
    pub fingerprint: Option<String>,
    pub listen: String,
    pub power: String,
}

pub struct Notice {
    pub text: String,
    pub error: bool,
}

pub struct App {
    pub rooms: Vec<RoomSummary>,
    /// 0 is the home pane; rooms start at 1.
    pub sel: usize,
    /// Per-room history, encrypted in RAM; decrypted only for drawing.
    pub lines: HashMap<String, SealedLog>,
    pub home: Vec<(String, bool)>,
    pub unread: HashSet<String>,
    pub input: String,
    pub secret: Option<Secret>,
    pub status: Status,
    pub notice: Option<Notice>,
    pub scroll: usize,
    pub quit: bool,
    /// Call state per room, as reported by the daemon.
    pub calls: HashMap<String, CallInfo>,
    pub muted: bool,
    /// Push-to-talk mode, and whether the talk key is currently down.
    pub ptt: bool,
    pub talking: bool,
    /// Terminal reports key releases (hold-to-talk); otherwise Space toggles.
    pub release_keys: bool,
    /// Local loopback test is running.
    pub echo: bool,
    pub devices: DeviceChoice,
    /// Last /devices listing, for resolving `/mic 2`.
    device_lists: (Vec<String>, Vec<String>),
    /// Live meters from the audio engine.
    pub mic_level: f32,
    pub speaking: Vec<String>,
}

impl App {
    pub fn new() -> Self {
        let mut app = Self {
            rooms: Vec::new(),
            sel: 0,
            lines: HashMap::new(),
            home: Vec::new(),
            unread: HashSet::new(),
            input: String::new(),
            secret: None,
            status: Status::default(),
            notice: None,
            scroll: 0,
            quit: false,
            calls: HashMap::new(),
            muted: false,
            ptt: false,
            talking: false,
            release_keys: false,
            echo: false,
            devices: DeviceChoice::default(),
            device_lists: (Vec::new(), Vec::new()),
            mic_level: 0.0,
            speaking: Vec::new(),
        };
        app.log("commx · end-to-end encrypted, memory-only chat. Nothing here touches disk.", false);
        app.log("Start: /alias new <name> --ephemeral  (or /unlock for saved aliases)", false);
        for h in commands::HELP {
            app.log(*h, false);
        }
        app
    }

    /// Is our microphone actually sending sound (vs. silence frames)?
    pub fn mic_open(&self) -> bool {
        !self.muted && (!self.ptt || self.talking)
    }

    fn list_devices(&mut self) {
        self.device_lists = crate::voice::list_devices();
        let (mics, speakers) = self.device_lists.clone();
        let (cur_mic, cur_speaker) = (self.devices.mic.clone(), self.devices.speaker.clone());
        for (title, list, chosen) in [("microphones", mics, cur_mic), ("speakers", speakers, cur_speaker)] {
            self.log(format!("{title}{}:", if chosen.is_none() { " (using system default)" } else { "" }), false);
            if list.is_empty() {
                self.log("  none found", true);
            }
            for (i, name) in list.iter().enumerate() {
                let mark = if chosen.as_deref() == Some(name.as_str()) { "▸" } else { " " };
                self.log(format!("{mark} {}. {name}", i + 1), false);
            }
        }
    }

    /// `2`, an exact name, a unique case-insensitive substring, or `default`.
    fn resolve_device(&mut self, arg: &str, mic: bool) -> Result<Option<String>, String> {
        if arg.eq_ignore_ascii_case("default") {
            return Ok(None);
        }
        if self.device_lists.0.is_empty() && self.device_lists.1.is_empty() {
            self.device_lists = crate::voice::list_devices();
        }
        let list = if mic { &self.device_lists.0 } else { &self.device_lists.1 };
        if let Ok(n) = arg.parse::<usize>() {
            return list.get(n.wrapping_sub(1)).cloned().map(Some).ok_or_else(|| format!("no device #{n} (see /devices)"));
        }
        if let Some(exact) = list.iter().find(|d| *d == arg) {
            return Ok(Some(exact.clone()));
        }
        let lower = arg.to_lowercase();
        let hits: Vec<&String> = list.iter().filter(|d| d.to_lowercase().contains(&lower)).collect();
        match hits.as_slice() {
            [one] => Ok(Some((*one).clone())),
            [] => Err(format!("no device matching '{arg}' (see /devices)")),
            _ => Err(format!("'{arg}' matches several devices; use its number from /devices")),
        }
    }

    /// The room whose call we're in (at most one; the daemon allows one per room).
    pub fn call_room(&self) -> Option<String> {
        self.calls.iter().find(|(_, c)| c.joined).map(|(id, _)| id.clone())
    }

    pub fn current(&self) -> Option<&RoomSummary> {
        self.sel.checked_sub(1).and_then(|i| self.rooms.get(i))
    }

    pub fn log(&mut self, text: impl Into<String>, error: bool) {
        self.home.push((text.into(), error));
        if self.home.len() > 300 {
            self.home.remove(0);
        }
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        let text = text.into();
        self.log(text.clone(), error);
        self.notice = Some(Notice { text, error });
    }

    fn local_line(&mut self, room_id: &str, text: String) {
        self.log_for(room_id).push(&ChatLine {
            from: LOCAL.into(),
            text,
            ts_min: commx_core::now_minute(),
            mine: false,
            system: true,
        });
    }

    fn log_for(&mut self, room_id: &str) -> &mut SealedLog {
        self.lines.entry(room_id.to_string()).or_insert_with(|| SealedLog::new(HISTORY))
    }

    pub fn select(&mut self, idx: usize) {
        self.sel = idx.min(self.rooms.len());
        self.scroll = 0;
        if let Some(r) = self.current() {
            let id = r.room_id.clone();
            self.unread.remove(&id);
        }
    }

    pub fn cycle(&mut self, forward: bool) {
        let n = self.rooms.len() + 1;
        let next = if forward { (self.sel + 1) % n } else { (self.sel + n - 1) % n };
        self.select(next);
    }

    fn upsert_room(&mut self, room: RoomSummary) -> bool {
        match self.rooms.iter_mut().find(|r| r.room_id == room.room_id) {
            Some(r) => {
                *r = room;
                false
            }
            None => {
                self.rooms.push(room);
                true
            }
        }
    }

    /// Apply an event from the daemon. Returns follow-up requests.
    pub fn on_event(&mut self, ev: IpcEvent) -> Vec<IpcRequest> {
        let mut out = Vec::new();
        match ev {
            IpcEvent::Ok { msg } => self.notify(msg, false),
            IpcEvent::Error { msg } => self.notify(msg, true),
            IpcEvent::Status { alias, fingerprint, listen, power, rooms } => {
                self.status = Status { alias, fingerprint, listen, power };
                for r in rooms {
                    let id = r.room_id.clone();
                    if self.upsert_room(r) {
                        out.push(IpcRequest::History { room_id: id });
                    }
                }
            }
            IpcEvent::Aliases { list } => {
                if list.is_empty() {
                    self.log("no aliases loaded", false);
                }
                for a in list {
                    self.log(
                        format!(
                            "{} {}  [{}]{}",
                            if a.active { "▸" } else { " " },
                            a.name,
                            a.fingerprint,
                            if a.ephemeral { "  ephemeral" } else { "" }
                        ),
                        false,
                    );
                }
            }
            IpcEvent::InviteCode { room_id, name, code } => {
                self.log(format!("invite for #{name} (single use, 10 min):"), false);
                self.log(code.clone(), false);
                self.local_line(&room_id, "invite (single use, expires in 10 min) — send it over a channel you trust:".into());
                self.local_line(&room_id, code);
                self.notice = Some(Notice { text: format!("invite ready for #{name}"), error: false });
            }
            IpcEvent::Room { room } => {
                let id = room.room_id.clone();
                if self.upsert_room(room) {
                    // Jump to rooms we just created or joined.
                    self.select(self.rooms.len());
                    out.push(IpcRequest::History { room_id: id });
                }
            }
            IpcEvent::Line { room_id, line } => {
                if self.current().map(|r| &r.room_id) != Some(&room_id) {
                    self.unread.insert(room_id.clone());
                }
                self.log_for(&room_id).push(&line);
            }
            IpcEvent::History { room_id, lines } => {
                // Keep invite lines we added locally after whatever history says.
                let local: Vec<ChatLine> = self.lines.remove(&room_id).map(|l| l.all()).unwrap_or_default();
                let log = self.log_for(&room_id);
                for l in lines.iter().chain(local.iter().filter(|l| l.from == LOCAL)) {
                    log.push(l);
                }
            }
            IpcEvent::Call { room_id, call } => match call {
                Some(c) => {
                    self.calls.insert(room_id, c);
                }
                None => {
                    self.calls.remove(&room_id);
                }
            },
            // Audio goes straight to the engine in main; never stored.
            IpcEvent::VoiceIn { .. } => {}
            IpcEvent::Files { room_id, list } => {
                if list.is_empty() {
                    self.local_line(&room_id, "no files in this room".into());
                }
                for f in list {
                    let line = format!("#{} {} · {} · from {} · {}", f.no, f.name, human_size(f.size), f.from, f.state);
                    self.local_line(&room_id, line);
                }
            }
            IpcEvent::Nuked { room_id, name, reason } => {
                let cur = self.current().map(|r| r.room_id.clone());
                self.rooms.retain(|r| r.room_id != room_id);
                self.lines.remove(&room_id);
                self.unread.remove(&room_id);
                self.calls.remove(&room_id);
                if cur.as_deref() == Some(&room_id) {
                    self.select(0);
                } else if let Some(cur) = cur {
                    let idx = self.rooms.iter().position(|r| r.room_id == cur).map_or(0, |i| i + 1);
                    self.select(idx);
                }
                self.notify(format!("☢ #{name} nuked — {reason}"), true);
            }
        }
        out
    }

    /// Enter pressed. Returns requests to send.
    pub fn submit(&mut self) -> Vec<IpcRequest> {
        let input = std::mem::take(&mut self.input);
        if let Some(secret) = self.secret.take() {
            return match secret {
                Secret::Unlock => vec![IpcRequest::Unlock { passphrase: input }],
                Secret::NewAlias(name) => {
                    vec![IpcRequest::AliasNew { name, ephemeral: false, passphrase: Some(input) }]
                }
            };
        }
        if input.trim().is_empty() {
            return Vec::new();
        }
        let cmd = match commands::parse(&input) {
            Ok(c) => c,
            Err(e) => {
                self.notify(e, true);
                return Vec::new();
            }
        };
        let cmd_kind = if matches!(cmd, Command::Mic(_)) { CmdKind::Mic } else { CmdKind::Other };
        let room = self.current().map(|r| r.room_id.clone());
        let need_room = |s: &mut Self| {
            s.notify("select a room first (Tab)", true);
            Vec::new()
        };
        match cmd {
            Command::Help => {
                for h in commands::HELP {
                    self.log(*h, false);
                }
                self.select(0);
                Vec::new()
            }
            Command::Quit => {
                self.quit = true;
                Vec::new()
            }
            Command::Status => vec![IpcRequest::Status, IpcRequest::AliasList],
            Command::AliasList => {
                self.select(0);
                vec![IpcRequest::AliasList]
            }
            Command::AliasUse(name) => vec![IpcRequest::AliasUse { name }],
            Command::AliasNew { name, ephemeral: true } => {
                vec![IpcRequest::AliasNew { name, ephemeral: true, passphrase: None }]
            }
            Command::AliasNew { name, ephemeral: false } => {
                self.secret = Some(Secret::NewAlias(name));
                Vec::new()
            }
            Command::Unlock => {
                self.secret = Some(Secret::Unlock);
                Vec::new()
            }
            Command::RoomNew { name, kill_mode, grace_secs } => {
                vec![IpcRequest::RoomNew { name, kill_mode, grace_secs, dm: false }]
            }
            Command::Dm(name) => vec![IpcRequest::RoomNew {
                name,
                kill_mode: commx_core::room::KillMode::AnyMember,
                grace_secs: commx_core::room::DEFAULT_GRACE_SECS,
                dm: true,
            }],
            Command::Join(code) => {
                self.notice = Some(Notice { text: "connecting…".into(), error: false });
                vec![IpcRequest::Join { code }]
            }
            Command::Invite => match room {
                Some(room_id) => vec![IpcRequest::Invite { room_id }],
                None => need_room(self),
            },
            Command::SendFile(path) => match room {
                Some(room_id) => vec![IpcRequest::SendFile { room_id, path: expand_path(&path) }],
                None => need_room(self),
            },
            Command::Files => match room {
                Some(room_id) => vec![IpcRequest::Files { room_id }],
                None => need_room(self),
            },
            Command::Save { no, dest } => match room {
                Some(room_id) => {
                    let dest = dest.map(|d| expand_path(&d)).unwrap_or_else(default_download_dir);
                    vec![IpcRequest::SaveFile { room_id, no, dest }]
                }
                None => need_room(self),
            },
            Command::Call => match room {
                Some(room_id) => {
                    if self.call_room().is_some_and(|r| r != room_id) {
                        self.notify("hang up your other call first", true);
                        return Vec::new();
                    }
                    vec![IpcRequest::Call { room_id }]
                }
                None => need_room(self),
            },
            Command::Hangup => match self.call_room() {
                Some(room_id) => vec![IpcRequest::Hangup { room_id }],
                None => {
                    self.notify("you're not in a call", true);
                    Vec::new()
                }
            },
            Command::Mute => {
                self.muted = !self.muted;
                self.notify(if self.muted { "microphone muted (still sending silence)" } else { "microphone on" }, false);
                Vec::new()
            }
            Command::Ptt => {
                self.ptt = !self.ptt;
                self.talking = false;
                let how = if self.release_keys { "hold Space" } else { "press Space to start/stop" };
                self.notify(
                    if self.ptt { format!("push-to-talk on: {how} with an empty input") } else { "push-to-talk off: open mic".into() },
                    false,
                );
                Vec::new()
            }
            Command::EchoTest => {
                if !self.echo && self.call_room().is_some() {
                    self.notify("hang up first; the echo test uses your mic and speakers", true);
                    return Vec::new();
                }
                self.echo = !self.echo;
                self.notify(
                    if self.echo { "echo test: speak, you'll hear yourself ~1s later (headphones!) — /echotest to stop" } else { "echo test stopped" },
                    false,
                );
                Vec::new()
            }
            Command::Devices => {
                self.list_devices();
                self.select(0);
                Vec::new()
            }
            Command::Mic(arg) | Command::Speaker(arg) => {
                let mic = matches!(cmd_kind, CmdKind::Mic);
                match self.resolve_device(&arg, mic) {
                    Ok(choice) => {
                        let label = choice.clone().unwrap_or_else(|| "system default".into());
                        if mic {
                            self.devices.mic = choice;
                        } else {
                            self.devices.speaker = choice;
                        }
                        self.notify(format!("{} → {label}", if mic { "microphone" } else { "speakers" }), false);
                    }
                    Err(e) => self.notify(e, true),
                }
                Vec::new()
            }
            Command::Nuke { all: true } => vec![IpcRequest::Nuke { room_id: None }],
            Command::Nuke { all: false } => match room {
                Some(room_id) => vec![IpcRequest::Nuke { room_id: Some(room_id) }],
                None => need_room(self),
            },
            Command::Say(text) => match room {
                Some(room_id) => {
                    self.scroll = 0;
                    vec![IpcRequest::Send { room_id, text }]
                }
                None => need_room(self),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptt_and_mute_gate_the_mic() {
        let mut app = App::new();
        assert!(app.mic_open());
        app.ptt = true;
        assert!(!app.mic_open(), "ptt idle");
        app.talking = true;
        assert!(app.mic_open(), "ptt held");
        app.muted = true;
        assert!(!app.mic_open(), "mute wins");
    }

    #[test]
    fn resolves_devices_by_number_name_and_substring() {
        let mut app = App::new();
        app.device_lists = (vec!["MacBook Pro Microphone".into(), "USB Headset Mic".into()], vec!["AirPods".into()]);
        assert_eq!(app.resolve_device("2", true).unwrap().as_deref(), Some("USB Headset Mic"));
        assert_eq!(app.resolve_device("usb", true).unwrap().as_deref(), Some("USB Headset Mic"));
        assert_eq!(app.resolve_device("default", true).unwrap(), None);
        assert!(app.resolve_device("mic", true).is_err(), "ambiguous");
        assert!(app.resolve_device("9", true).is_err());
        assert_eq!(app.resolve_device("airpods", false).unwrap().as_deref(), Some("AirPods"));
    }
}
