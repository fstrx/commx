//! Client state: mirrors what the daemon tells us. Holds nothing the daemon
//! doesn't already have, and forgets a room's lines the moment it's nuked.

use commx_core::ipc::{ChatLine, IpcEvent, IpcRequest, RoomSummary};
use std::collections::{HashMap, HashSet};

use crate::commands::{self, Command};

/// Author tag for lines only this client shows (invite codes).
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
    pub lines: HashMap<String, Vec<ChatLine>>,
    pub home: Vec<(String, bool)>,
    pub unread: HashSet<String>,
    pub input: String,
    pub secret: Option<Secret>,
    pub status: Status,
    pub notice: Option<Notice>,
    pub scroll: usize,
    pub quit: bool,
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
        };
        app.log("commx · end-to-end encrypted, memory-only chat. Nothing here touches disk.", false);
        app.log("Start: /alias new <name> --ephemeral  (or /unlock for saved aliases)", false);
        for h in commands::HELP {
            app.log(*h, false);
        }
        app
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
        self.lines.entry(room_id.to_string()).or_default().push(ChatLine {
            from: LOCAL.into(),
            text,
            ts_min: commx_core::now_minute(),
            mine: false,
            system: true,
        });
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
                self.lines.entry(room_id).or_default().push(line);
            }
            IpcEvent::History { room_id, lines } => {
                // Keep invite lines we added locally after whatever history says.
                let local: Vec<ChatLine> = self.lines.remove(&room_id).unwrap_or_default();
                let mut merged = lines;
                merged.extend(local.into_iter().filter(|l| l.from == LOCAL));
                self.lines.insert(room_id, merged);
            }
            IpcEvent::Nuked { room_id, name, reason } => {
                let cur = self.current().map(|r| r.room_id.clone());
                self.rooms.retain(|r| r.room_id != room_id);
                self.lines.remove(&room_id);
                self.unread.remove(&room_id);
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
