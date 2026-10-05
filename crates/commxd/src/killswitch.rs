//! Kill switch: liveness, per-room nuke policy, and the nuke itself.

use commx_core::chain::Body;
use commx_core::ipc::IpcEvent;
use commx_core::room::KillMode;
use commx_core::wire::{nuke_bytes, verify_nuke, WireMsg};
use commx_core::{room_id_hex, RoomId};
use std::time::{Duration, Instant};

use crate::files::FileState;
use crate::state::{Daemon, Events, Followup, PeerKind, Role, Room};
use crate::supervise::contain;

const FILE_STALL: Duration = Duration::from_secs(90);

enum After {
    Nothing,
    Gone(&'static str),
    Nuke(String, bool),
}

impl Daemon {
    /// A message arrived on one of a room's connections.
    pub fn on_wire(&mut self, room_id: RoomId, kind: PeerKind, msg: WireMsg) -> Followup {
        let ev = self.events.clone();
        let Some(room) = self.rooms.get_mut(&room_id) else { return Followup::default() };
        #[cfg(debug_assertions)]
        if room.fault_armed == Some("wire") {
            panic!("injected fault: room wire handling");
        }
        room.touch(kind);
        match msg {
            WireMsg::FileChunk { .. } => return room.on_chunk(kind, msg),
            WireMsg::Voice { .. } => {
                room.on_voice(&ev, kind, msg);
                return Followup::default();
            }
            WireMsg::CallPresence { call_id, member, joined, .. } => {
                room.on_presence(&ev, kind, call_id, member, joined);
                return Followup::default();
            }
            _ => {}
        }
        let after = match (kind, msg) {
            (PeerKind::Member(pk), WireMsg::Submit(p)) => {
                if room.allow_submit(&pk) {
                    room.host_submit(&ev, pk, p);
                }
                After::Nothing
            }
            (PeerKind::Member(_), WireMsg::Leave { .. }) => After::Gone("left"),
            (PeerKind::Host, WireMsg::Block(b)) => match room.member_block(&ev, &b) {
                Ok(()) => After::Nothing,
                Err(e) => After::Nuke(format!("integrity failure, host may be compromised: {e}"), true),
            },
            (PeerKind::Host, WireMsg::Nuke { room_id: rid, sig }) => {
                if rid == room_id && verify_nuke(&room.chain.host_pk, &rid, &sig) {
                    After::Nuke("host nuked the room".into(), false)
                } else {
                    After::Nothing
                }
            }
            _ => After::Nothing,
        };
        match after {
            After::Nothing => {}
            After::Gone(why) => self.peer_gone(room_id, kind, why),
            After::Nuke(reason, tell) => self.nuke(&room_id, &reason, tell),
        }
        Followup::default()
    }

    /// Background hash check of a received file finished.
    pub fn file_verified(&mut self, room_id: RoomId, file_id: [u8; 16], res: anyhow::Result<()>) {
        let ev = self.events.clone();
        let Some(room) = self.rooms.get_mut(&room_id) else { return };
        let Some(e) = room.files.get_mut(&file_id) else { return };
        let (no, name) = (e.no, e.name.clone());
        let line = match res {
            Ok(()) => {
                e.state = FileState::Ready;
                format!("📎 #{no} '{name}' ready — /save {no} [path]")
            }
            Err(err) => {
                e.state = FileState::Failed(err.to_string());
                e.blob = None;
                format!("📎 #{no} '{name}' failed verification: {err}")
            }
        };
        room.system(&ev, line);
    }

    /// A connection died or went silent past the grace window.
    pub fn peer_gone(&mut self, room_id: RoomId, kind: PeerKind, why: &str) {
        let ev = self.events.clone();
        let Some(room) = self.rooms.get_mut(&room_id) else { return };
        match kind {
            PeerKind::Host => {
                let reason = format!("host dropped ({why})");
                self.nuke(&room_id, &reason, false);
            }
            PeerKind::Member(pk) => {
                let Role::Host { peers } = &mut room.role else { return };
                if peers.remove(&pk).is_none() {
                    return;
                }
                room.call_member_gone(&ev, pk);
                let name = room
                    .members
                    .iter()
                    .find(|m| m.id.sign_pk == pk)
                    .map(|m| m.name.clone())
                    .unwrap_or_else(|| "?".into());
                match room.cfg.kill_mode {
                    KillMode::AnyMember => {
                        let reason = format!("{name} dropped ({why})");
                        self.nuke(&room_id, &reason, true);
                    }
                    KillMode::HostOnly => {
                        // Members only receive blocks, never the key itself, so
                        // removing them + rotating locks them out going forward.
                        let ok = room.host_body(&ev, Body::Leave { sign_pk: pk }).and_then(|_| room.rotate_key(&ev));
                        if ok.is_err() {
                            self.nuke(&room_id, "key rotation failed", true);
                        }
                    }
                }
            }
        }
    }

    /// Destroy a room: tell peers if asked, drop every connection, wipe keys,
    /// chain and plaintext from memory.
    pub fn nuke(&mut self, room_id: &RoomId, reason: &str, tell_peers: bool) {
        let Some(room) = self.rooms.remove(room_id) else { return };
        if tell_peers {
            match &room.role {
                Role::Host { .. } => room.send_all(&WireMsg::Nuke {
                    room_id: *room_id,
                    sig: room.me.sign(&nuke_bytes(room_id)),
                }),
                Role::Member { .. } => room.send_all(&WireMsg::Leave { room_id: *room_id }),
            }
        }
        self.invites.retain(|_, i| &i.room_id != room_id);
        if let Some(onion) = &room.onion {
            self.net.release(onion.clone());
        }
        self.emit(IpcEvent::Nuked {
            room_id: room_id_hex(room_id),
            name: room.cfg.name.clone(),
            reason: reason.to_string(),
        });
        // Dropping the room zeroizes keys and lines and closes its connections.
        drop(room);
        self.refresh_power();
    }

    pub fn nuke_all(&mut self, reason: &str) {
        let ids: Vec<RoomId> = self.rooms.keys().copied().collect();
        for id in ids {
            self.nuke(&id, reason, true);
        }
    }

    /// Runs every second: heartbeats, liveness, sleep detection, invite expiry.
    /// Runs every second: heartbeats, liveness, sleep detection, invite expiry.
    ///
    /// Each room is its own fault domain: if one room's step panics, that
    /// room is nuked and every other room still gets its heartbeats and its
    /// kill switch.
    pub fn tick(&mut self) {
        let now = Instant::now();
        #[cfg(debug_assertions)]
        if self.fault.as_deref() == Some("tick-task") {
            self.fault = None;
            panic!("injected fault: tick task");
        }

        let slept = self.power.tick();
        if !slept.is_zero() {
            let ids: Vec<RoomId> = self
                .rooms
                .iter()
                .filter(|(_, r)| slept.as_secs() >= r.cfg.grace_secs)
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                let reason = format!("machine slept {}s, past the grace window", slept.as_secs());
                self.nuke(&id, &reason, true);
            }
        }

        let ev = self.events.clone();
        let ids: Vec<RoomId> = self.rooms.keys().copied().collect();
        for id in ids {
            let Some(room) = self.rooms.get_mut(&id) else { continue };
            match contain(|| tick_room(room, &ev, now)) {
                Ok(gone) => {
                    for (kind, why) in gone {
                        if contain(|| self.peer_gone(id, kind, why)).is_err() {
                            self.contained_fault(&id);
                        }
                    }
                }
                Err(()) => self.contained_fault(&id),
            }
        }

        self.invites.retain(|_, i| i.expires > now);
        // Forget UDP paths whose room or peer is gone.
        let rooms = &self.rooms;
        self.udp_index.retain(|_, (rid, kind)| match (rooms.get(rid).map(|r| &r.role), kind) {
            (Some(Role::Host { peers }), PeerKind::Member(pk)) => peers.contains_key(pk),
            (Some(Role::Member { .. }), PeerKind::Host) => true,
            _ => false,
        });
        self.refresh_power();
    }

    /// A room's code panicked: its state can't be trusted, so destroy it.
    /// Done with the panic already caught, so it never reaches the daemon.
    pub fn contained_fault(&mut self, room_id: &RoomId) {
        // Even the nuke is contained; worst case the room is just dropped.
        if contain(|| self.nuke(room_id, "internal fault (contained)", true)).is_err() {
            self.rooms.remove(room_id);
        }
    }
}

/// One room's per-second work. Returns peers to treat as gone.
fn tick_room(room: &mut Room, ev: &Events, now: Instant) -> Vec<(PeerKind, &'static str)> {
    #[cfg(debug_assertions)]
    if room.fault_armed == Some("tick") {
        panic!("injected fault: room tick");
    }
    let grace = Duration::from_secs(room.cfg.grace_secs);
    if now.duration_since(room.last_hb) >= Duration::from_secs(room.cfg.heartbeat_secs()) {
        room.send_all(&WireMsg::Heartbeat);
        room.last_hb = now;
    }
    if let Role::Member { host } = &mut room.role {
        if let Some(u) = &mut host.udp {
            u.maybe_ping();
        }
    }
    let mut gone = Vec::new();
    match &room.role {
        Role::Host { peers } => {
            for (pk, p) in peers {
                if p.overflowed() {
                    gone.push((PeerKind::Member(*pk), "can't keep up"));
                } else if now.duration_since(p.last_seen) > grace {
                    gone.push((PeerKind::Member(*pk), "timed out"));
                }
            }
        }
        Role::Member { host } => {
            if host.overflowed() {
                gone.push((PeerKind::Host, "can't keep up"));
            } else if now.duration_since(host.last_seen) > grace {
                gone.push((PeerKind::Host, "timed out"));
            }
        }
    }
    let stalled: Vec<[u8; 16]> = room.files.values().filter(|f| f.stalled(FILE_STALL)).map(|f| f.id).collect();
    for id in stalled {
        if let Some(f) = room.files.get_mut(&id) {
            f.state = FileState::Failed("transfer stalled".into());
            f.blob = None;
            let line = format!("📎 #{} '{}' failed: transfer stalled", f.no, f.name);
            room.system(ev, line);
        }
    }
    gone
}
