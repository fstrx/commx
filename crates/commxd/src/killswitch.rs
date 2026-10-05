//! Kill switch: liveness, per-room nuke policy, and the nuke itself.

use commx_core::chain::Body;
use commx_core::ipc::IpcEvent;
use commx_core::room::KillMode;
use commx_core::wire::{nuke_bytes, verify_nuke, WireMsg};
use commx_core::{room_id_hex, RoomId};
use std::time::{Duration, Instant};

use crate::state::{Daemon, PeerKind, Role};

enum After {
    Nothing,
    Gone(&'static str),
    Nuke(String, bool),
}

impl Daemon {
    /// A message arrived on one of a room's connections.
    pub fn on_wire(&mut self, room_id: RoomId, kind: PeerKind, msg: WireMsg) {
        let ev = self.events.clone();
        let Some(room) = self.rooms.get_mut(&room_id) else { return };
        room.touch(kind);
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
    pub fn tick(&mut self) {
        let now = Instant::now();

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

        let mut gone = Vec::new();
        for (id, room) in self.rooms.iter_mut() {
            let grace = Duration::from_secs(room.cfg.grace_secs);
            if now.duration_since(room.last_hb) >= Duration::from_secs(room.cfg.heartbeat_secs()) {
                room.send_all(&WireMsg::Heartbeat);
                room.last_hb = now;
            }
            match &room.role {
                Role::Host { peers } => {
                    for (pk, p) in peers {
                        if p.overflowed() {
                            gone.push((*id, PeerKind::Member(*pk), "can't keep up"));
                        } else if now.duration_since(p.last_seen) > grace {
                            gone.push((*id, PeerKind::Member(*pk), "timed out"));
                        }
                    }
                }
                Role::Member { host } => {
                    if host.overflowed() {
                        gone.push((*id, PeerKind::Host, "can't keep up"));
                    } else if now.duration_since(host.last_seen) > grace {
                        gone.push((*id, PeerKind::Host, "timed out"));
                    }
                }
            }
        }
        for (id, kind, why) in gone {
            self.peer_gone(id, kind, why);
        }

        self.invites.retain(|_, i| i.expires > now);
        self.refresh_power();
    }
}
