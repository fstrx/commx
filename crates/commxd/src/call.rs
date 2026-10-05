//! Voice calls inside a room.
//!
//! A call starts with a signed `Body::Call` in the room chain carrying a fresh
//! call key sealed under the room key. Joining/leaving is a `CallPresence`
//! control message; the host keeps the authoritative roster and echoes it to
//! everyone. Frames go member → host → other participants on the media lane,
//! sealed end-to-end with the call key; the host forwards (and, as a member,
//! can listen) but there is no server in the loop.
//!
//! Known limit: frames are authenticated as "someone holding the call key",
//! not per sender. A malicious participant (or host) could inject audio
//! attributed to someone else. Per-frame signatures would double bandwidth.

use anyhow::{anyhow, bail, Result};
use commx_core::chain::{msg_aad, Body, Payload};
use commx_core::ipc::{CallInfo, IpcEvent};
use commx_core::room_id_hex;
use commx_core::secmem::Locked;
use commx_core::voice::{open_frame, seal_frame, CallMeta, ReplayWindow, MAX_FPS};
use commx_core::wire::WireMsg;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::state::{Events, PeerKind, Role, Room};

pub struct Call {
    pub id: [u8; 16],
    key: Locked<32>,
    /// Join order, for display.
    pub participants: Vec<[u8; 32]>,
    my_seq: u64,
    replay: HashMap<[u8; 32], ReplayWindow>,
    rate: HashMap<[u8; 32], (Instant, u32)>,
}

impl Call {
    fn new(id: [u8; 16], key: Locked<32>, starter: [u8; 32]) -> Self {
        Self {
            id,
            key,
            participants: vec![starter],
            my_seq: 0,
            replay: HashMap::new(),
            rate: HashMap::new(),
        }
    }

    pub fn has(&self, pk: &[u8; 32]) -> bool {
        self.participants.contains(pk)
    }

    /// Per-sender frames-per-second cap.
    fn rate_ok(&mut self, pk: &[u8; 32]) -> bool {
        let now = Instant::now();
        let (start, n) = self.rate.entry(*pk).or_insert((now, 0));
        if now.duration_since(*start) >= Duration::from_secs(1) {
            *start = now;
            *n = 0;
        }
        *n += 1;
        *n <= MAX_FPS
    }
}

fn call_meta_aad(room: &Room, p: &Payload, call_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = msg_aad(&room.id, p.epoch, &p.author);
    aad.extend_from_slice(b"call");
    aad.extend_from_slice(call_id);
    aad
}

impl Room {
    pub fn call_info(&self) -> Option<CallInfo> {
        let me = self.me.public().sign_pk;
        self.call.as_ref().map(|c| CallInfo {
            participants: c
                .participants
                .iter()
                .map(|pk| self.members.iter().find(|m| &m.id.sign_pk == pk).map_or("?".into(), |m| m.name.clone()))
                .collect(),
            joined: c.has(&me),
        })
    }

    pub fn emit_call(&self, ev: &Events) {
        ev.send(IpcEvent::Call { room_id: room_id_hex(&self.id), call: self.call_info() });
    }

    pub fn open_call_meta(&self, p: &Payload, call_id: &[u8; 16], nonce: &[u8; 24], ct: &[u8]) -> Result<CallMeta> {
        let key = self.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch {}", p.epoch))?;
        let plain = key.decrypt(nonce, ct, &call_meta_aad(self, p, call_id))?;
        Ok(postcard::from_bytes(&plain)?)
    }

    /// A `Body::Call` block: a new call (replacing any old one), started by its author.
    pub fn apply_call(&mut self, ev: &Events, p: &Payload, call_id: &[u8; 16], nonce: &[u8; 24], ct: &[u8]) -> Result<()> {
        let meta = self.open_call_meta(p, call_id, nonce, ct)?;
        let from = self
            .members
            .iter()
            .find(|m| m.id.sign_pk == p.author)
            .map(|m| m.name.clone())
            .ok_or_else(|| anyhow!("call from non-member"))?;
        self.call = Some(Call::new(*call_id, Locked::from_bytes(&meta.key), p.author));
        let hint = if p.author == self.me.public().sign_pk { "you're in" } else { "/call to join" };
        self.system(ev, format!("📞 {from} started a call — {hint}"));
        self.emit_call(ev);
        Ok(())
    }

    pub fn start_call(&mut self, ev: &Events) -> Result<()> {
        if self.call.is_some() {
            bail!("a call is already running here");
        }
        let mut call_id = [0u8; 16];
        OsRng.fill_bytes(&mut call_id);
        let meta = CallMeta { key: *Locked::<32>::random().bytes() };
        let key = self.keys.get(&self.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let plain = Zeroizing::new(postcard::to_allocvec(&meta)?);
        let me_pk = self.me.public().sign_pk;
        let mut aad = msg_aad(&self.id, self.epoch, &me_pk);
        aad.extend_from_slice(b"call");
        aad.extend_from_slice(&call_id);
        let (nonce, ct) = key.encrypt(&plain, &aad)?;
        let payload = Payload::new(&self.me, self.id, self.epoch, Body::Call { call_id, nonce, ct });
        match &self.role {
            Role::Host { .. } => self.publish(ev, payload),
            Role::Member { host } => {
                host.send(WireMsg::Submit(payload));
                Ok(())
            }
        }
    }

    /// Update the roster. Returns true if it changed. Ends the call when empty.
    fn set_presence(&mut self, ev: &Events, pk: [u8; 32], joined: bool) -> bool {
        let Some(call) = &mut self.call else { return false };
        let changed = if joined {
            if call.has(&pk) {
                false
            } else {
                call.participants.push(pk);
                true
            }
        } else {
            let before = call.participants.len();
            call.participants.retain(|p| *p != pk);
            call.replay.remove(&pk);
            before != call.participants.len()
        };
        if !changed {
            return false;
        }
        let name = self.members.iter().find(|m| m.id.sign_pk == pk).map_or("?".into(), |m| m.name.clone());
        let empty = self.call.as_ref().is_some_and(|c| c.participants.is_empty());
        if empty {
            self.call = None;
            self.system(ev, "📞 call ended");
        } else {
            self.system(ev, format!("📞 {name} {} the call", if joined { "joined" } else { "left" }));
        }
        self.emit_call(ev);
        true
    }

    /// Host: tell everyone about a roster change.
    fn broadcast_presence(&self, call_id: [u8; 16], member: [u8; 32], joined: bool) {
        if let Role::Host { peers } = &self.role {
            let msg = WireMsg::CallPresence { room_id: self.id, call_id, member, joined };
            peers.values().for_each(|p| p.send(msg.clone()));
        }
    }

    /// Our own join/leave.
    pub fn set_my_presence(&mut self, ev: &Events, joined: bool) -> Result<()> {
        let call_id = self.call.as_ref().ok_or_else(|| anyhow!("no call in this room"))?.id;
        let me = self.me.public().sign_pk;
        match &self.role {
            Role::Host { .. } => {
                if self.set_presence(ev, me, joined) {
                    self.broadcast_presence(call_id, me, joined);
                }
            }
            Role::Member { host } => {
                host.send(WireMsg::CallPresence { room_id: self.id, call_id, member: me, joined });
                self.set_presence(ev, me, joined);
            }
        }
        Ok(())
    }

    pub fn on_presence(&mut self, ev: &Events, kind: PeerKind, call_id: [u8; 16], member: [u8; 32], joined: bool) {
        if self.call.as_ref().map(|c| c.id) != Some(call_id) {
            return;
        }
        match kind {
            // Members may only speak for themselves.
            PeerKind::Member(pk) if pk == member => {
                if self.set_presence(ev, member, joined) {
                    self.broadcast_presence(call_id, member, joined);
                }
            }
            PeerKind::Host => {
                self.set_presence(ev, member, joined);
            }
            _ => {}
        }
    }

    /// Host: a member's connection went away.
    pub fn call_member_gone(&mut self, ev: &Events, pk: [u8; 32]) {
        if let Some(id) = self.call.as_ref().map(|c| c.id) {
            if self.set_presence(ev, pk, false) {
                self.broadcast_presence(id, pk, false);
            }
        }
    }

    /// Our microphone produced a frame.
    pub fn send_voice(&mut self, opus: &[u8]) -> Result<()> {
        let me = self.me.public().sign_pk;
        let room_id = self.id;
        let Some(call) = &mut self.call else { return Ok(()) };
        if !call.has(&me) {
            return Ok(());
        }
        call.my_seq += 1;
        let seq = call.my_seq;
        let (nonce, ct) = seal_frame(call.key.bytes(), &room_id, &call.id, &me, seq, opus)?;
        let msg = WireMsg::Voice { room_id, call_id: call.id, from: me, seq, nonce, ct };
        match &self.role {
            Role::Host { peers } => {
                for (pk, p) in peers {
                    if call.has(pk) {
                        p.send_media(msg.clone());
                    }
                }
            }
            Role::Member { host } => host.send_media(msg),
        }
        Ok(())
    }

    /// A frame arrived from the network.
    pub fn on_voice(&mut self, ev: &Events, kind: PeerKind, msg: WireMsg) {
        let me = self.me.public().sign_pk;
        let room_id = self.id;
        let WireMsg::Voice { call_id, from, seq, nonce, ct, .. } = &msg else { return };
        let Some(call) = &mut self.call else { return };
        if call.id != *call_id || !call.has(from) {
            return;
        }
        match kind {
            PeerKind::Member(pk) if pk == *from => {
                if !call.rate_ok(&pk) {
                    return;
                }
            }
            PeerKind::Host => {}
            _ => return,
        }
        if !call.replay.entry(*from).or_default().accept(*seq) {
            return;
        }
        // Drop anything that doesn't authenticate; never relay garbage.
        let Ok(opus) = open_frame(call.key.bytes(), &room_id, call_id, from, *seq, nonce, ct) else { return };
        if let Role::Host { peers } = &self.role {
            for (pk, p) in peers {
                if pk != from && call.has(pk) {
                    p.send_media(msg.clone());
                }
            }
        }
        if call.has(&me) {
            let name = self.members.iter().find(|m| &m.id.sign_pk == from).map_or("?".into(), |m| m.name.clone());
            ev.send(IpcEvent::VoiceIn { room_id: room_id_hex(&room_id), from: name, seq: *seq, opus: hex::encode(&*opus) });
        }
    }
}
