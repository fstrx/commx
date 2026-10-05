//! Daemon state: aliases, live rooms and their peers. Everything here lives in
//! RAM only. Locked with a std mutex and never held across an await.

use anyhow::{anyhow, bail, Result};
use commx_core::chain::{msg_aad, Block, Body, Chain, ChatPlain, Payload};
use commx_core::crypto::{open_sealed, seal_to, RoomKey};
use commx_core::identity::{verify, Identity};
use commx_core::invite::Invite;
use commx_core::ipc::{AliasInfo, ChatLine, IpcEvent, RoomSummary};
use commx_core::room::{KillMode, MemberInfo, RoomConfig, MIN_GRACE_SECS};
use commx_core::wire::{channel_binding, WireMsg};
use commx_core::{room_id_hex, RoomId, MAX_TEXT_LEN};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot};
use zeroize::Zeroize;

use crate::power::Power;

pub type Shared = Arc<Mutex<Daemon>>;
pub type Events = broadcast::Sender<IpcEvent>;

pub const INVITE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_LINES: usize = 500;

pub fn lock(s: &Shared) -> MutexGuard<'_, Daemon> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct AliasEntry {
    pub id: Arc<Identity>,
    pub ephemeral: bool,
}

/// One live connection. Dropping it closes the channel: the writer drains and
/// exits, and the dropped cancel sender stops the reader.
pub struct Peer {
    tx: mpsc::UnboundedSender<WireMsg>,
    pub last_seen: Instant,
    _cancel: oneshot::Sender<()>,
}

impl Peer {
    pub fn new(tx: mpsc::UnboundedSender<WireMsg>, cancel: oneshot::Sender<()>) -> Self {
        Self { tx, last_seen: Instant::now(), _cancel: cancel }
    }

    pub fn send(&self, msg: WireMsg) {
        let _ = self.tx.send(msg);
    }
}

pub enum Role {
    Host { peers: HashMap<[u8; 32], Peer> },
    Member { host: Peer },
}

/// Which end of a connection a message came from.
#[derive(Clone, Copy, Debug)]
pub enum PeerKind {
    /// Seen by the host: a member, keyed by signing key.
    Member([u8; 32]),
    /// Seen by a member: the room host.
    Host,
}

pub struct PendingInvite {
    pub room_id: RoomId,
    pub expires: Instant,
}

pub struct Room {
    pub id: RoomId,
    pub cfg: RoomConfig,
    pub me: Arc<Identity>,
    pub host: MemberInfo,
    pub members: Vec<MemberInfo>,
    pub keys: HashMap<u32, RoomKey>,
    pub epoch: u32,
    pub chain: Chain,
    pub lines: Vec<ChatLine>,
    pub role: Role,
    pub last_hb: Instant,
}

impl Drop for Room {
    fn drop(&mut self) {
        for l in &mut self.lines {
            l.text.zeroize();
            l.from.zeroize();
        }
    }
}

impl Room {
    pub fn is_host(&self) -> bool {
        matches!(self.role, Role::Host { .. })
    }

    pub fn summary(&self) -> RoomSummary {
        RoomSummary {
            room_id: room_id_hex(&self.id),
            name: self.cfg.name.clone(),
            kill_mode: self.cfg.kill_mode,
            grace_secs: self.cfg.grace_secs,
            is_dm: self.cfg.is_dm,
            is_host: self.is_host(),
            alias: self.me.name.clone(),
            host_fp: self.host.id.fingerprint(),
            members: self.members.iter().map(|m| m.name.clone()).collect(),
        }
    }

    fn name_of(&self, pk: &[u8; 32]) -> Option<String> {
        self.members.iter().find(|m| &m.id.sign_pk == pk).map(|m| m.name.clone())
    }

    fn push(&mut self, ev: &Events, line: ChatLine) {
        if self.lines.len() >= MAX_LINES {
            let mut old = self.lines.remove(0);
            old.text.zeroize();
        }
        self.lines.push(line.clone());
        let _ = ev.send(IpcEvent::Line { room_id: room_id_hex(&self.id), line });
    }

    pub fn system(&mut self, ev: &Events, text: impl Into<String>) {
        let line = ChatLine {
            from: "*".into(),
            text: text.into(),
            ts_min: commx_core::now_minute(),
            mine: false,
            system: true,
        };
        self.push(ev, line);
    }

    /// Send to every connection of this room (host: all members; member: host).
    pub fn send_all(&self, msg: &WireMsg) {
        match &self.role {
            Role::Host { peers } => peers.values().for_each(|p| p.send(msg.clone())),
            Role::Member { host } => host.send(msg.clone()),
        }
    }

    pub fn touch(&mut self, kind: PeerKind) {
        match (&mut self.role, kind) {
            (Role::Host { peers }, PeerKind::Member(pk)) => {
                if let Some(p) = peers.get_mut(&pk) {
                    p.last_seen = Instant::now();
                }
            }
            (Role::Member { host }, PeerKind::Host) => host.last_seen = Instant::now(),
            _ => {}
        }
    }

    fn set_key(&mut self, epoch: u32, key: RoomKey) {
        self.keys.insert(epoch, key);
        self.epoch = epoch;
        // Keep the previous epoch for in-flight messages; drop the rest.
        self.keys.retain(|e, _| *e + 1 >= epoch);
    }

    fn decrypt_msg(&self, p: &Payload) -> Result<String> {
        let Body::Msg { nonce, ct } = &p.body else { bail!("not a message") };
        let key = self.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch {}", p.epoch))?;
        let plain = key.decrypt(nonce, ct, &msg_aad(&self.id, p.epoch, &p.author))?;
        let msg: ChatPlain = postcard::from_bytes(&plain)?;
        Ok(msg.text)
    }

    /// Interpret a block that's already part of the chain.
    fn apply_block(&mut self, ev: &Events, block: &Block) -> Result<()> {
        let p = &block.payload;
        let mine = p.author == self.me.public().sign_pk;
        let from_host = p.author == self.host.id.sign_pk;
        match &p.body {
            Body::Msg { .. } => {
                let from = self.name_of(&p.author).ok_or_else(|| anyhow!("message from non-member"))?;
                let text = self.decrypt_msg(p)?;
                self.push(ev, ChatLine { from, text, ts_min: p.ts_min, mine, system: false });
            }
            Body::KeyRotate { new_epoch, sealed } => {
                if !from_host {
                    bail!("key rotation not from host");
                }
                if !mine {
                    let me_pk = self.me.public().sign_pk;
                    let (_, s) = sealed
                        .iter()
                        .find(|(pk, _)| *pk == me_pk)
                        .ok_or_else(|| anyhow!("excluded from key rotation"))?;
                    let key = RoomKey::from_bytes(&open_sealed(&self.me, s)?)?;
                    self.set_key(*new_epoch, key);
                }
                self.system(ev, format!("room key rotated (epoch {new_epoch})"));
            }
            Body::Join { member } => {
                if !from_host {
                    bail!("join not from host");
                }
                if !self.members.iter().any(|m| m.id == member.id) {
                    self.members.push(member.clone());
                }
                self.system(ev, format!("{} joined [{}]", member.name, member.id.fingerprint()));
                let _ = ev.send(IpcEvent::Room { room: self.summary() });
            }
            Body::Leave { sign_pk } => {
                if !from_host {
                    bail!("leave not from host");
                }
                let name = self.name_of(sign_pk).unwrap_or_else(|| "?".into());
                self.members.retain(|m| &m.id.sign_pk != sign_pk);
                self.system(ev, format!("{name} dropped"));
                let _ = ev.send(IpcEvent::Room { room: self.summary() });
            }
        }
        Ok(())
    }

    /// Host: sequence a payload, fan it out, show it locally.
    fn publish(&mut self, ev: &Events, payload: Payload) -> Result<()> {
        let block = self.chain.append(&self.me, payload);
        self.send_all(&WireMsg::Block(block.clone()));
        self.apply_block(ev, &block)
    }

    pub fn host_body(&mut self, ev: &Events, body: Body) -> Result<()> {
        let payload = Payload::new(&self.me, self.id, self.epoch, body);
        self.publish(ev, payload)
    }

    /// Host: new room key for whoever is still here.
    pub fn rotate_key(&mut self, ev: &Events) -> Result<()> {
        let key = RoomKey::generate();
        let new_epoch = self.epoch + 1;
        let me_pk = self.me.public().sign_pk;
        let sealed = self
            .members
            .iter()
            .filter(|m| m.id.sign_pk != me_pk)
            .map(|m| Ok((m.id.sign_pk, seal_to(&m.id.dh_pk, key.as_bytes())?)))
            .collect::<Result<Vec<_>>>()?;
        self.host_body(ev, Body::KeyRotate { new_epoch, sealed })?;
        self.set_key(new_epoch, key);
        Ok(())
    }

    /// Host: a member asked us to sequence their message.
    pub fn host_submit(&mut self, ev: &Events, from: [u8; 32], payload: Payload) {
        let ok = payload.room_id == self.id
            && payload.author == from
            && matches!(payload.body, Body::Msg { .. })
            && payload.verify_author()
            // Refuse anything members couldn't decrypt, so one bad member
            // can't trip everyone's integrity check.
            && self.decrypt_msg(&payload).is_ok();
        if ok {
            let _ = self.publish(ev, payload);
        }
    }

    /// Member: a block from the host. Any error means nuke.
    pub fn member_block(&mut self, ev: &Events, block: &Block) -> Result<()> {
        self.chain.verify_append(block)?;
        self.apply_block(ev, block)
    }

    pub fn send_text(&mut self, ev: &Events, text: &str) -> Result<()> {
        if text.trim().is_empty() {
            bail!("empty message");
        }
        if text.len() > MAX_TEXT_LEN {
            bail!("message too long (max {MAX_TEXT_LEN} bytes)");
        }
        let plain = postcard::to_allocvec(&ChatPlain { text: text.to_string() })?;
        let key = self.keys.get(&self.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let me_pk = self.me.public().sign_pk;
        let (nonce, ct) = key.encrypt(&plain, &msg_aad(&self.id, self.epoch, &me_pk))?;
        let payload = Payload::new(&self.me, self.id, self.epoch, Body::Msg { nonce, ct });
        match &self.role {
            Role::Host { .. } => self.publish(ev, payload),
            // Shown when the host's block comes back, so everyone sees one order.
            Role::Member { host } => {
                host.send(WireMsg::Submit(payload));
                Ok(())
            }
        }
    }
}

pub struct Daemon {
    pub data_dir: PathBuf,
    pub advertise: String,
    pub aliases: Vec<AliasEntry>,
    pub active: Option<usize>,
    pub rooms: HashMap<RoomId, Room>,
    pub invites: HashMap<[u8; 16], PendingInvite>,
    pub events: Events,
    pub power: Power,
}

impl Daemon {
    pub fn new(data_dir: PathBuf, advertise: String, keep_awake: bool) -> Self {
        Self {
            data_dir,
            advertise,
            aliases: Vec::new(),
            active: None,
            rooms: HashMap::new(),
            invites: HashMap::new(),
            events: broadcast::channel(1024).0,
            power: Power::new(keep_awake),
        }
    }

    pub fn emit(&self, ev: IpcEvent) {
        let _ = self.events.send(ev);
    }

    pub fn active_identity(&self) -> Result<Arc<Identity>> {
        self.active
            .and_then(|i| self.aliases.get(i))
            .map(|a| a.id.clone())
            .ok_or_else(|| anyhow!("no active alias: /alias new <name> or /unlock"))
    }

    pub fn alias_list(&self) -> IpcEvent {
        IpcEvent::Aliases {
            list: self
                .aliases
                .iter()
                .enumerate()
                .map(|(i, a)| AliasInfo {
                    name: a.id.name.clone(),
                    fingerprint: a.id.fingerprint(),
                    ephemeral: a.ephemeral,
                    active: self.active == Some(i),
                })
                .collect(),
        }
    }

    pub fn add_alias(&mut self, id: Identity, ephemeral: bool) -> bool {
        if self.aliases.iter().any(|a| a.id.public() == id.public()) {
            return false;
        }
        self.aliases.push(AliasEntry { id: Arc::new(id), ephemeral });
        if self.active.is_none() {
            self.active = Some(self.aliases.len() - 1);
        }
        true
    }

    pub fn status(&mut self) -> IpcEvent {
        let id = self.active_identity().ok();
        IpcEvent::Status {
            alias: id.as_ref().map(|i| i.name.clone()),
            fingerprint: id.as_ref().map(|i| i.fingerprint()),
            listen: self.advertise.clone(),
            power: self.power.label(),
            rooms: self.rooms.values().map(Room::summary).collect(),
        }
    }

    pub fn refresh_power(&mut self) {
        let active = !self.rooms.is_empty();
        self.power.set_active(active);
    }

    pub fn create_room(&mut self, name: &str, kill_mode: KillMode, grace_secs: u64, dm: bool) -> Result<RoomId> {
        let me = self.active_identity()?;
        let name = name.trim();
        if name.is_empty() || name.len() > 48 {
            bail!("room name must be 1-48 chars");
        }
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let host = MemberInfo { name: me.name.clone(), id: me.public() };
        let mut room = Room {
            id,
            cfg: RoomConfig {
                name: name.to_string(),
                kill_mode: if dm { KillMode::AnyMember } else { kill_mode },
                grace_secs: grace_secs.max(MIN_GRACE_SECS),
                is_dm: dm,
            },
            chain: Chain::genesis(id, host.id.sign_pk),
            me,
            members: vec![host.clone()],
            host,
            keys: HashMap::new(),
            epoch: 0,
            lines: Vec::new(),
            role: Role::Host { peers: HashMap::new() },
            last_hb: Instant::now(),
        };
        room.keys.insert(0, RoomKey::generate());
        let ev = self.events.clone();
        room.system(
            &ev,
            format!(
                "{} created · kill switch: {} · grace {}s",
                if dm { "DM" } else { "room" },
                room.cfg.kill_mode.label(),
                room.cfg.grace_secs
            ),
        );
        self.emit(IpcEvent::Room { room: room.summary() });
        self.rooms.insert(id, room);
        self.refresh_power();
        Ok(id)
    }

    pub fn make_invite(&mut self, room_id: &RoomId) -> Result<String> {
        let room = self.rooms.get(room_id).ok_or_else(|| anyhow!("no such room"))?;
        let Role::Host { peers } = &room.role else {
            bail!("only the room host can invite");
        };
        if room.cfg.is_dm && !peers.is_empty() {
            bail!("DM is full");
        }
        let mut token = [0u8; 16];
        OsRng.fill_bytes(&mut token);
        let invite = Invite { addr: self.advertise.clone(), host: room.host.id, room_id: *room_id, token };
        self.invites.insert(token, PendingInvite { room_id: *room_id, expires: Instant::now() + INVITE_TTL });
        Ok(invite.encode())
    }

    /// Host side of a join. On success the JoinOk is already queued on `peer`.
    pub fn admit(
        &mut self,
        room_id: RoomId,
        token: [u8; 16],
        member: MemberInfo,
        sig: &[u8],
        handshake_hash: &[u8],
        peer: Peer,
    ) -> std::result::Result<(), String> {
        let deny = |s: &str| Err(s.to_string());
        let invite_ok = self
            .invites
            .remove(&token)
            .is_some_and(|i| i.room_id == room_id && i.expires > Instant::now());
        if !invite_ok {
            return deny("invite invalid, used or expired");
        }
        if !verify(&member.id.sign_pk, &channel_binding(handshake_hash, "member"), sig) {
            return deny("bad identity proof");
        }
        if member.name.trim().is_empty() || member.name.len() > 32 {
            return deny("bad alias name");
        }
        let ev = self.events.clone();
        let Some(room) = self.rooms.get_mut(&room_id) else {
            return deny("room is gone");
        };
        let Role::Host { peers } = &room.role else {
            return deny("not hosted here");
        };
        if room.cfg.is_dm && !peers.is_empty() {
            return deny("DM is full");
        }
        if room.members.iter().any(|m| m.id == member.id) {
            return deny("already a member");
        }
        let sealed_key = match seal_to(&member.id.dh_pk, room.keys[&room.epoch].as_bytes()) {
            Ok(s) => s,
            Err(_) => return deny("internal error"),
        };
        if room.host_body(&ev, Body::Join { member: member.clone() }).is_err() {
            return deny("internal error");
        }
        peer.send(WireMsg::JoinOk {
            cfg: room.cfg.clone(),
            host: room.host.clone(),
            host_sig: room.me.sign(&channel_binding(handshake_hash, "host")),
            epoch: room.epoch,
            sealed_key,
            members: room.members.clone(),
            next_seq: room.chain.next_seq,
            head: room.chain.head,
        });
        if let Role::Host { peers } = &mut room.role {
            peers.insert(member.id.sign_pk, peer);
        }
        Ok(())
    }
}
