//! Daemon state: aliases, live rooms and their peers. Everything here lives in
//! RAM only. Locked with a std mutex and never held across an await.

use anyhow::{anyhow, bail, Result};
use commx_core::chain::{msg_aad, Block, Body, Chain, ChatPlain, FileMeta, Payload};
use commx_core::crypto::{aead_decrypt, aead_encrypt, open_sealed, seal_to, RoomKey};
use commx_core::secmem::{Locked, SealedLog};
use commx_core::identity::{verify, Identity};
use commx_core::invite::Invite;
use commx_core::ipc::{AliasInfo, ChatLine, FileInfo, IpcEvent, RoomSummary};
use commx_core::room::{KillMode, MemberInfo, RoomConfig, MIN_GRACE_SECS};
use commx_core::text::{clean, valid_name};
use commx_core::wire::{channel_binding, WireMsg};
use commx_core::{room_id_hex, RoomId, MAX_TEXT_LEN};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::call::Call;
use crate::files::{BlobReader, FileEntry};
use crate::power::Power;
use crate::transport::Net;
use crate::udp::{Outbox, UdpPath};

pub type Shared = Arc<Mutex<Daemon>>;

/// Broadcast of events to every connected client. Events sit in the ring
/// buffer until overwritten, so they're stored sealed under a locked key and
/// only decrypted by each client's writer right before hitting the socket.
#[derive(Clone)]
pub struct Events {
    tx: broadcast::Sender<Arc<([u8; 24], Vec<u8>)>>,
    key: Arc<Locked<32>>,
}

pub struct EventSub {
    rx: broadcast::Receiver<Arc<([u8; 24], Vec<u8>)>>,
    key: Arc<Locked<32>>,
}

impl Events {
    pub fn new() -> Self {
        Self { tx: broadcast::channel(1024).0, key: Arc::new(Locked::random()) }
    }

    pub fn send(&self, ev: IpcEvent) {
        let json = Zeroizing::new(serde_json::to_vec(&ev).expect("serialize event"));
        if let Ok(sealed) = aead_encrypt(self.key.bytes(), &json, b"commx-ipc") {
            let _ = self.tx.send(Arc::new(sealed));
        }
    }

    pub fn subscribe(&self) -> EventSub {
        EventSub { rx: self.tx.subscribe(), key: self.key.clone() }
    }
}

impl EventSub {
    /// Next event as JSON bytes. `None` when the daemon is shutting down.
    pub async fn recv(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        loop {
            match self.rx.recv().await {
                Ok(s) => {
                    if let Ok(plain) = aead_decrypt(self.key.bytes(), &s.0, &s.1, b"commx-ipc") {
                        return Some(plain);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

pub const INVITE_TTL: Duration = Duration::from_secs(10 * 60);
pub const MAX_LINES: usize = 500;

pub fn human_size(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GiB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KiB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

fn file_meta_aad(room_id: &RoomId, epoch: u32, author: &[u8; 32], file_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = msg_aad(room_id, epoch, author);
    aad.extend_from_slice(b"file");
    aad.extend_from_slice(file_id);
    aad
}

pub fn lock(s: &Shared) -> MutexGuard<'_, Daemon> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct AliasEntry {
    pub id: Arc<Identity>,
    pub ephemeral: bool,
}

/// Outbound frames queued per connection before the peer counts as dead.
pub const PEER_QUEUE: usize = 512;
/// File chunks queued per connection (~2 MiB).
pub const BULK_QUEUE: usize = 64;
/// Voice frames queued per connection (~320 ms); late ones are dropped.
pub const MEDIA_QUEUE: usize = 16;
/// Member message rate limit: sustained per second, and burst.
const SUBMIT_RATE: f64 = 5.0;
const SUBMIT_BURST: f64 = 20.0;

/// Sending halves of a connection's three priority lanes.
pub struct Lanes {
    pub ctl: mpsc::Sender<WireMsg>,
    pub bulk: mpsc::Sender<WireMsg>,
    pub media: mpsc::Sender<WireMsg>,
}

/// One live connection. Dropping it closes the channel: the writer drains and
/// exits, and the dropped cancel sender stops the reader.
pub struct Peer {
    tx: mpsc::Sender<WireMsg>,
    /// File chunks: awaited (backpressure) instead of try_send.
    bulk: mpsc::Sender<WireMsg>,
    /// Voice: try_send, and a full queue just drops the frame (it'd be late).
    media: mpsc::Sender<WireMsg>,
    pub last_seen: Instant,
    overflowed: AtomicBool,
    tokens: f64,
    refilled: Instant,
    /// UDP fast path for voice (direct-TCP mode only).
    pub udp: Option<UdpPath>,
    _cancel: oneshot::Sender<()>,
}

impl Peer {
    pub fn new(lanes: Lanes, cancel: oneshot::Sender<()>, udp: Option<UdpPath>) -> Self {
        let Lanes { ctl: tx, bulk, media } = lanes;
        Self {
            tx,
            bulk,
            media,
            last_seen: Instant::now(),
            overflowed: AtomicBool::new(false),
            tokens: SUBMIT_BURST,
            refilled: Instant::now(),
            udp,
            _cancel: cancel,
        }
    }

    /// Never blocks. A peer that can't keep up is flagged and dropped on the
    /// next tick instead of growing memory without bound.
    pub fn send(&self, msg: WireMsg) {
        if self.tx.try_send(msg).is_err() {
            self.overflowed.store(true, Ordering::Relaxed);
        }
    }

    /// Voice: UDP when that path is live, else the TCP media lane.
    pub fn send_media(&self, msg: WireMsg) {
        if self.udp.as_ref().is_some_and(|u| u.send_voice(&msg)) {
            return;
        }
        let _ = self.media.try_send(msg);
    }

    /// Voice path in use: "udp" when the fast path is live, else "tcp".
    pub fn link(&self) -> &'static str {
        match &self.udp {
            Some(u) if u.fresh() => "udp",
            _ => "tcp",
        }
    }

    pub fn bulk(&self) -> mpsc::Sender<WireMsg> {
        self.bulk.clone()
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Relaxed)
    }

    /// Token bucket for member submissions.
    fn allow_submit(&mut self) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.refilled).as_secs_f64() * SUBMIT_RATE;
        self.tokens = (self.tokens + refill).min(SUBMIT_BURST);
        self.refilled = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
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
    /// History, encrypted in RAM; dropped (key wiped) on nuke.
    pub lines: SealedLog,
    pub role: Role,
    pub last_hb: Instant,
    /// Where invites point (host only).
    pub addr: String,
    /// This room's onion service, taken down on nuke (Tor mode, host only).
    pub onion: Option<String>,
    /// Shared files; dropping an entry wipes its key and unlinks its blob.
    pub files: HashMap<[u8; 16], FileEntry>,
    pub next_file_no: u32,
    pub data_dir: PathBuf,
    /// At most one call per room; dropping it wipes the call key.
    pub call: Option<Call>,
    pub over_tor: bool,
}

/// Work the connection task does after releasing the lock.
#[derive(Default)]
pub struct Followup {
    /// File chunks to relay, awaited one by one (backpressure).
    pub forward: Vec<(mpsc::Sender<WireMsg>, WireMsg)>,
    /// A file finished arriving and needs its hash checked.
    pub verify: Option<(RoomId, [u8; 16], BlobReader)>,
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
            link: match &self.role {
                _ if self.over_tor => "tor".into(),
                Role::Member { host } => host.link().to_string(),
                Role::Host { peers } => {
                    let up = peers.values().filter(|p| p.link() == "udp").count();
                    format!("udp {up}/{}", peers.len())
                }
            },
        }
    }

    fn name_of(&self, pk: &[u8; 32]) -> Option<String> {
        self.members.iter().find(|m| &m.id.sign_pk == pk).map(|m| m.name.clone())
    }

    fn push(&mut self, ev: &Events, line: ChatLine) {
        self.lines.push(&line);
        ev.send(IpcEvent::Line { room_id: room_id_hex(&self.id), line });
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

    /// Host: rate-limit a member's submissions; floods are dropped silently.
    pub fn allow_submit(&mut self, pk: &[u8; 32]) -> bool {
        match &mut self.role {
            Role::Host { peers } => peers.get_mut(pk).is_some_and(Peer::allow_submit),
            Role::Member { .. } => false,
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
                let text = clean(&self.decrypt_msg(p)?);
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
                ev.send(IpcEvent::Room { room: self.summary() });
            }
            Body::File { file_id, nonce, ct } => {
                let from = self.name_of(&p.author).ok_or_else(|| anyhow!("file from non-member"))?;
                let meta = self.open_file_meta(p, file_id, nonce, ct)?;
                if self.files.contains_key(file_id) {
                    bail!("duplicate file id");
                }
                self.next_file_no += 1;
                let no = self.next_file_no;
                let entry = if mine {
                    FileEntry::outgoing(no, *file_id, p.author, from.clone(), &meta)
                } else {
                    FileEntry::incoming(no, *file_id, p.author, from.clone(), &meta, &self.data_dir)
                };
                let size = human_size(meta.size);
                let name = entry.name.clone();
                self.files.insert(*file_id, entry);
                self.system(ev, format!("📎 {from} is sharing #{no} '{name}' ({size})"));
            }
            Body::Call { call_id, nonce, ct } => self.apply_call(ev, p, call_id, nonce, ct)?,
            Body::Leave { sign_pk } => {
                if !from_host {
                    bail!("leave not from host");
                }
                let name = self.name_of(sign_pk).unwrap_or_else(|| "?".into());
                self.members.retain(|m| &m.id.sign_pk != sign_pk);
                self.system(ev, format!("{name} dropped"));
                ev.send(IpcEvent::Room { room: self.summary() });
            }
        }
        Ok(())
    }

    /// Host: sequence a payload, fan it out, show it locally.
    pub fn publish(&mut self, ev: &Events, payload: Payload) -> Result<()> {
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
            && payload.verify_author()
            // Refuse anything members couldn't decrypt, so one bad member
            // can't trip everyone's integrity check.
            && match &payload.body {
                Body::Msg { .. } => self.decrypt_msg(&payload).is_ok(),
                Body::File { file_id, nonce, ct } => {
                    !self.files.contains_key(file_id) && self.open_file_meta(&payload, file_id, nonce, ct).is_ok()
                }
                Body::Call { call_id, nonce, ct } => self.open_call_meta(&payload, call_id, nonce, ct).is_ok(),
                _ => false,
            };
        if ok {
            let _ = self.publish(ev, payload);
        }
    }

    fn open_file_meta(&self, p: &Payload, file_id: &[u8; 16], nonce: &[u8; 24], ct: &[u8]) -> Result<FileMeta> {
        let key = self.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch {}", p.epoch))?;
        let plain = key.decrypt(nonce, ct, &file_meta_aad(&self.id, p.epoch, &p.author, file_id))?;
        let mut meta: FileMeta = postcard::from_bytes(&plain)?;
        if !meta.is_consistent() {
            bail!("bad file metadata");
        }
        meta.name = clean(&meta.name);
        Ok(meta)
    }

    /// Announce a file through the chain. Returns where its chunks must go.
    pub fn announce_file(
        &mut self,
        ev: &Events,
        file_id: [u8; 16],
        meta: &FileMeta,
    ) -> Result<Vec<mpsc::Sender<WireMsg>>> {
        let key = self.keys.get(&self.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let me_pk = self.me.public().sign_pk;
        let plain = Zeroizing::new(postcard::to_allocvec(meta)?);
        let (nonce, ct) = key.encrypt(&plain, &file_meta_aad(&self.id, self.epoch, &me_pk, &file_id))?;
        let payload = Payload::new(&self.me, self.id, self.epoch, Body::File { file_id, nonce, ct });
        match &self.role {
            Role::Host { peers } => {
                let targets = peers.values().map(Peer::bulk).collect();
                self.publish(ev, payload)?;
                Ok(targets)
            }
            Role::Member { host } => {
                host.send(WireMsg::Submit(payload));
                Ok(vec![host.bulk()])
            }
        }
    }

    /// A file chunk arrived on one of this room's connections.
    pub fn on_chunk(&mut self, kind: PeerKind, msg: WireMsg) -> Followup {
        let mut out = Followup::default();
        let WireMsg::FileChunk { file_id, idx, nonce, ct, .. } = &msg else { return out };
        let Some(entry) = self.files.get_mut(file_id) else { return out };
        // Only the announcer may supply chunks; the host only relays.
        let allowed = match kind {
            PeerKind::Member(pk) => entry.author == pk,
            PeerKind::Host => entry.author != self.me.public().sign_pk,
        };
        if !allowed {
            return out;
        }
        if entry.store_chunk(*idx, nonce, ct) {
            out.verify = entry.reader().map(|r| (self.id, *file_id, r));
        }
        if let (Role::Host { peers }, PeerKind::Member(author)) = (&self.role, kind) {
            out.forward = peers.iter().filter(|(pk, _)| **pk != author).map(|(_, p)| (p.bulk(), msg.clone())).collect();
        }
        out
    }

    pub fn file_list(&self) -> Vec<FileInfo> {
        let mut v: Vec<FileInfo> = self.files.values().map(FileEntry::info).collect();
        v.sort_by_key(|f| f.no);
        v
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
    pub net: Arc<Net>,
    pub aliases: Vec<AliasEntry>,
    pub active: Option<usize>,
    pub rooms: HashMap<RoomId, Room>,
    pub invites: HashMap<[u8; 16], PendingInvite>,
    /// UDP path id → which connection it belongs to.
    pub udp_index: HashMap<[u8; 8], (RoomId, PeerKind)>,
    /// Set in direct-TCP mode once the UDP socket is up.
    pub udp_out: Option<Outbox>,
    pub events: Events,
    pub power: Power,
}

impl Daemon {
    pub fn new(data_dir: PathBuf, net: Arc<Net>, keep_awake: bool) -> Self {
        Self {
            data_dir,
            net,
            aliases: Vec::new(),
            active: None,
            rooms: HashMap::new(),
            invites: HashMap::new(),
            udp_index: HashMap::new(),
            udp_out: None,
            events: Events::new(),
            power: Power::new(keep_awake),
        }
    }

    pub fn emit(&self, ev: IpcEvent) {
        self.events.send(ev);
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
            listen: self.net.label(),
            power: self.power.label(),
            rooms: self.rooms.values().map(Room::summary).collect(),
        }
    }

    pub fn refresh_power(&mut self) {
        let active = !self.rooms.is_empty();
        self.power.set_active(active);
    }

    /// `addr`/`onion` come from [`Net::room_endpoint`].
    pub fn create_room(
        &mut self,
        name: &str,
        kill_mode: KillMode,
        grace_secs: u64,
        dm: bool,
        (addr, onion): (String, Option<String>),
    ) -> Result<RoomId> {
        let me = self.active_identity()?;
        let name = name.trim();
        if !valid_name(name, 48) {
            bail!("room name must be 1-48 printable chars");
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
            lines: SealedLog::new(MAX_LINES),
            role: Role::Host { peers: HashMap::new() },
            last_hb: Instant::now(),
            addr,
            onion,
            files: HashMap::new(),
            next_file_no: 0,
            call: None,
            data_dir: self.data_dir.clone(),
            over_tor: self.net.is_tor(),
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
        let invite = Invite { addr: room.addr.clone(), host: room.host.id, room_id: *room_id, token };
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
        if !valid_name(&member.name, 32) || member.name.contains(char::is_whitespace) {
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
        // Names are display-only, but duplicates make impersonation trivial.
        if room.members.iter().any(|m| m.name.eq_ignore_ascii_case(&member.name)) {
            return deny("that alias name is taken in this room");
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
