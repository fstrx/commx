//! A room member with no I/O of its own: feed it the bytes that arrive from
//! the host, send the bytes it hands back. The browser wires this to a
//! WebSocket; tests wire it to a TCP socket. Same wire protocol as the apps
//! (length-prefixed Noise_XX frames), same chain verification, same crypto.

use anyhow::{anyhow, bail, Context, Result};
use commx_core::chain::{call_meta_aad, file_meta_aad, msg_aad, Block, Body, Chain, ChatPlain, FileMeta, Payload};
use commx_core::crypto::{open_sealed, RoomKey};
use commx_core::voice::{open_frame, seal_frame, CallMeta};
use rand::{rngs::OsRng, RngCore};
use std::collections::VecDeque;

use crate::media::{FileState, Outgoing, SealedChunk, VoiceOut, WebCall, WebFile, MAX_HELD_BYTES};
use commx_core::identity::{verify, Identity};
use commx_core::invite::{password_key, password_proof, Invite};
use commx_core::room::{KillMode, MemberInfo, RoomConfig};
use commx_core::text::{clean, safe_file_name, valid_name};
use commx_core::wire::{self, channel_binding, verify_nuke, WireMsg};
use commx_core::MAX_TEXT_LEN;
use serde_json::{json, Value};
use std::collections::HashMap;
use zeroize::Zeroizing;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME: usize = 65535;
const TAG: usize = 16;

/// UI events, as JSON objects (`{"ev": ...}`).
pub type Event = Value;

enum Stage {
    /// Waiting for the responder's `e, ee, s, es`.
    Handshake(Box<snow::HandshakeState>),
    /// Password invite: JoinHello sent, waiting for the host to prove itself.
    HostCheck(Box<Transport>),
    /// Channel up, JoinReq sent, waiting for JoinOk.
    Joining(Box<Transport>),
    Room(Box<Transport>, Box<RoomState>),
    Dead,
}

struct Transport {
    noise: snow::StatelessTransportState,
    tx_nonce: u64,
    rx_nonce: u64,
    hash: Vec<u8>,
}

impl Transport {
    fn seal(&mut self, msg: &WireMsg) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(wire::encode(msg));
        if plain.len() > MAX_FRAME - TAG {
            bail!("message too large");
        }
        let mut out = vec![0u8; plain.len() + TAG];
        let n = self.noise.write_message(self.tx_nonce, &plain, &mut out)?;
        self.tx_nonce += 1;
        Ok(frame(&out[..n]))
    }

    fn open(&mut self, f: &[u8]) -> Result<WireMsg> {
        let mut plain = Zeroizing::new(vec![0u8; f.len()]);
        let n = self.noise.read_message(self.rx_nonce, f, &mut plain)?;
        self.rx_nonce += 1;
        wire::decode(&plain[..n])
    }
}

struct RoomState {
    cfg: RoomConfig,
    host: MemberInfo,
    members: Vec<MemberInfo>,
    keys: HashMap<u32, RoomKey>,
    epoch: u32,
    chain: Chain,
    files: HashMap<[u8; 16], WebFile>,
    next_file_no: u32,
    uploads: VecDeque<Outgoing>,
    call: Option<WebCall>,
    /// Our sealed voice frames waiting for the socket; the oldest are
    /// dropped when it can't keep up (late audio is useless).
    voice_tx: VecDeque<WireMsg>,
}

/// Voice frames queued before the oldest is dropped (~100 ms).
const VOICE_QUEUE: usize = 5;

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + bytes.len());
    v.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    v.extend_from_slice(bytes);
    v
}

pub struct Member {
    me: Identity,
    invite: Invite,
    /// `cx2:` invites: Argon2id of the password, used only after HostProof.
    pw_key: Option<Zeroizing<[u8; 32]>>,
    stage: Stage,
    rx: Vec<u8>,
    out: Vec<u8>,
    events: Vec<Event>,
    voice_in: VoiceOut,
    /// Separate from `stage`, which is temporarily swapped out while a frame
    /// is being handled.
    alive: bool,
}

impl Member {
    /// Parse the invite, make a fresh RAM-only alias, and queue the first
    /// handshake message. Nothing is ever stored.
    pub fn new(invite_code: &str, alias: &str, password: Option<&str>) -> Result<Self> {
        let alias = alias.trim();
        if !valid_name(alias, 32) || alias.contains(char::is_whitespace) {
            bail!("alias must be 1-32 printable chars, no spaces");
        }
        let invite = Invite::decode(invite_code)?;
        let pw_key = match (invite.password, password) {
            (false, _) => None,
            (true, None | Some("")) => bail!("this invite needs a password"),
            (true, Some(pw)) => Some(password_key(pw, &invite.room_id, &invite.token)?),
        };
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse()?;
        let kp = snow::Builder::new(params.clone()).generate_keypair()?;
        let private = Zeroizing::new(kp.private);
        let mut hs = snow::Builder::new(params).local_private_key(&private).build_initiator()?;
        let mut buf = vec![0u8; MAX_FRAME];
        let n = hs.write_message(&[], &mut buf)?;
        let mut m = Self {
            me: Identity::generate(alias),
            invite,
            pw_key,
            stage: Stage::Handshake(Box::new(hs)),
            rx: Vec::new(),
            out: frame(&buf[..n]),
            events: Vec::new(),
            voice_in: VoiceOut::default(),
            alive: true,
        };
        m.event(json!({"ev": "status", "text": "connecting…"}));
        Ok(m)
    }

    pub fn fingerprint(&self) -> String {
        self.me.fingerprint()
    }

    /// Bytes to send to the host (drains the queue), everything included.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        self.take(true, usize::MAX)
    }

    /// Bytes to send: control frames always; queued voice if `media`; file
    /// chunks up to about `bulk_budget` bytes. Frames are sealed here, in the
    /// order they're returned, because Noise nonces must arrive in sequence.
    pub fn take(&mut self, media: bool, bulk_budget: usize) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.out);
        if let Stage::Room(t, room) = &mut self.stage {
            if media {
                while let Some(m) = room.voice_tx.pop_front() {
                    if let Ok(b) = t.seal(&m) {
                        out.extend(b);
                    }
                }
            }
            let start = out.len();
            let room_id = room.chain.room_id;
            while out.len() - start < bulk_budget {
                let Some(up) = room.uploads.front_mut() else { break };
                // Chunks follow the host's sequenced announcement, never precede it.
                if !room.files.contains_key(&up.file_id) {
                    break;
                }
                match up.next_chunk() {
                    Ok(Some(SealedChunk { idx, nonce, ct })) => {
                        let file_id = up.file_id;
                        if let Ok(b) = t.seal(&WireMsg::FileChunk { room_id, file_id, idx, nonce, ct }) {
                            out.extend(b);
                        }
                        if let Some(f) = room.files.get_mut(&file_id) {
                            f.got = idx + 1;
                        }
                    }
                    _ => {
                        let done = room.uploads.pop_front().map(|u| u.file_id);
                        if let Some(f) = done.and_then(|id| room.files.get_mut(&id)) {
                            f.state = FileState::Sent;
                            let line = format!("📎 #{} sent", f.no);
                            self.events.push(system_line(line));
                        }
                        self.events.push(files_event(room));
                    }
                }
            }
        }
        out
    }

    /// File chunks still waiting to be sent?
    pub fn bulk_pending(&self) -> bool {
        matches!(&self.stage, Stage::Room(_, room) if !room.uploads.is_empty())
    }

    /// Voice frames for the page to decode (see `media::VoiceOut`).
    pub fn take_voice(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.voice_in.0)
    }

    /// Events for the UI (drains the queue).
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    pub fn is_dead(&self) -> bool {
        !self.alive
    }

    fn event(&mut self, e: Event) {
        self.events.push(e);
    }

    fn die(&mut self, reason: &str) {
        self.stage = Stage::Dead; // drops (and wipes) room keys
        if self.alive {
            self.alive = false;
            self.event(json!({"ev": "nuked", "reason": reason}));
        }
    }

    /// The connection to the host closed: for a member that's a host drop.
    pub fn on_close(&mut self) {
        self.die("host dropped (connection lost)");
    }

    /// Bytes from the host. Never panics on hostile input; any protocol or
    /// integrity failure ends the room.
    pub fn on_bytes(&mut self, data: &[u8]) {
        if self.is_dead() {
            return;
        }
        self.rx.extend_from_slice(data);
        loop {
            if self.rx.len() < 4 {
                return;
            }
            let len = u32::from_be_bytes(self.rx[..4].try_into().unwrap()) as usize;
            if len > MAX_FRAME {
                return self.die("protocol error: oversized frame");
            }
            if self.rx.len() < 4 + len {
                return;
            }
            let f: Vec<u8> = self.rx.drain(..4 + len).skip(4).collect();
            if let Err(e) = self.on_frame(&f) {
                return self.die(&format!("integrity failure: {e}"));
            }
            if self.is_dead() {
                return;
            }
        }
    }

    fn on_frame(&mut self, f: &[u8]) -> Result<()> {
        match std::mem::replace(&mut self.stage, Stage::Dead) {
            Stage::Handshake(mut hs) => {
                let mut buf = vec![0u8; MAX_FRAME];
                hs.read_message(f, &mut buf).context("handshake")?;
                let n = hs.write_message(&[], &mut buf)?;
                self.out.extend(frame(&buf[..n]));
                let hash = hs.get_handshake_hash().to_vec();
                let noise = hs.into_stateless_transport_mode()?;
                let mut t = Transport { noise, tx_nonce: 0, rx_nonce: 0, hash };
                if self.pw_key.is_some() {
                    // Nothing derived from the password goes out until the
                    // host proves itself on this channel.
                    let hello = WireMsg::JoinHello { room_id: self.invite.room_id, token: self.invite.token };
                    self.out.extend(t.seal(&hello)?);
                    self.event(json!({"ev": "status", "text": "checking host…"}));
                    self.stage = Stage::HostCheck(Box::new(t));
                } else {
                    self.send_join(t)?;
                }
            }
            Stage::HostCheck(mut t) => match t.open(f)? {
                WireMsg::HostProof { host, sig } => {
                    if host.id != self.invite.host || !verify(&host.id.sign_pk, &channel_binding(&t.hash, "host"), &sig) {
                        bail!("host failed identity proof");
                    }
                    self.send_join(*t)?;
                }
                WireMsg::JoinDenied { reason } => {
                    self.event(json!({"ev": "error", "msg": format!("join denied: {}", clean(&reason))}));
                    self.alive = false;
                }
                _ => bail!("unexpected reply from host"),
            },
            Stage::Joining(mut t) => match t.open(f)? {
                WireMsg::JoinOk { cfg, host, host_sig, epoch, sealed_key, members, next_seq, head } => {
                    // The invite pins the host's keys; the signature pins them to this channel.
                    if host.id != self.invite.host {
                        bail!("host identity doesn't match the invite");
                    }
                    if !verify(&host.id.sign_pk, &channel_binding(&t.hash, "host"), &host_sig) {
                        bail!("host failed identity proof");
                    }
                    let key = RoomKey::from_bytes(&open_sealed(&self.me, &sealed_key).map_err(|_| anyhow!("can't open room key"))?)?;
                    let mut cfg = cfg;
                    cfg.name = clean(&cfg.name);
                    let host = MemberInfo { name: clean(&host.name), id: host.id };
                    let members: Vec<MemberInfo> =
                        members.into_iter().map(|m| MemberInfo { name: clean(&m.name), id: m.id }).collect();
                    let room = RoomState {
                        chain: Chain::resume(self.invite.room_id, host.id.sign_pk, next_seq, head),
                        keys: HashMap::from([(epoch, key)]),
                        epoch,
                        cfg,
                        host,
                        members,
                        files: HashMap::new(),
                        next_file_no: 0,
                        uploads: VecDeque::new(),
                        call: None,
                        voice_tx: VecDeque::new(),
                    };
                    self.event(json!({
                        "ev": "joined",
                        "name": room.cfg.name,
                        "kill_mode": if room.cfg.kill_mode == KillMode::AnyMember { "any-member" } else { "host-only" },
                        "grace_secs": room.cfg.grace_secs,
                        "is_dm": room.cfg.is_dm,
                        "host": room.host.name,
                        "host_fp": room.host.id.fingerprint(),
                        "me": self.me.name,
                        "fp": self.me.fingerprint(),
                    }));
                    self.emit_members(&room);
                    self.stage = Stage::Room(t, Box::new(room));
                }
                WireMsg::JoinDenied { reason } => {
                    self.event(json!({"ev": "error", "msg": format!("join denied: {}", clean(&reason))}));
                    self.alive = false;
                }
                _ => bail!("unexpected reply from host"),
            },
            Stage::Room(mut t, mut room) => {
                match t.open(f)? {
                    WireMsg::Block(b) => self.apply_block(&mut room, &b)?,
                    // Liveness is event-driven: answer the host's heartbeat
                    // instead of relying on timers, which browsers throttle
                    // in background tabs.
                    WireMsg::Heartbeat => self.out.extend(t.seal(&WireMsg::Heartbeat)?),
                    WireMsg::Nuke { room_id, sig } => {
                        if room_id == self.invite.room_id && verify_nuke(&room.chain.host_pk, &room_id, &sig) {
                            self.die("host nuked the room");
                            return Ok(());
                        }
                    }
                    WireMsg::FileChunk { file_id, idx, nonce, ct, .. } => {
                        let me = self.me.public().sign_pk;
                        if let Some(f) = room.files.get_mut(&file_id).filter(|f| f.author != me) {
                            let changed = f.store_chunk(&file_id, idx, &nonce, &ct);
                            if changed || f.got % 32 == 0 {
                                if changed {
                                    let line = match &f.state {
                                        FileState::Ready => format!("📎 #{} '{}' ready to save", f.no, f.name),
                                        s => format!("📎 #{} {}", f.no, s.label(f.got, f.chunks)),
                                    };
                                    self.event(system_line(line));
                                }
                                self.event(files_event(&room));
                            }
                        }
                    }
                    WireMsg::CallPresence { call_id, member, joined, .. } => {
                        let name = Self::name_of(&room, &member).unwrap_or_else(|| "?".into());
                        if let Some(c) = room.call.as_mut().filter(|c| c.id == call_id) {
                            if c.set(member, joined) {
                                if c.participants.is_empty() {
                                    room.call = None;
                                    self.system("📞 call ended".into());
                                } else {
                                    self.system(format!("📞 {name} {} the call", if joined { "joined" } else { "left" }));
                                }
                                self.emit_call(&room);
                            }
                        }
                    }
                    WireMsg::Voice { call_id, from, seq, nonce, ct, .. } => {
                        let me = self.me.public().sign_pk;
                        let room_id = room.chain.room_id;
                        if let Some(c) = room.call.as_mut().filter(|c| c.id == call_id && c.has(&from) && c.has(&me)) {
                            if c.replay.entry(from).or_default().accept(seq) {
                                if let Ok(opus) = open_frame(&c.key, &room_id, &call_id, &from, seq, &nonce, &ct) {
                                    let name = Self::name_of(&room, &from).unwrap_or_else(|| "?".into());
                                    self.voice_in.push(&name, seq, &opus);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                self.stage = Stage::Room(t, room);
            }
            Stage::Dead => {}
        }
        Ok(())
    }

    /// Send JoinReq (or, for password invites, JoinReqPw) and wait for JoinOk.
    fn send_join(&mut self, mut t: Transport) -> Result<()> {
        let room_id = self.invite.room_id;
        let token = self.invite.token;
        let member = MemberInfo { name: self.me.name.clone(), id: self.me.public() };
        let sig = self.me.sign(&channel_binding(&t.hash, "member"));
        let req = match &self.pw_key {
            None => WireMsg::JoinReq { room_id, token, member, sig },
            Some(k) => WireMsg::JoinReqPw { room_id, token, member, sig, proof: password_proof(k, &t.hash) },
        };
        self.out.extend(t.seal(&req)?);
        self.event(json!({"ev": "status", "text": "joining…"}));
        self.stage = Stage::Joining(Box::new(t));
        Ok(())
    }

    fn name_of(room: &RoomState, pk: &[u8; 32]) -> Option<String> {
        room.members.iter().find(|m| &m.id.sign_pk == pk).map(|m| m.name.clone())
    }

    fn system(&mut self, text: String) {
        self.event(system_line(text));
    }

    fn emit_call(&mut self, room: &RoomState) {
        let e = call_event(&self.me.public().sign_pk, room);
        self.event(e);
    }

    fn emit_members(&mut self, room: &RoomState) {
        let names: Vec<&str> = room.members.iter().map(|m| m.name.as_str()).collect();
        self.event(json!({"ev": "members", "members": names}));
    }

    fn apply_block(&mut self, room: &mut RoomState, block: &Block) -> Result<()> {
        room.chain.verify_append(block)?;
        let p: &Payload = &block.payload;
        let from_host = p.author == room.host.id.sign_pk;
        let me_pk = self.me.public().sign_pk;
        match &p.body {
            Body::Msg { nonce, ct } => {
                let from = Self::name_of(room, &p.author).ok_or_else(|| anyhow!("message from non-member"))?;
                let key = room.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch"))?;
                let plain = key.decrypt(nonce, ct, &msg_aad(&room.chain.room_id, p.epoch, &p.author))?;
                let msg: ChatPlain = postcard::from_bytes(&plain)?;
                self.event(json!({
                    "ev": "line", "from": from, "text": clean(&msg.text), "ts_min": p.ts_min,
                    "mine": p.author == me_pk, "system": false,
                }));
            }
            Body::KeyRotate { new_epoch, sealed } => {
                if !from_host {
                    bail!("key rotation not from host");
                }
                let (_, s) = sealed.iter().find(|(pk, _)| *pk == me_pk).ok_or_else(|| anyhow!("excluded from key rotation"))?;
                let key = RoomKey::from_bytes(&open_sealed(&self.me, s)?)?;
                room.keys.insert(*new_epoch, key);
                room.epoch = *new_epoch;
                let e = *new_epoch;
                room.keys.retain(|k, _| k.saturating_add(1) >= e);
                self.system(format!("room key rotated (epoch {new_epoch})"));
            }
            Body::Join { member } => {
                if !from_host {
                    bail!("join not from host");
                }
                let member = MemberInfo { name: clean(&member.name), id: member.id };
                if !room.members.iter().any(|m| m.id == member.id) {
                    room.members.push(member.clone());
                }
                self.system(format!("{} joined [{}]", member.name, member.id.fingerprint()));
                self.emit_members(room);
            }
            Body::Leave { sign_pk } => {
                if !from_host {
                    bail!("leave not from host");
                }
                let name = Self::name_of(room, sign_pk).unwrap_or_else(|| "?".into());
                room.members.retain(|m| &m.id.sign_pk != sign_pk);
                self.system(format!("{name} dropped"));
                self.emit_members(room);
            }
            Body::File { nonce, ct, file_id } => {
                let from = Self::name_of(room, &p.author).ok_or_else(|| anyhow!("file from non-member"))?;
                let key = room.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch"))?;
                let plain = key.decrypt(nonce, ct, &file_meta_aad(&room.chain.room_id, p.epoch, &p.author, file_id))?;
                let mut meta: FileMeta = postcard::from_bytes(&plain)?;
                if !meta.is_consistent() {
                    bail!("bad file metadata");
                }
                if room.files.contains_key(file_id) {
                    bail!("duplicate file id");
                }
                // Peer-chosen; it ends up as a download name. One safe component.
                meta.name = safe_file_name(&meta.name);
                room.next_file_no = room.next_file_no.saturating_add(1);
                let no = room.next_file_no;
                let held: u64 = room.files.values().map(WebFile::held).sum();
                let f = if p.author == me_pk {
                    let mut f = WebFile::incoming(no, p.author, from.clone(), &meta, u64::MAX);
                    f.state = FileState::Sending;
                    f
                } else {
                    WebFile::incoming(no, p.author, from.clone(), &meta, MAX_HELD_BYTES.saturating_sub(held))
                };
                let note = match &f.state {
                    FileState::Failed(why) => format!(" — {why}"),
                    _ => String::new(),
                };
                room.files.insert(*file_id, f);
                self.system(format!("📎 {from} is sharing #{no} '{}' ({}){note}", meta.name, human_size(meta.size)));
                self.event(files_event(room));
            }
            Body::Call { call_id, nonce, ct } => {
                let from = Self::name_of(room, &p.author).ok_or_else(|| anyhow!("call from non-member"))?;
                let key = room.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch"))?;
                let plain = key.decrypt(nonce, ct, &call_meta_aad(&room.chain.room_id, p.epoch, &p.author, call_id))?;
                let meta: CallMeta = postcard::from_bytes(&plain)?;
                room.call = Some(WebCall::new(*call_id, meta.key, p.author));
                let hint = if p.author == me_pk { "you're in" } else { "press Join call" };
                self.system(format!("📞 {from} started a call — {hint}"));
                self.emit_call(room);
            }
        }
        Ok(())
    }

    /// Queue a chat message. It shows up when the host's block comes back,
    /// so everyone sees the same order.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        let text = text.trim();
        if text.is_empty() {
            bail!("empty message");
        }
        if text.len() > MAX_TEXT_LEN {
            bail!("message too long (max {MAX_TEXT_LEN} bytes)");
        }
        let Stage::Room(t, room) = &mut self.stage else { bail!("not in a room") };
        let key = room.keys.get(&room.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let plain = Zeroizing::new(postcard::to_allocvec(&ChatPlain { text: text.to_string() })?);
        let me_pk = self.me.public().sign_pk;
        let (nonce, ct) = key.encrypt(&plain, &msg_aad(&room.chain.room_id, room.epoch, &me_pk))?;
        let payload = Payload::new(&self.me, room.chain.room_id, room.epoch, Body::Msg { nonce, ct });
        let bytes = t.seal(&WireMsg::Submit(payload))?;
        self.out.extend(bytes);
        Ok(())
    }

    /// Share a file with the room. Its chunks go out through `take`.
    pub fn send_file(&mut self, name: &str, data: Vec<u8>) -> Result<()> {
        let Stage::Room(t, room) = &mut self.stage else { bail!("not in a room") };
        let mut file_id = [0u8; 16];
        OsRng.fill_bytes(&mut file_id);
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut key[..]);
        let (meta, up) = Outgoing::prepare(safe_file_name(name), data, file_id, *key)?;
        let rkey = room.keys.get(&room.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let me_pk = self.me.public().sign_pk;
        let plain = Zeroizing::new(postcard::to_allocvec(&meta)?);
        let (nonce, ct) = rkey.encrypt(&plain, &file_meta_aad(&room.chain.room_id, room.epoch, &me_pk, &file_id))?;
        let payload = Payload::new(&self.me, room.chain.room_id, room.epoch, Body::File { file_id, nonce, ct });
        self.out.extend(t.seal(&WireMsg::Submit(payload))?);
        room.uploads.push_back(up);
        Ok(())
    }

    /// Decrypted, hash-verified contents of file `no`, if it's ready.
    pub fn file_bytes(&self, no: u32) -> Option<Vec<u8>> {
        let Stage::Room(_, room) = &self.stage else { return None };
        room.files.values().find(|f| f.no == no).and_then(|f| f.bytes()).map(<[u8]>::to_vec)
    }

    pub fn file_name(&self, no: u32) -> Option<String> {
        let Stage::Room(_, room) = &self.stage else { return None };
        room.files.values().find(|f| f.no == no).map(|f| f.name.clone())
    }

    /// Start a call (we're in it once the host sequences it).
    pub fn start_call(&mut self) -> Result<()> {
        let Stage::Room(t, room) = &mut self.stage else { bail!("not in a room") };
        if room.call.is_some() {
            bail!("a call is already running here");
        }
        let mut call_id = [0u8; 16];
        OsRng.fill_bytes(&mut call_id);
        let mut meta = CallMeta { key: [0; 32] };
        OsRng.fill_bytes(&mut meta.key);
        let key = room.keys.get(&room.epoch).ok_or_else(|| anyhow!("no room key"))?;
        let me_pk = self.me.public().sign_pk;
        let plain = Zeroizing::new(postcard::to_allocvec(&meta)?);
        let (nonce, ct) = key.encrypt(&plain, &call_meta_aad(&room.chain.room_id, room.epoch, &me_pk, &call_id))?;
        let payload = Payload::new(&self.me, room.chain.room_id, room.epoch, Body::Call { call_id, nonce, ct });
        self.out.extend(t.seal(&WireMsg::Submit(payload))?);
        Ok(())
    }

    /// Join (true) or leave (false) the room's running call.
    pub fn set_in_call(&mut self, joined: bool) -> Result<()> {
        let me = self.me.public().sign_pk;
        let Stage::Room(t, room) = &mut self.stage else { bail!("not in a room") };
        let call = room.call.as_mut().ok_or_else(|| anyhow!("no call in this room"))?;
        let msg = WireMsg::CallPresence { room_id: room.chain.room_id, call_id: call.id, member: me, joined };
        self.out.extend(t.seal(&msg)?);
        if call.set(me, joined) {
            if call.participants.is_empty() {
                room.call = None;
            }
            room.voice_tx.clear();
            self.events.push(call_event(&me, room));
        }
        Ok(())
    }

    /// One 20 ms Opus packet from our microphone (silence included).
    pub fn send_voice(&mut self, opus: &[u8]) -> Result<()> {
        let me = self.me.public().sign_pk;
        let Stage::Room(_, room) = &mut self.stage else { return Ok(()) };
        let room_id = room.chain.room_id;
        let Some(call) = room.call.as_mut().filter(|c| c.has(&me)) else { return Ok(()) };
        call.my_seq += 1;
        let seq = call.my_seq;
        let (nonce, ct) = seal_frame(&call.key, &room_id, &call.id, &me, seq, opus)?;
        room.voice_tx.push_back(WireMsg::Voice { room_id, call_id: call.id, from: me, seq, nonce, ct });
        while room.voice_tx.len() > VOICE_QUEUE {
            room.voice_tx.pop_front();
        }
        Ok(())
    }

    /// Leave voluntarily: tell the host, then wipe.
    pub fn leave(&mut self) {
        if let Stage::Room(t, room) = &mut self.stage {
            if let Ok(b) = t.seal(&WireMsg::Leave { room_id: room.chain.room_id }) {
                self.out.extend(b);
            }
        }
        self.die("you left");
    }
}

fn system_line(text: String) -> Event {
    json!({"ev": "line", "from": "*", "text": text, "ts_min": commx_core::now_minute(), "mine": false, "system": true})
}

fn call_event(me: &[u8; 32], room: &RoomState) -> Event {
    let call = room.call.as_ref().map(|c| {
        let names: Vec<String> =
            c.participants.iter().map(|pk| Member::name_of(room, pk).unwrap_or_else(|| "?".into())).collect();
        json!({"participants": names, "joined": c.has(me)})
    });
    json!({"ev": "call", "call": call})
}

fn files_event(room: &RoomState) -> Event {
    let mut list: Vec<&WebFile> = room.files.values().collect();
    list.sort_by_key(|f| f.no);
    let list: Vec<Value> = list
        .iter()
        .map(|f| {
            json!({
                "no": f.no, "name": f.name, "size": f.size, "from": f.from,
                "state": f.state.label(f.got, f.chunks), "ready": f.state == FileState::Ready,
            })
        })
        .collect();
    json!({"ev": "files", "list": list})
}

fn human_size(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GiB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KiB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}
