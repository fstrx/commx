//! A room member with no I/O of its own: feed it the bytes that arrive from
//! the host, send the bytes it hands back. The browser wires this to a
//! WebSocket; tests wire it to a TCP socket. Same wire protocol as the apps
//! (length-prefixed Noise_XX frames), same chain verification, same crypto.

use anyhow::{anyhow, bail, Context, Result};
use commx_core::chain::{msg_aad, Block, Body, Chain, ChatPlain, FileMeta, Payload};
use commx_core::crypto::{open_sealed, RoomKey};
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
}

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
            alive: true,
        };
        m.event(json!({"ev": "status", "text": "connecting…"}));
        Ok(m)
    }

    pub fn fingerprint(&self) -> String {
        self.me.fingerprint()
    }

    /// Bytes to send to the host (drains the queue).
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
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
                    // Files and voice aren't supported in the browser yet.
                    WireMsg::FileChunk { .. } | WireMsg::Voice { .. } | WireMsg::CallPresence { .. } => {}
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
        self.event(json!({"ev": "line", "from": "*", "text": text, "ts_min": commx_core::now_minute(), "mine": false, "system": true}));
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
                let from = Self::name_of(room, &p.author).unwrap_or_else(|| "?".into());
                let key = room.keys.get(&p.epoch).ok_or_else(|| anyhow!("unknown key epoch"))?;
                let mut aad = msg_aad(&room.chain.room_id, p.epoch, &p.author);
                aad.extend_from_slice(b"file");
                aad.extend_from_slice(file_id);
                let name = key
                    .decrypt(nonce, ct, &aad)
                    .ok()
                    .and_then(|pl| postcard::from_bytes::<FileMeta>(&pl).ok())
                    .map(|m| safe_file_name(&m.name))
                    .unwrap_or_else(|| "a file".into());
                self.system(format!("📎 {from} shared '{name}' — files need the desktop or Android app"));
            }
            Body::Call { .. } => {
                let from = Self::name_of(room, &p.author).unwrap_or_else(|| "?".into());
                self.system(format!("📞 {from} started a call — voice isn't available on the web yet"));
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
