//! One room running on the radio profile (SPEC §18), as a sans-IO state
//! machine. The caller feeds it received packets and the clock (unix ms),
//! and pulls packets to transmit; it never touches a socket or a timer.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use commx_core::identity::{verify, Identity, PublicIdentity};
use commx_core::room::KillMode;
use commx_core::secmem::Locked;
use commx_core::RoomId;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use zeroize::Zeroizing;

use crate::airtime::{Budget, LoRa};
use crate::packet::{
    bucket, mac, short_hash, signing_bytes, unix_hour, unpad, EpochChain, Header, Kind, MAC_LEN, MAX_CTR, MAX_TEXT,
    MTU, OVERHEAD, SIG_LEN,
};

/// Most entries one `ORDER` sequences: 32 + 4 + 10 × 13 + 64 = 230.
pub const ORDER_MAX: usize = 10;
const ENTRY_LEN: usize = 13;
/// Most packets one `REPAIR` asks for: 32 + 1 + 37 × 5 + 8 = 226.
const REPAIR_MAX: usize = 37;
const REPAIR_ENTRY: usize = 5;
/// Members whose new key fits in one `REKEY`: 32 + 6 + 2 × 49 + 64 = 200.
const REKEY_MAX: usize = 2;
/// `index || AEAD(chain_key)`.
const REKEY_ENTRY: usize = 1 + 32 + 16;
/// `new_epoch || n || BE32(hour)` before the entries.
const REKEY_HEAD: usize = 6;
/// A member this far behind the chain can't catch up: the packets it needs
/// are sealed under hour keys that have been erased.
const BEHIND_LIMIT_MS: u64 = 60 * 60_000;
/// Missing messages stop being asked for after this long, for the same reason.
const WANTED_TTL_MS: u64 = 90 * 60_000;
/// Messages waiting for airtime before `send_text` refuses more.
const TEXT_QUEUE: usize = 8;
const CACHE_CAP: usize = 512;
const MSGS_CAP: usize = 2048;
const BOUNDARY_CAP: usize = 4096;
const STASH_CAP: usize = 32;
const CLAIMS_CAP: usize = 64;

#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub id: PublicIdentity,
}

/// Everything a node needs to move a room from IP to radio.
pub struct Setup {
    pub room_id: RoomId,
    pub me: Arc<Identity>,
    /// Radio index order. Index 0 is the host.
    pub members: Vec<Member>,
    /// Wiped as soon as the radio's own key chain is derived from it.
    pub room_key: Locked<32>,
    pub epoch: u32,
    /// Unix hour the host named at handover: the radio key chain starts there.
    pub start_hour: u32,
    /// Head of the room's IP chain at handover. Every member must agree on it.
    pub ip_head: [u8; 32],
    pub kill_mode: KillMode,
    pub grace_ms: u64,
    pub lora: LoRa,
    /// Share of airtime this node may use (0.01 = 1%).
    pub budget: f64,
}

#[derive(Debug)]
pub enum Event {
    /// A message, shown on arrival before the host has sequenced it.
    Msg { from: String, mine: bool, text: Zeroizing<String> },
    /// Three `ORDER`s went by without this message: the host may be
    /// dropping it, or never heard it.
    Unconfirmed { from: String, mine: bool },
    MemberGone { name: String, id: PublicIdentity, why: &'static str },
    Rekeyed { epoch: u32 },
    /// The room is dead. Drain `poll_transmit` (the host's `NUKE`), then drop it.
    Nuked { reason: String },
}

/// `(sender, epoch, ctr)`: names one packet everywhere.
type PktId = (u8, u32, u32);

struct MsgState {
    hash: [u8; 8],
    author: u8,
    mine: bool,
    confirmed: bool,
    orders_since: u8,
    /// Own messages: rebroadcasts so far, and when the next one is due.
    retries: u8,
    next_retry: u64,
}

/// An author rebroadcasts its unconfirmed message this many times at most.
const MAX_RETRIES: u8 = 8;

#[derive(Debug, PartialEq, Eq)]
enum Out {
    Msg(Zeroizing<String>),
    Order,
    Beat,
    Repair,
    Raw(PktId),
    Remove(u8),
    Rekey { epoch: u32, idxs: Vec<u8> },
}

struct PendingRekey {
    chain: EpochChain,
    left: usize,
}

/// 64-packet anti-replay window for one sender in one epoch.
#[derive(Default)]
struct Window {
    top: u32,
    bits: u64,
    init: bool,
}

impl Window {
    fn fresh(&self, ctr: u32) -> bool {
        if !self.init || ctr > self.top {
            return true;
        }
        let d = self.top - ctr;
        d < 64 && self.bits & (1 << d) == 0
    }

    fn mark(&mut self, ctr: u32) {
        if !self.init {
            *self = Window { top: ctr, bits: 1, init: true };
        } else if ctr > self.top {
            let s = ctr - self.top;
            self.bits = if s >= 64 { 0 } else { self.bits << s };
            self.bits |= 1;
            self.top = ctr;
        } else if self.top - ctr < 64 {
            self.bits |= 1 << (self.top - ctr);
        }
    }
}

struct Entry {
    id: Option<PktId>,
    hash: [u8; 8],
}

/// What a handler concluded about a packet.
enum Verdict {
    /// Authenticated as coming from its sender.
    Authentic,
    /// Fine to have seen, but proves nothing about the sender.
    Ignored,
}

type Handled = std::result::Result<Verdict, String>;

pub struct Radio {
    room_id: RoomId,
    me: Arc<Identity>,
    my_idx: u8,
    members: Vec<Option<Member>>,
    kill_mode: KillMode,
    grace_ms: u64,

    /// Ascending epochs, at most two: the current one last.
    keys: Vec<EpochChain>,
    /// Host: one per member. Member: one, with the host, under index 0.
    pair: HashMap<u8, Locked<32>>,
    ctrs: HashMap<u32, u32>,
    replay: HashMap<(u8, u32), Window>,

    next_seq: u32,
    head: [u8; 32],
    boundaries: BTreeMap<u32, [u8; 32]>,
    /// `ORDER`s that arrived ahead of a gap, by first_seq.
    stash: BTreeMap<u32, (PktId, Vec<u8>)>,
    /// Chain positions others reported beyond ours, checked once we get there.
    claims: VecDeque<(u32, [u8; 4])>,
    /// Furthest chain position anyone has reported.
    target_seq: u32,

    msgs: HashMap<PktId, MsgState>,
    msg_fifo: VecDeque<PktId>,
    /// Sequenced packets we haven't heard, with the hash the host gave and
    /// when we learned of them.
    wanted: HashMap<PktId, ([u8; 8], u64)>,
    /// Since when our chain has been behind what others report.
    behind_since: Option<u64>,
    cache: HashMap<PktId, Vec<u8>>,
    cache_fifo: VecDeque<PktId>,
    order_ids: BTreeMap<u32, PktId>,
    /// Rebroadcasts waiting out their random delay.
    rb: HashMap<PktId, u64>,

    unordered: VecDeque<(PktId, [u8; 8])>,
    last_order: u64,
    pending_rekey: Option<PendingRekey>,
    rekey_resent: HashMap<u8, u64>,
    heard: HashMap<u8, u64>,

    ctl: VecDeque<Out>,
    texts: VecDeque<Zeroizing<String>>,
    last_tx: u64,
    repair_due: u64,
    lora: LoRa,
    budget: Budget,

    events: VecDeque<Event>,
    dead: bool,
    final_out: VecDeque<Vec<u8>>,
    /// Latest clock reading we were given.
    now: u64,
    /// Jitter for rebroadcasts. Not secret.
    rng: StdRng,
}

fn chain_start(room_id: &RoomId, ip_head: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"commx-radio-start-v1");
    h.update(room_id);
    h.update(ip_head);
    *h.finalize().as_bytes()
}

fn pair_key(me: &Identity, peer_dh: &[u8; 32], room_id: &RoomId) -> Locked<32> {
    let mut m = Zeroizing::new([0u8; 48]);
    m[..32].copy_from_slice(&*me.dh(peer_dh));
    m[32..].copy_from_slice(room_id);
    Locked::from_bytes(&Zeroizing::new(blake3::derive_key("commx radio pair v1", &m[..])))
}

fn be24(b: &[u8]) -> u32 {
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

/// The nonce covers the hour, so a resend in a later hour (a different
/// chain key) never reuses one.
fn rekey_crypto(
    pair: &[u8; 32],
    room_id: &RoomId,
    epoch: u32,
    hour: u32,
    idx: u8,
) -> (XChaCha20Poly1305, [u8; 24], Vec<u8>) {
    let mut m = [0u8; 9];
    m[..4].copy_from_slice(&epoch.to_be_bytes());
    m[4..8].copy_from_slice(&hour.to_be_bytes());
    m[8] = idx;
    let nonce: [u8; 24] = blake3::derive_key("commx radio rekey nonce v1", &m)[..24].try_into().unwrap();
    let mut aad = room_id.to_vec();
    aad.extend_from_slice(&m);
    (XChaCha20Poly1305::new(Key::from_slice(pair)), nonce, aad)
}

/// Zero-pad text so the whole `MSG` fills its size class. The padding sits
/// inside the signature, which stays last.
fn pad(text: &str) -> Vec<u8> {
    let mut v = text.as_bytes().to_vec();
    let target = bucket(v.len() + SIG_LEN) - OVERHEAD - SIG_LEN;
    v.resize(target.max(v.len()), 0);
    v
}

impl Radio {
    pub fn new(s: Setup, now: u64) -> Result<Self> {
        if s.members.is_empty() || s.members.len() > 255 {
            bail!("a radio room holds 1–255 members");
        }
        if !s.lora.valid() {
            bail!("invalid LoRa settings");
        }
        let me_pk = s.me.public();
        let Some(my_idx) = s.members.iter().position(|m| m.id == me_pk) else {
            bail!("not a member of this room");
        };
        let my_idx = my_idx as u8;
        let mut pair = HashMap::new();
        if my_idx == 0 {
            for (i, m) in s.members.iter().enumerate().skip(1) {
                pair.insert(i as u8, pair_key(&s.me, &m.id.dh_pk, &s.room_id));
            }
        } else {
            pair.insert(0, pair_key(&s.me, &s.members[0].id.dh_pk, &s.room_id));
        }
        let head = chain_start(&s.room_id, &s.ip_head);
        let mut chain = EpochChain::from_room_key(s.epoch, s.start_hour, s.room_key.bytes());
        chain.advance_to(unix_hour(now));
        // `s.room_key` drops (and is wiped) at the end of this function.
        let heard = (0..s.members.len() as u8).map(|i| (i, now)).collect();
        Ok(Self {
            room_id: s.room_id,
            me: s.me,
            my_idx,
            members: s.members.into_iter().map(Some).collect(),
            kill_mode: s.kill_mode,
            grace_ms: s.grace_ms.max(4_000),
            keys: vec![chain],
            pair,
            ctrs: HashMap::new(),
            replay: HashMap::new(),
            next_seq: 0,
            head,
            boundaries: BTreeMap::from([(0, head)]),
            stash: BTreeMap::new(),
            claims: VecDeque::new(),
            target_seq: 0,
            msgs: HashMap::new(),
            msg_fifo: VecDeque::new(),
            wanted: HashMap::new(),
            behind_since: None,
            cache: HashMap::new(),
            cache_fifo: VecDeque::new(),
            order_ids: BTreeMap::new(),
            rb: HashMap::new(),
            unordered: VecDeque::new(),
            last_order: now,
            pending_rekey: None,
            rekey_resent: HashMap::new(),
            heard,
            ctl: VecDeque::new(),
            texts: VecDeque::new(),
            last_tx: now,
            repair_due: 0,
            lora: s.lora,
            budget: Budget::new(s.budget),
            events: VecDeque::new(),
            dead: false,
            final_out: VecDeque::new(),
            now,
            rng: StdRng::from_entropy(),
        })
    }

    pub fn is_host(&self) -> bool {
        self.my_idx == 0
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    pub fn epoch(&self) -> u32 {
        self.keys.last().map(|k| k.epoch).unwrap_or(0)
    }

    pub fn member_names(&self) -> Vec<String> {
        self.members.iter().flatten().map(|m| m.name.clone()).collect()
    }

    /// Sequenced messages so far.
    pub fn seq(&self) -> u32 {
        self.next_seq
    }

    /// Six beats per grace window: at 30% loss a live member still gets
    /// one through with probability 1 − 0.3⁶ ≈ 99.93%.
    fn beat_ms(&self) -> u64 {
        self.grace_ms / 6
    }

    fn order_ms(&self) -> u64 {
        (self.grace_ms / 4).min(30_000)
    }

    fn jitter_ms(&self) -> u64 {
        (self.grace_ms / 8).min(10_000)
    }

    fn name(&self, idx: u8) -> String {
        self.members.get(idx as usize).and_then(|m| m.as_ref()).map(|m| m.name.clone()).unwrap_or_else(|| "?".into())
    }

    fn member(&self, idx: u8) -> Option<&Member> {
        self.members.get(idx as usize)?.as_ref()
    }

    fn keys_for(&self, epoch: u32) -> Option<&EpochChain> {
        self.keys.iter().find(|k| k.epoch == epoch)
    }

    /// Ratchet every key chain to the current hour.
    fn advance(&mut self, now: u64) {
        self.now = now;
        let h = unix_hour(now);
        for k in &mut self.keys {
            k.advance_to(h);
        }
        if let Some(p) = &mut self.pending_rekey {
            p.chain.advance_to(h);
        }
    }

    /// Find the keys for a packet and open it.
    fn open_any(&self, pkt: &[u8]) -> Option<(u32, Header, Zeroizing<Vec<u8>>)> {
        let tag = pkt.get(..4)?;
        self.keys.iter().find_map(|c| {
            let k = c.find(tag)?;
            let (h, b) = k.open(pkt)?;
            Some((k.epoch, h, b))
        })
    }

    fn full_epoch(&self, low: u8) -> Option<u32> {
        self.keys.iter().rev().find(|k| k.epoch as u8 == low).map(|k| k.epoch)
    }

    fn seen(&self) -> (u16, [u8; 4]) {
        (self.next_seq as u16, self.head[..4].try_into().unwrap())
    }

    /// The header of our next packet in `epoch`, spending a counter value.
    fn header(&mut self, kind: Kind, epoch: u32) -> Option<Header> {
        let ctr = self.ctrs.entry(epoch).or_insert(0);
        if *ctr > MAX_CTR {
            return None;
        }
        let this = *ctr;
        *ctr += 1;
        let (seen_seq, seen_head) = self.seen();
        Some(Header { kind, sender: self.my_idx, ctr: this, epoch: epoch as u8, seen_seq, seen_head })
    }

    fn remember(&mut self, id: PktId, raw: Vec<u8>) {
        if self.cache.insert(id, raw).is_none() {
            self.cache_fifo.push_back(id);
            while self.cache_fifo.len() > CACHE_CAP {
                if let Some(old) = self.cache_fifo.pop_front() {
                    self.cache.remove(&old);
                }
            }
        }
    }

    fn track(&mut self, id: PktId, st: MsgState) {
        if self.msgs.insert(id, st).is_none() {
            self.msg_fifo.push_back(id);
            while self.msg_fifo.len() > MSGS_CAP {
                if let Some(old) = self.msg_fifo.pop_front() {
                    self.msgs.remove(&old);
                }
            }
        }
    }

    // ---- sending -------------------------------------------------------

    /// Queue a message. It goes out when the airtime budget allows.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        if self.dead {
            bail!("room is gone");
        }
        if text.trim().is_empty() {
            bail!("empty message");
        }
        if text.len() > MAX_TEXT {
            bail!("too long for radio ({} bytes, max {MAX_TEXT})", text.len());
        }
        if text.contains('\0') {
            bail!("message contains a NUL byte");
        }
        if self.texts.len() >= TEXT_QUEUE {
            bail!("radio queue full; the airtime budget is used up for now");
        }
        self.texts.push_back(Zeroizing::new(text.to_string()));
        Ok(())
    }

    /// Messages still waiting for airtime.
    pub fn queued(&self) -> usize {
        self.texts.len()
    }

    /// On-air size of what `out` would build.
    fn out_len(&self, out: &Out) -> Option<usize> {
        Some(match out {
            Out::Msg(t) => bucket(pad(t).len() + SIG_LEN),
            Out::Order => bucket(4 + ENTRY_LEN * self.unordered.len().min(ORDER_MAX) + SIG_LEN),
            Out::Beat => bucket(MAC_LEN),
            Out::Repair => bucket(1 + REPAIR_ENTRY * self.wanted.len().min(REPAIR_MAX) + MAC_LEN),
            Out::Raw(id) => self.cache.get(id)?.len(),
            Out::Remove(_) => bucket(1 + SIG_LEN),
            Out::Rekey { idxs, .. } => bucket(REKEY_HEAD + REKEY_ENTRY * idxs.len() + SIG_LEN),
        })
    }

    /// Next packet to put on the air, if there is one and the airtime
    /// budget allows it. Call after `tick` and after each received packet.
    pub fn poll_transmit(&mut self, now: u64) -> Option<Vec<u8>> {
        self.advance(now);
        if self.dead {
            return self.final_out.pop_front();
        }
        loop {
            let from_ctl = !self.ctl.is_empty();
            let out = match self.ctl.front() {
                Some(_) => self.ctl.pop_front()?,
                None => Out::Msg(self.texts.front()?.clone()),
            };
            let Some(len) = self.out_len(&out) else {
                continue; // a rebroadcast whose packet we no longer hold
            };
            let ms = self.lora.airtime_ms(len);
            if !self.budget.allows(now, ms) {
                if from_ctl {
                    self.ctl.push_front(out);
                }
                return None;
            }
            if !from_ctl {
                self.texts.pop_front();
            }
            // Rebroadcasts carry someone else's proof of life, or a stale
            // copy of ours: they don't stand in for a beat.
            let proves_life = !matches!(out, Out::Raw(_));
            if let Some(pkt) = self.build(out, now) {
                debug_assert!(pkt.len() <= MTU);
                self.budget.spend(now, self.lora.airtime_ms(pkt.len()));
                if proves_life {
                    self.last_tx = now;
                }
                return Some(pkt);
            }
            if self.dead {
                return self.final_out.pop_front();
            }
        }
    }

    fn sign(&self, hdr: &Header, body: &[u8]) -> Vec<u8> {
        self.me.sign(&signing_bytes(&self.room_id, hdr, body))
    }

    fn seal(&self, epoch: u32, hdr: &Header, body: &[u8]) -> Option<Vec<u8>> {
        Some(self.keys_for(epoch)?.current().seal(hdr, body))
    }

    fn build(&mut self, out: Out, now: u64) -> Option<Vec<u8>> {
        let epoch = self.epoch();
        let kind = match &out {
            Out::Msg(_) => Kind::Msg,
            Out::Order => Kind::Order,
            Out::Beat => Kind::Beat,
            Out::Repair => Kind::Repair,
            Out::Raw(id) => {
                self.rb.remove(id);
                return self.cache.get(id).cloned();
            }
            Out::Remove(_) => Kind::Remove,
            Out::Rekey { .. } => Kind::Rekey,
        };
        let hdr_epoch = match &out {
            // Sealed under the key everyone still has.
            Out::Rekey { epoch: e, .. } => e.checked_sub(1)?,
            _ => epoch,
        };
        let Some(hdr) = self.header(kind, hdr_epoch) else {
            self.die("packet counter exhausted");
            return None;
        };
        let id = (self.my_idx, hdr_epoch, hdr.ctr);
        match out {
            Out::Msg(text) => {
                let mut body = Zeroizing::new(pad(&text));
                let sig = self.sign(&hdr, &body);
                body.extend_from_slice(&sig);
                let pkt = self.seal(epoch, &hdr, &body)?;
                let hash = short_hash(&pkt);
                let next_retry = now + 2 * self.order_ms();
                self.track(
                    id,
                    MsgState { hash, author: self.my_idx, mine: true, confirmed: false, orders_since: 0, retries: 0, next_retry },
                );
                self.remember(id, pkt.clone());
                if self.is_host() {
                    self.unordered.push_back((id, hash));
                }
                self.events.push_back(Event::Msg { from: self.name(self.my_idx), mine: true, text });
                Some(pkt)
            }
            Out::Order => {
                let n = self.unordered.len().min(ORDER_MAX);
                let entries: Vec<(PktId, [u8; 8])> = self.unordered.drain(..n).collect();
                let mut body = Vec::with_capacity(4 + n * ENTRY_LEN + SIG_LEN);
                body.extend_from_slice(&self.next_seq.to_be_bytes()[1..]);
                body.push(n as u8);
                for ((s, e, c), h) in &entries {
                    body.push(*s);
                    body.push(*e as u8);
                    body.extend_from_slice(&c.to_be_bytes()[1..]);
                    body.extend_from_slice(h);
                }
                let sig = self.sign(&hdr, &body);
                body.extend_from_slice(&sig);
                let pkt = self.seal(epoch, &hdr, &body)?;
                self.last_order = now;
                if n > 0 {
                    let first = self.next_seq;
                    if let Err(e) = self.apply_order(first, &body[4..4 + n * ENTRY_LEN], &pkt, id) {
                        self.die(&e);
                        return None;
                    }
                }
                Some(pkt)
            }
            Out::Beat => {
                let m = mac(self.pair.get(&0)?.bytes(), &hdr, &[]);
                self.seal(epoch, &hdr, &m)
            }
            Out::Repair => {
                let ids: Vec<PktId> = self.wanted.keys().take(REPAIR_MAX).copied().collect();
                debug_assert!(ids.len() <= REPAIR_MAX);
                let mut body = vec![ids.len() as u8];
                for (s, e, c) in ids {
                    body.push(s);
                    body.push(e as u8);
                    body.extend_from_slice(&c.to_be_bytes()[1..]);
                }
                let m = mac(self.pair.get(&0)?.bytes(), &hdr, &body);
                body.extend_from_slice(&m);
                self.repair_due = now + self.order_ms();
                self.seal(epoch, &hdr, &body)
            }
            Out::Remove(idx) => {
                let mut body = vec![idx];
                let sig = self.sign(&hdr, &body);
                body.extend_from_slice(&sig);
                self.seal(epoch, &hdr, &body)
            }
            Out::Rekey { epoch: new_epoch, idxs } => {
                let chain = match &self.pending_rekey {
                    Some(p) if p.chain.epoch == new_epoch => &p.chain,
                    _ if epoch == new_epoch => self.keys.last()?,
                    _ => return None,
                };
                let (hour, ck) = chain.chain_key();
                let idxs: Vec<u8> = idxs.into_iter().filter(|i| self.pair.contains_key(i)).collect();
                let mut body = vec![new_epoch as u8, idxs.len() as u8];
                body.extend_from_slice(&hour.to_be_bytes());
                for idx in idxs {
                    let pk = self.pair.get(&idx)?;
                    let (aead, nonce, aad) = rekey_crypto(pk.bytes(), &self.room_id, new_epoch, hour, idx);
                    let ct = aead.encrypt(XNonce::from_slice(&nonce), Payload { msg: ck, aad: &aad }).ok()?;
                    body.push(idx);
                    body.extend_from_slice(&ct);
                }
                let sig = self.sign(&hdr, &body);
                body.extend_from_slice(&sig);
                let pkt = self.seal(hdr_epoch, &hdr, &body);
                if let Some(p) = &mut self.pending_rekey {
                    if p.chain.epoch == new_epoch {
                        p.left = p.left.saturating_sub(1);
                        if p.left == 0 {
                            let p = self.pending_rekey.take()?;
                            self.switch_epoch(p.chain);
                        }
                    }
                }
                pkt
            }
            Out::Raw(_) => None,
        }
    }

    fn switch_epoch(&mut self, mut chain: EpochChain) {
        chain.advance_to(unix_hour(self.now));
        let epoch = chain.epoch;
        self.keys.push(chain);
        if self.keys.len() > 2 {
            self.keys.remove(0);
        }
        self.events.push_back(Event::Rekeyed { epoch });
    }

    // ---- receiving -----------------------------------------------------

    /// Handle one packet heard on the air.
    pub fn on_packet(&mut self, pkt: &[u8], now: u64) {
        if self.dead || pkt.len() < OVERHEAD || pkt.len() > MTU {
            return;
        }
        self.advance(now);
        let Some((epoch, hdr, body)) = self.open_any(pkt) else { return };
        if hdr.sender == self.my_idx || self.member(hdr.sender).is_none() {
            return;
        }
        let id = (hdr.sender, epoch, hdr.ctr);
        let fresh = self.replay.get(&(hdr.sender, epoch)).is_none_or(|w| w.fresh(hdr.ctr));
        if !fresh {
            // Someone else already rebroadcast it: no need for us to.
            self.rb.remove(&id);
        }
        // Even an unverifiable packet can tell us we're behind; asking for
        // a repair is harmless if it lied.
        self.note_claimed_seq(hdr.seen_seq);
        let res = match hdr.kind {
            Kind::Msg => self.on_msg(&hdr, &body, pkt, id, fresh),
            Kind::Order => self.on_order(&hdr, &body, pkt, id, fresh),
            Kind::Beat => self.on_beat(&hdr, &body, fresh),
            Kind::Repair => self.on_repair(&hdr, &body, fresh, now),
            Kind::Remove => self.on_remove(&hdr, &body, fresh),
            Kind::Rekey => self.on_rekey(&hdr, &body, fresh),
            Kind::Nuke => self.on_nuke(&hdr, &body),
            Kind::Join => Ok(Verdict::Ignored), // over-the-air joins aren't implemented
        };
        match res {
            Err(reason) => self.die(&reason),
            Ok(Verdict::Ignored) => {}
            Ok(Verdict::Authentic) => {
                if !fresh {
                    return;
                }
                self.replay.entry((hdr.sender, epoch)).or_default().mark(hdr.ctr);
                if self.is_host() || hdr.sender == 0 {
                    self.heard.insert(hdr.sender, now);
                }
                if let Err(reason) = self.check_claim(hdr.seen_seq, hdr.seen_head) {
                    self.die(&reason);
                    return;
                }
                if self.is_host() && epoch < self.epoch() {
                    self.resend_rekey(hdr.sender, now);
                }
            }
        }
    }

    /// Check a host-signed packet whose unpadded body is `body[..len]`
    /// (signature last). Returns where the signature starts.
    fn host_signed(&self, hdr: &Header, body: &[u8], len: usize) -> std::result::Result<usize, String> {
        if hdr.sender != 0 {
            return Err(format!("{} sent a host-only packet", self.name(hdr.sender)));
        }
        let body = unpad(body, len).ok_or("malformed packet from the host")?;
        let Some(split) = body.len().checked_sub(SIG_LEN) else {
            return Err("malformed packet from the host".into());
        };
        let host = self.member(0).ok_or("no host")?;
        if !verify(&host.id.sign_pk, &signing_bytes(&self.room_id, hdr, &body[..split]), &body[split..]) {
            return Err("bad host signature".into());
        }
        Ok(split)
    }

    fn on_msg(&mut self, hdr: &Header, body: &[u8], pkt: &[u8], id: PktId, fresh: bool) -> Handled {
        if !fresh && !self.wanted.contains_key(&id) {
            return Ok(Verdict::Ignored);
        }
        let from = self.name(hdr.sender);
        let Some(split) = body.len().checked_sub(SIG_LEN) else {
            return Err(format!("malformed message from {from}"));
        };
        let author = self.member(hdr.sender).ok_or("unknown sender")?;
        if !verify(&author.id.sign_pk, &signing_bytes(&self.room_id, hdr, &body[..split]), &body[split..]) {
            return Err(format!("forged message claiming to be from {from}"));
        }
        if self.msgs.contains_key(&id) {
            return Ok(Verdict::Authentic);
        }
        let hash = short_hash(pkt);
        let confirmed = match self.wanted.remove(&id).map(|(h, _)| h) {
            Some(want) if want != hash => {
                return Err(format!("a message from {from} doesn't match the host's order"));
            }
            Some(_) => true,
            None => false,
        };
        let end = body[..split].iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let text = Zeroizing::new(String::from_utf8_lossy(&body[..end]).into_owned());
        self.track(
            id,
            MsgState { hash, author: hdr.sender, mine: false, confirmed, orders_since: 0, retries: 0, next_retry: 0 },
        );
        self.remember(id, pkt.to_vec());
        if self.is_host() {
            self.unordered.push_back((id, hash));
        }
        self.events.push_back(Event::Msg { from, mine: false, text });
        Ok(Verdict::Authentic)
    }

    fn parse_entries(&self, raw: &[u8]) -> Vec<Entry> {
        raw.as_chunks::<ENTRY_LEN>()
            .0
            .iter()
            .map(|e| Entry {
                id: self.full_epoch(e[1]).map(|ep| (e[0], ep, be24(&e[2..5]))),
                hash: e[5..13].try_into().unwrap(),
            })
            .collect()
    }

    fn next_head(&self, head: &[u8; 32], first: u32, entries: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"commx-radio-chain-v1");
        h.update(head);
        h.update(&first.to_be_bytes()[1..]);
        h.update(&[(entries.len() / ENTRY_LEN) as u8]);
        h.update(entries);
        *h.finalize().as_bytes()
    }

    fn on_order(&mut self, hdr: &Header, body: &[u8], pkt: &[u8], id: PktId, fresh: bool) -> Handled {
        if body.len() < 4 || body[3] as usize > ORDER_MAX {
            return Err("malformed order from the host".into());
        }
        let split = self.host_signed(hdr, body, 4 + ENTRY_LEN * body[3] as usize + SIG_LEN)?;
        let body = &body[..split];
        let first = be24(body);
        let n = body[3] as u32;
        let entries = &body[4..];
        if n == 0 {
            // The host's heartbeat: no chain step, but it tells us where the chain is.
            self.note_target(first);
            return Ok(Verdict::Authentic);
        }
        if first < self.next_seq {
            // Already applied: it must say exactly what we applied.
            if let (Some(before), Some(after)) = (self.boundaries.get(&first), self.boundaries.get(&(first + n))) {
                if self.next_head(before, first, entries) != *after {
                    return Err("the host sent two different orders for the same messages".into());
                }
            } else if self.boundaries.keys().next().is_some_and(|&lo| first >= lo) {
                return Err("the host's orders don't line up with each other".into());
            }
            return Ok(if fresh { Verdict::Authentic } else { Verdict::Ignored });
        }
        if first > self.next_seq {
            if self.stash.len() < STASH_CAP {
                self.stash.insert(first, (id, pkt.to_vec()));
            }
            self.note_target(first);
            return Ok(Verdict::Authentic);
        }
        self.apply_order(first, entries, pkt, id)?;
        // Anything stashed that now fits.
        while let Some((id, raw)) = self.stash.remove(&self.next_seq) {
            let Some((_, _, body)) = self.open_any(&raw) else { continue };
            let n = body[3] as usize;
            let first = self.next_seq;
            self.apply_order(first, &body[4..4 + n * ENTRY_LEN], &raw, id)?;
        }
        self.stash.retain(|&k, _| k > self.next_seq);
        Ok(Verdict::Authentic)
    }

    fn note_claimed_seq(&mut self, seq16: u16) {
        let delta = seq16.wrapping_sub(self.next_seq as u16) as i16;
        if delta > 0 && !self.is_host() {
            self.note_target(self.next_seq + delta as u32);
        }
    }

    fn note_target(&mut self, seq: u32) {
        self.target_seq = self.target_seq.max(seq);
    }

    fn apply_order(&mut self, first: u32, entries: &[u8], pkt: &[u8], id: PktId) -> std::result::Result<(), String> {
        let n = (entries.len() / ENTRY_LEN) as u32;
        self.head = self.next_head(&self.head, first, entries);
        self.next_seq = first + n;
        self.boundaries.insert(self.next_seq, self.head);
        while self.boundaries.len() > BOUNDARY_CAP {
            self.boundaries.pop_first();
        }
        self.remember(id, pkt.to_vec());
        self.order_ids.insert(first, id);
        while self.order_ids.len() > CACHE_CAP {
            self.order_ids.pop_first();
        }
        let listed = self.parse_entries(entries);
        for e in &listed {
            let Some(eid) = e.id else { continue };
            match self.msgs.get_mut(&eid) {
                Some(m) if m.hash != e.hash => {
                    let who = self.name(eid.0);
                    return Err(format!("the host's order names a different message from {who} than the one sent"));
                }
                Some(m) => m.confirmed = true,
                None if eid.0 == self.my_idx => {
                    return Err("the host's order names a message I never sent".into());
                }
                None => {
                    self.wanted.insert(eid, (e.hash, self.now));
                }
            }
        }
        if !self.is_host() {
            self.age_unconfirmed();
        }
        // Reported chain positions we've now reached.
        let reached: Vec<(u32, [u8; 4])> = self.claims.iter().filter(|(s, _)| *s <= self.next_seq).copied().collect();
        self.claims.retain(|(s, _)| *s > self.next_seq);
        for (s, h) in reached {
            self.check_full_claim(s, h)?;
        }
        Ok(())
    }

    /// One more `ORDER` went by without others' messages we hold: maybe
    /// the host never heard them, so pass them on, then flag them.
    /// (Our own are retried on a timer and flagged there.)
    fn age_unconfirmed(&mut self) {
        let mut flag = Vec::new();
        let mut pass_on = Vec::new();
        for (id, m) in self.msgs.iter_mut().filter(|(_, m)| !m.confirmed && !m.mine) {
            m.orders_since = m.orders_since.saturating_add(1);
            if m.orders_since == 2 {
                pass_on.push(*id);
            }
            if m.orders_since == 3 {
                flag.push((m.author, m.mine));
            }
        }
        let (now, jitter) = (self.now, self.jitter_ms());
        for id in pass_on {
            let due = now + self.rng.gen_range(0..=jitter);
            self.rb.entry(id).or_insert(due);
        }
        for (author, mine) in flag {
            self.events.push_back(Event::Unconfirmed { from: self.name(author), mine });
        }
    }

    fn check_claim(&mut self, seq16: u16, head4: [u8; 4]) -> std::result::Result<(), String> {
        let delta = seq16.wrapping_sub(self.next_seq as u16) as i16 as i64;
        let full = self.next_seq as i64 + delta;
        if full < 0 {
            return Ok(());
        }
        let full = full as u32;
        if full > self.next_seq {
            if self.is_host() {
                return Err("a member reports a chain the host never made".into());
            }
            self.note_target(full);
            if self.claims.len() >= CLAIMS_CAP {
                self.claims.pop_front();
            }
            self.claims.push_back((full, head4));
            return Ok(());
        }
        self.check_full_claim(full, head4)
    }

    fn check_full_claim(&self, seq: u32, head4: [u8; 4]) -> std::result::Result<(), String> {
        match self.boundaries.get(&seq) {
            Some(h) if h[..4] != head4 => Err("members disagree on the chain: the host showed them different histories".into()),
            Some(_) => Ok(()),
            None if self.boundaries.keys().next().is_some_and(|&lo| seq >= lo) => {
                Err("members disagree on the chain: the host showed them different histories".into())
            }
            None => Ok(()),
        }
    }

    fn on_beat(&mut self, hdr: &Header, body: &[u8], fresh: bool) -> Handled {
        let Some(body) = unpad(body, MAC_LEN).filter(|_| self.is_host() && fresh) else {
            return Ok(Verdict::Ignored);
        };
        let Some(pk) = self.pair.get(&hdr.sender) else { return Ok(Verdict::Ignored) };
        Ok(if mac(pk.bytes(), hdr, &[]) == body[..] { Verdict::Authentic } else { Verdict::Ignored })
    }

    fn on_repair(&mut self, hdr: &Header, body: &[u8], fresh: bool, now: u64) -> Handled {
        let Some(body) = body.first().and_then(|&n| unpad(body, 1 + REPAIR_ENTRY * n as usize + MAC_LEN)) else {
            return Ok(Verdict::Ignored);
        };
        if !fresh {
            return Ok(Verdict::Ignored);
        }
        let split = body.len() - MAC_LEN;
        // Anyone may answer, but only the host can check who asked.
        let verdict = match self.pair.get(&hdr.sender) {
            Some(pk) if self.is_host() && mac(pk.bytes(), hdr, &body[..split]) == body[split..] => Verdict::Authentic,
            _ if self.is_host() => return Ok(Verdict::Ignored),
            _ => Verdict::Ignored,
        };
        let jitter = self.jitter_ms();
        let mut want: Vec<PktId> = body[1..split]
            .as_chunks::<REPAIR_ENTRY>()
            .0
            .iter()
            .filter_map(|e| Some((e[0], self.full_epoch(e[1])?, be24(&e[2..5]))))
            .collect();
        // Their chain stops at seen_seq: send the next few ORDERs too.
        let delta = hdr.seen_seq.wrapping_sub(self.next_seq as u16) as i16 as i64;
        let theirs = self.next_seq as i64 + delta;
        if theirs >= 0 && (theirs as u32) < self.next_seq {
            want.extend(self.order_ids.range(theirs as u32..).take(3).map(|(_, id)| *id));
        }
        for id in want {
            if self.cache.contains_key(&id) && !self.ctl.contains(&Out::Raw(id)) {
                let due = now + self.rng.gen_range(0..=jitter);
                self.rb.entry(id).or_insert(due);
            }
        }
        Ok(verdict)
    }

    fn on_remove(&mut self, hdr: &Header, body: &[u8], fresh: bool) -> Handled {
        self.host_signed(hdr, body, 1 + SIG_LEN)?;
        if !fresh {
            return Ok(Verdict::Ignored);
        }
        let idx = body[0];
        if idx == self.my_idx {
            return Err("removed from the room by the host".into());
        }
        if idx != 0 {
            if let Some(m) = self.members.get_mut(idx as usize).and_then(Option::take) {
                self.events.push_back(Event::MemberGone { name: m.name, id: m.id, why: "removed by the host" });
            }
        }
        Ok(Verdict::Authentic)
    }

    fn on_rekey(&mut self, hdr: &Header, body: &[u8], fresh: bool) -> Handled {
        if body.len() < 2 || body[1] as usize > REKEY_MAX {
            return Err("malformed rekey from the host".into());
        }
        let split = self.host_signed(hdr, body, REKEY_HEAD + REKEY_ENTRY * body[1] as usize + SIG_LEN)?;
        let cur = self.epoch();
        if body[0] != cur.wrapping_add(1) as u8 {
            // Old news, or a rekey we already have.
            return Ok(if fresh { Verdict::Authentic } else { Verdict::Ignored });
        }
        let new_epoch = cur + 1;
        let hour = u32::from_be_bytes(body[2..6].try_into().unwrap());
        let mine = body[REKEY_HEAD..split].as_chunks::<REKEY_ENTRY>().0.iter().find(|e| e[0] == self.my_idx);
        if let (Some(e), Some(pk)) = (mine, self.pair.get(&0)) {
            let (aead, nonce, aad) = rekey_crypto(pk.bytes(), &self.room_id, new_epoch, hour, self.my_idx);
            let ck = aead
                .decrypt(XNonce::from_slice(&nonce), Payload { msg: &e[1..], aad: &aad })
                .map(Zeroizing::new)
                .map_err(|_| "the host's new room key doesn't open".to_string())?;
            let ck: &[u8; 32] = ck.as_slice().try_into().map_err(|_| "bad room key length".to_string())?;
            self.switch_epoch(EpochChain::start(new_epoch, hour, ck));
            self.ctrs.retain(|e, _| *e >= cur);
        }
        Ok(if fresh { Verdict::Authentic } else { Verdict::Ignored })
    }

    fn on_nuke(&mut self, hdr: &Header, body: &[u8]) -> Handled {
        match self.host_signed(hdr, body, SIG_LEN) {
            Ok(0) => Err("host nuked the room".into()),
            _ => Ok(Verdict::Ignored),
        }
    }

    // ---- time ----------------------------------------------------------

    /// Run timers: liveness, ordering, repair, rebroadcasts, beats.
    pub fn tick(&mut self, now: u64) {
        if self.dead {
            return;
        }
        self.advance(now);
        // Liveness: minutes, not seconds.
        if self.is_host() {
            let silent: Vec<u8> = self
                .heard
                .iter()
                .filter(|(&i, &t)| i != 0 && now.saturating_sub(t) > self.grace_ms)
                .map(|(&i, _)| i)
                .collect();
            for idx in silent {
                let name = self.name(idx);
                match self.kill_mode {
                    KillMode::AnyMember => {
                        self.die(&format!("{name} went silent"));
                        return;
                    }
                    KillMode::HostOnly => {
                        // One removal (and its rekey) at a time.
                        if self.pending_rekey.is_none() {
                            self.remove(idx, "went silent");
                        }
                    }
                }
            }
        } else if self.heard.get(&0).is_some_and(|&t| now.saturating_sub(t) > self.grace_ms) {
            self.die("host went silent");
            return;
        }

        // Our own messages the host hasn't sequenced yet: say them again.
        if !self.is_host() {
            let order_ms = self.order_ms();
            let mut retry = Vec::new();
            for (id, m) in self.msgs.iter_mut().filter(|(_, m)| m.mine && !m.confirmed && m.retries < MAX_RETRIES) {
                if now >= m.next_retry {
                    m.retries += 1;
                    m.next_retry = now + (2 * order_ms * (m.retries as u64 + 1)).min(4 * order_ms);
                    retry.push((*id, m.retries == 3));
                }
            }
            for (id, flag) in retry {
                if !self.ctl.contains(&Out::Raw(id)) {
                    self.ctl.push_back(Out::Raw(id));
                }
                if flag {
                    self.events.push_back(Event::Unconfirmed { from: self.name(self.my_idx), mine: true });
                }
            }
        }

        let due: Vec<PktId> = self.rb.iter().filter(|(_, &t)| t <= now).map(|(id, _)| *id).collect();
        for id in due {
            self.rb.remove(&id);
            self.ctl.push_back(Out::Raw(id));
        }

        if self.is_host() {
            if !self.unordered.is_empty()
                && now.saturating_sub(self.last_order) >= self.order_ms()
                && !self.ctl.contains(&Out::Order)
            {
                self.ctl.push_back(Out::Order);
            }
        } else {
            self.wanted.retain(|_, (_, since)| now.saturating_sub(*since) < WANTED_TTL_MS);
            let chain_gap = !self.stash.is_empty() || self.target_seq > self.next_seq;
            if !chain_gap {
                self.behind_since = None;
            } else if now.saturating_sub(*self.behind_since.get_or_insert(now)) > BEHIND_LIMIT_MS {
                self.die("fell too far behind the room to catch up");
                return;
            }
            let behind = !self.wanted.is_empty() || chain_gap;
            if behind && now >= self.repair_due && !self.ctl.contains(&Out::Repair) {
                self.ctl.push_back(Out::Repair);
                self.repair_due = now + self.order_ms();
            }
        }

        if now.saturating_sub(self.last_tx) >= self.beat_ms() && self.ctl.is_empty() && self.texts.is_empty() {
            self.ctl.push_back(if self.is_host() { Out::Order } else { Out::Beat });
        }
    }

    /// Host: drop a member and re-key everyone else.
    fn remove(&mut self, idx: u8, why: &'static str) {
        let Some(m) = self.members.get_mut(idx as usize).and_then(Option::take) else { return };
        self.heard.remove(&idx);
        self.pair.remove(&idx);
        self.events.push_back(Event::MemberGone { name: m.name, id: m.id, why });
        self.ctl.push_back(Out::Remove(idx));
        let new_epoch = self.epoch() + 1;
        let rest: Vec<u8> = (1..self.members.len() as u8).filter(|&i| self.member(i).is_some()).collect();
        // A fresh random chain: nothing about it follows from earlier keys.
        let seed = Locked::<32>::random();
        let chain = EpochChain::start(new_epoch, unix_hour(self.now), seed.bytes());
        if rest.is_empty() {
            self.switch_epoch(chain);
            return;
        }
        let chunks: Vec<Vec<u8>> = rest.chunks(REKEY_MAX).map(<[u8]>::to_vec).collect();
        self.pending_rekey = Some(PendingRekey { chain, left: chunks.len() });
        for idxs in chunks {
            self.ctl.push_back(Out::Rekey { epoch: new_epoch, idxs });
        }
    }

    /// Host: a member is still talking under the old key, so it missed its `REKEY`.
    fn resend_rekey(&mut self, idx: u8, now: u64) {
        if self.pending_rekey.is_some() || idx == 0 {
            return;
        }
        if self.rekey_resent.get(&idx).is_some_and(|&t| now.saturating_sub(t) < self.order_ms()) {
            return;
        }
        self.rekey_resent.insert(idx, now);
        self.ctl.push_back(Out::Rekey { epoch: self.epoch(), idxs: vec![idx] });
    }

    // ---- death ---------------------------------------------------------

    /// Destroy the room. The host leaves a signed `NUKE` for `poll_transmit`
    /// (sent twice, outside the airtime budget: it's the last thing it sends).
    pub fn shutdown(&mut self, reason: &str, now: u64) {
        self.now = now;
        self.die(reason);
    }

    fn die(&mut self, reason: &str) {
        if self.dead {
            return;
        }
        if self.is_host() {
            let epoch = self.epoch();
            if let Some(hdr) = self.header(Kind::Nuke, epoch) {
                let sig = self.sign(&hdr, &[]);
                if let Some(pkt) = self.seal(epoch, &hdr, &sig) {
                    self.final_out.push_back(pkt.clone());
                    self.final_out.push_back(pkt);
                }
            }
        }
        self.dead = true;
        // Wipe: keys are on locked pages and zeroize on drop.
        self.keys.clear();
        self.pair.clear();
        self.pending_rekey = None;
        self.msgs.clear();
        self.cache.clear();
        self.wanted.clear();
        self.stash.clear();
        self.ctl.clear();
        self.texts.clear();
        self.unordered.clear();
        self.events.push_back(Event::Nuked { reason: reason.to_string() });
    }

    /// Make rebroadcast jitter reproducible (simulations).
    #[doc(hidden)]
    pub fn reseed(&mut self, seed: u64) {
        self.rng = StdRng::seed_from_u64(seed);
    }

    #[doc(hidden)]
    pub fn debug_state(&self) -> String {
        format!(
            "seq={} target={} wanted={} stash={} repair_due={} last_tx={} ctl={:?} heard0={:?} now={}",
            self.next_seq, self.target_seq, self.wanted.len(), self.stash.len(), self.repair_due, self.last_tx,
            self.ctl, self.heard.get(&0), self.now
        )
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
}
