//! Radio packet format (SPEC §18.3): a 4-byte rotating room tag, a masked
//! 12-byte header, and an AEAD body under a key derived from the room key.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use commx_core::secmem::Locked;
use zeroize::Zeroizing;

pub const TAG_LEN: usize = 4;
pub const HDR_LEN: usize = 12;
pub const AEAD_TAG: usize = 16;
/// Bytes every packet spends before its body.
pub const OVERHEAD: usize = TAG_LEN + HDR_LEN + AEAD_TAG;
pub const SIG_LEN: usize = 64;
pub const MAC_LEN: usize = 8;
/// Largest packet this profile sends.
pub const MTU: usize = 230;
/// Most text one `MSG` carries.
pub const MAX_TEXT: usize = MTU - OVERHEAD - SIG_LEN;
/// Counters are 24 bits on the air.
pub const MAX_CTR: u32 = (1 << 24) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Msg = 0,
    Order = 1,
    Beat = 2,
    Repair = 3,
    Join = 4,
    Remove = 5,
    Rekey = 6,
    Nuke = 7,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Kind::Msg,
            1 => Kind::Order,
            2 => Kind::Beat,
            3 => Kind::Repair,
            4 => Kind::Join,
            5 => Kind::Remove,
            6 => Kind::Rekey,
            7 => Kind::Nuke,
            _ => return None,
        })
    }

    /// Domain separation for what each packet type signs.
    pub fn sig_context(self) -> &'static [u8] {
        match self {
            Kind::Msg => b"commx-radio-msg-v1",
            Kind::Order => b"commx-radio-order-v1",
            Kind::Beat => b"commx-radio-beat-v1",
            Kind::Repair => b"commx-radio-repair-v1",
            Kind::Join => b"commx-radio-join-v1",
            Kind::Remove => b"commx-radio-remove-v1",
            Kind::Rekey => b"commx-radio-rekey-v1",
            Kind::Nuke => b"commx-radio-nuke-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub sender: u8,
    /// 24 bits.
    pub ctr: u32,
    /// Low byte of the key epoch.
    pub epoch: u8,
    pub seen_seq: u16,
    pub seen_head: [u8; 4],
}

impl Header {
    pub fn encode(&self) -> [u8; HDR_LEN] {
        let mut h = [0u8; HDR_LEN];
        h[0] = self.kind as u8;
        h[1] = self.sender;
        h[2..5].copy_from_slice(&self.ctr.to_be_bytes()[1..]);
        h[5] = self.epoch;
        h[6..8].copy_from_slice(&self.seen_seq.to_be_bytes());
        h[8..12].copy_from_slice(&self.seen_head);
        h
    }

    pub fn decode(h: &[u8; HDR_LEN]) -> Option<Self> {
        Some(Self {
            kind: Kind::from_u8(h[0])?,
            sender: h[1],
            ctr: u32::from_be_bytes([0, h[2], h[3], h[4]]),
            epoch: h[5],
            seen_seq: u16::from_be_bytes([h[6], h[7]]),
            seen_head: h[8..12].try_into().unwrap(),
        })
    }
}

/// Packet sizes on the air. Every packet is padded up to one of these, so
/// its length says little about its type or content.
pub const SIZES: [usize; 4] = [64, 128, 176, MTU];

/// The on-air size of a packet whose body is `body_len` bytes.
pub fn bucket(body_len: usize) -> usize {
    let total = OVERHEAD + body_len;
    SIZES.iter().copied().find(|&s| s >= total).unwrap_or(total)
}

/// `body[..len]` if everything after it is zero padding.
pub fn unpad(body: &[u8], len: usize) -> Option<&[u8]> {
    (body.len() >= len && body[len..].iter().all(|&b| b == 0)).then(|| &body[..len])
}

pub fn unix_hour(now_ms: u64) -> u32 {
    (now_ms / 3_600_000) as u32
}

/// Packet keys for one epoch during one unix hour. Both live on locked pages.
pub struct HourKeys {
    pub epoch: u32,
    pub hour: u32,
    radio: Locked<32>,
    hp: Locked<32>,
}

impl HourKeys {
    fn derive(epoch: u32, hour: u32, chain: &[u8; 32]) -> Self {
        let radio = Zeroizing::new(blake3::derive_key("commx radio key v1", chain));
        let hp = Zeroizing::new(blake3::derive_key("commx radio hp v1", chain));
        Self { epoch, hour, radio: Locked::from_bytes(&radio), hp: Locked::from_bytes(&hp) }
    }

    pub fn tag(&self) -> [u8; TAG_LEN] {
        let mut m = [0u8; 7];
        m[..3].copy_from_slice(b"tag");
        m[3..].copy_from_slice(&self.hour.to_be_bytes());
        blake3::keyed_hash(self.radio.bytes(), &m).as_bytes()[..TAG_LEN].try_into().unwrap()
    }

    fn nonce(&self, sender: u8, ctr: u32) -> [u8; 24] {
        let mut m = [0u8; 8];
        m[..4].copy_from_slice(&self.epoch.to_be_bytes());
        m[4] = sender;
        m[5..].copy_from_slice(&ctr.to_be_bytes()[1..]);
        blake3::derive_key("commx radio nonce v1", &m)[..24].try_into().unwrap()
    }

    fn mask(&self, ct: &[u8]) -> [u8; HDR_LEN] {
        blake3::keyed_hash(self.hp.bytes(), &ct[..16]).as_bytes()[..HDR_LEN].try_into().unwrap()
    }

    /// Build a packet, zero-padding the body up to its size class. The caller
    /// guarantees `(sender, ctr)` is fresh for this epoch.
    pub fn seal(&self, hdr: &Header, body: &[u8]) -> Vec<u8> {
        debug_assert_eq!(hdr.epoch, self.epoch as u8);
        let mut padded = Zeroizing::new(body.to_vec());
        padded.resize(bucket(body.len()) - OVERHEAD, 0);
        let tag = self.tag();
        let plain_hdr = hdr.encode();
        let mut aad = [0u8; TAG_LEN + HDR_LEN];
        aad[..TAG_LEN].copy_from_slice(&tag);
        aad[TAG_LEN..].copy_from_slice(&plain_hdr);
        let ct = XChaCha20Poly1305::new(Key::from_slice(self.radio.bytes()))
            .encrypt(XNonce::from_slice(&self.nonce(hdr.sender, hdr.ctr)), Payload { msg: &padded, aad: &aad })
            .expect("radio seal");
        let mask = self.mask(&ct);
        let mut pkt = Vec::with_capacity(OVERHEAD + padded.len());
        pkt.extend_from_slice(&tag);
        pkt.extend(plain_hdr.iter().zip(mask).map(|(h, m)| h ^ m));
        pkt.extend_from_slice(&ct);
        pkt
    }

    /// Unmask and decrypt. `None` for anything that isn't a valid packet
    /// under these keys. The body comes back with its padding.
    pub fn open(&self, pkt: &[u8]) -> Option<(Header, Zeroizing<Vec<u8>>)> {
        if pkt.len() < OVERHEAD || pkt.len() > MTU || pkt[..TAG_LEN] != self.tag() {
            return None;
        }
        let (tag, rest) = pkt.split_at(TAG_LEN);
        let (masked, ct) = rest.split_at(HDR_LEN);
        let mask = self.mask(ct);
        let mut plain_hdr = [0u8; HDR_LEN];
        for i in 0..HDR_LEN {
            plain_hdr[i] = masked[i] ^ mask[i];
        }
        let hdr = Header::decode(&plain_hdr)?;
        if hdr.epoch != self.epoch as u8 {
            return None;
        }
        let mut aad = [0u8; TAG_LEN + HDR_LEN];
        aad[..TAG_LEN].copy_from_slice(tag);
        aad[TAG_LEN..].copy_from_slice(&plain_hdr);
        let body = XChaCha20Poly1305::new(Key::from_slice(self.radio.bytes()))
            .decrypt(XNonce::from_slice(&self.nonce(hdr.sender, hdr.ctr)), Payload { msg: ct, aad: &aad })
            .ok()?;
        Some((hdr, Zeroizing::new(body)))
    }
}

/// Longest gap the ratchet will step across in one go (two weeks of hours).
const MAX_STEPS: u32 = 24 * 14;

/// One epoch's forward-secret key chain: `C(h+1) = KDF(C(h))`, and each
/// link is erased once its hour is two hours gone. Someone who later takes a
/// node's memory reads at most the last hour or so of recorded traffic.
pub struct EpochChain {
    pub epoch: u32,
    /// `chain` is `C(hour)`.
    hour: u32,
    chain: Locked<32>,
    prev: Option<HourKeys>,
    cur: HourKeys,
    next: HourKeys,
}

fn ratchet(c: &[u8; 32]) -> Locked<32> {
    Locked::from_bytes(&Zeroizing::new(blake3::derive_key("commx radio ratchet v1", c)))
}

impl EpochChain {
    /// Start from a chain key handed over directly (a `REKEY`).
    pub fn start(epoch: u32, hour: u32, chain: &[u8; 32]) -> Self {
        let chain = Locked::from_bytes(chain);
        let next = HourKeys::derive(epoch, hour.wrapping_add(1), ratchet(chain.bytes()).bytes());
        Self { epoch, hour, cur: HourKeys::derive(epoch, hour, chain.bytes()), chain, prev: None, next }
    }

    /// Start from a room key at the IP→radio handover. The room key itself
    /// should be wiped afterwards.
    pub fn from_room_key(epoch: u32, hour: u32, room_key: &[u8; 32]) -> Self {
        let mut m = Zeroizing::new([0u8; 36]);
        m[..32].copy_from_slice(room_key);
        m[32..].copy_from_slice(&hour.to_be_bytes());
        Self::start(epoch, hour, &Zeroizing::new(blake3::derive_key("commx radio chain v1", &m[..])))
    }

    /// Hour this chain currently sends in.
    pub fn hour(&self) -> u32 {
        self.hour
    }

    /// `(hour, C(hour))`, for handing the chain to a member.
    pub fn chain_key(&self) -> (u32, &[u8; 32]) {
        (self.hour, self.chain.bytes())
    }

    /// Step forward to `hour` (never back), erasing what's left behind.
    pub fn advance_to(&mut self, hour: u32) {
        if hour <= self.hour {
            return;
        }
        if hour - self.hour > MAX_STEPS {
            // Far beyond anything a live room survives; just jump.
            let mut c = Locked::from_bytes(self.chain.bytes());
            for _ in 0..MAX_STEPS {
                c = ratchet(c.bytes());
            }
            *self = Self::start(self.epoch, hour, c.bytes());
            return;
        }
        while self.hour < hour {
            self.chain = ratchet(self.chain.bytes());
            self.hour += 1;
            let next = HourKeys::derive(self.epoch, self.hour + 1, ratchet(self.chain.bytes()).bytes());
            let cur = std::mem::replace(&mut self.next, next);
            self.prev = Some(std::mem::replace(&mut self.cur, cur));
        }
    }

    /// Keys for sending now.
    pub fn current(&self) -> &HourKeys {
        &self.cur
    }

    /// Keys for a received packet's tag: last, this or next hour.
    pub fn find(&self, tag: &[u8]) -> Option<&HourKeys> {
        [Some(&self.cur), self.prev.as_ref(), Some(&self.next)].into_iter().flatten().find(|k| k.tag() == tag)
    }
}

/// What a packet's signature covers: its type's context, the room, the
/// plaintext header, and the body up to the signature.
pub fn signing_bytes(room_id: &[u8; 16], hdr: &Header, body: &[u8]) -> Vec<u8> {
    let ctx = hdr.kind.sig_context();
    let mut v = Vec::with_capacity(ctx.len() + 16 + HDR_LEN + body.len());
    v.extend_from_slice(ctx);
    v.extend_from_slice(room_id);
    v.extend_from_slice(&hdr.encode());
    v.extend_from_slice(body);
    v
}

/// Short MAC under a member↔host pairwise key.
pub fn mac(pair_key: &[u8; 32], hdr: &Header, body: &[u8]) -> [u8; MAC_LEN] {
    let mut h = blake3::Hasher::new_keyed(pair_key);
    h.update(&hdr.encode());
    h.update(body);
    h.finalize().as_bytes()[..MAC_LEN].try_into().unwrap()
}

/// `BLAKE3(packet)[0..8]`: how an `ORDER` names a packet.
pub fn short_hash(pkt: &[u8]) -> [u8; 8] {
    blake3::hash(pkt).as_bytes()[..8].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr() -> Header {
        Header { kind: Kind::Msg, sender: 3, ctr: 0x01_02_03, epoch: 7, seen_seq: 513, seen_head: [9, 8, 7, 6] }
    }

    #[test]
    fn header_roundtrip() {
        assert_eq!(Header::decode(&hdr().encode()), Some(hdr()));
    }

    #[test]
    fn seal_open_and_tamper() {
        let c = EpochChain::start(7, 100, &[1; 32]);
        let k = c.current();
        let pkt = k.seal(&hdr(), b"hello");
        assert_eq!(pkt.len(), 64, "padded to the smallest size");
        let (h, body) = c.find(&pkt[..4]).unwrap().open(&pkt).unwrap();
        assert_eq!(h, hdr());
        assert_eq!(unpad(&body, 5), Some(&b"hello"[..]));
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 1;
            assert!(k.open(&bad).is_none(), "flipped byte {i} accepted");
        }
        assert!(EpochChain::start(7, 100, &[2; 32]).current().open(&pkt).is_none());
    }

    #[test]
    fn ratchet_keeps_a_window_and_forgets_the_past() {
        let mut a = EpochChain::start(7, 100, &[1; 32]);
        let mut b = EpochChain::start(7, 100, &[1; 32]);
        let at_100 = a.current().seal(&hdr(), b"x");
        a.advance_to(101);
        assert!(a.find(&at_100[..4]).is_some(), "an hour late is still fine");
        let at_101 = a.current().seal(&hdr(), b"x");
        assert!(b.find(&at_101[..4]).is_some(), "an hour early is fine too");
        b.advance_to(101);
        assert_eq!(a.chain_key(), b.chain_key(), "both sides ratchet alike");
        a.advance_to(102);
        assert!(a.find(&at_100[..4]).is_none(), "two hours on, the old keys are gone");
        // Starting a chain from the handed-over key reaches the same place.
        let (h, k) = b.chain_key();
        let mut c = EpochChain::start(7, h, k);
        c.advance_to(102);
        b.advance_to(102);
        assert_eq!(c.chain_key(), b.chain_key());
    }

    #[test]
    fn sizes_are_classes() {
        assert_eq!(bucket(8), 64);
        assert_eq!(bucket(33), 128);
        assert_eq!(bucket(97), 176);
        assert_eq!(bucket(198), 230);
        assert_eq!(unpad(&[1, 2, 0, 0], 2), Some(&[1u8, 2][..]));
        assert_eq!(unpad(&[1, 2, 0, 9], 2), None);
    }

    #[test]
    fn header_is_hidden() {
        let k = EpochChain::start(7, 100, &[1; 32]);
        let a = k.current().seal(&hdr(), b"x");
        let b = k.current().seal(&Header { ctr: 0x01_02_04, ..hdr() }, b"x");
        assert_ne!(&a[4..16], &b[4..16]);
        assert_ne!(&a[4..16], &hdr().encode());
    }

    #[test]
    fn text_capacity() {
        assert_eq!(OVERHEAD, 32);
        assert_eq!(MAX_TEXT, 134);
    }
}
