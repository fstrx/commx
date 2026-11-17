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

/// Keys for one room-key epoch. Both live on locked pages.
pub struct EpochKeys {
    pub epoch: u32,
    radio: Locked<32>,
    hp: Locked<32>,
}

pub fn unix_hour(now_ms: u64) -> u32 {
    (now_ms / 3_600_000) as u32
}

impl EpochKeys {
    pub fn derive(epoch: u32, room_key: &[u8; 32]) -> Self {
        let radio = Zeroizing::new(blake3::derive_key("commx radio key v1", room_key));
        let hp = Zeroizing::new(blake3::derive_key("commx radio hp v1", room_key));
        Self { epoch, radio: Locked::from_bytes(&radio), hp: Locked::from_bytes(&hp) }
    }

    pub fn tag(&self, hour: u32) -> [u8; TAG_LEN] {
        let mut m = [0u8; 7];
        m[..3].copy_from_slice(b"tag");
        m[3..].copy_from_slice(&hour.to_be_bytes());
        blake3::keyed_hash(self.radio.bytes(), &m).as_bytes()[..TAG_LEN].try_into().unwrap()
    }

    /// Does this packet's tag belong to us, within an hour either side?
    pub fn matches(&self, tag: &[u8], now_ms: u64) -> bool {
        let h = unix_hour(now_ms);
        [h.wrapping_sub(1), h, h.wrapping_add(1)].iter().any(|&h| self.tag(h) == tag)
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

    /// Build a packet. The caller guarantees `(sender, ctr)` is fresh for this epoch.
    pub fn seal(&self, now_ms: u64, hdr: &Header, body: &[u8]) -> Vec<u8> {
        debug_assert_eq!(hdr.epoch, self.epoch as u8);
        let tag = self.tag(unix_hour(now_ms));
        let plain_hdr = hdr.encode();
        let mut aad = [0u8; TAG_LEN + HDR_LEN];
        aad[..TAG_LEN].copy_from_slice(&tag);
        aad[TAG_LEN..].copy_from_slice(&plain_hdr);
        let ct = XChaCha20Poly1305::new(Key::from_slice(self.radio.bytes()))
            .encrypt(XNonce::from_slice(&self.nonce(hdr.sender, hdr.ctr)), Payload { msg: body, aad: &aad })
            .expect("radio seal");
        let mask = self.mask(&ct);
        let mut pkt = Vec::with_capacity(OVERHEAD + body.len());
        pkt.extend_from_slice(&tag);
        pkt.extend(plain_hdr.iter().zip(mask).map(|(h, m)| h ^ m));
        pkt.extend_from_slice(&ct);
        pkt
    }

    /// Unmask and decrypt. `None` for anything that isn't a valid packet under this epoch.
    pub fn open(&self, pkt: &[u8]) -> Option<(Header, Zeroizing<Vec<u8>>)> {
        if pkt.len() < OVERHEAD || pkt.len() > MTU {
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
        let k = EpochKeys::derive(7, &[1; 32]);
        let now = 1_700_000_000_000;
        let pkt = k.seal(now, &hdr(), b"hello");
        assert_eq!(pkt.len(), OVERHEAD + 5);
        assert!(k.matches(&pkt[..4], now));
        assert!(k.matches(&pkt[..4], now + 3_600_000), "next hour still accepts last hour's tag");
        assert!(!k.matches(&pkt[..4], now + 3 * 3_600_000));
        let (h, body) = k.open(&pkt).unwrap();
        assert_eq!((h, &body[..]), (hdr(), &b"hello"[..]));
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 1;
            assert!(k.open(&bad).is_none(), "flipped byte {i} accepted");
        }
        assert!(EpochKeys::derive(7, &[2; 32]).open(&pkt).is_none());
    }

    #[test]
    fn header_is_hidden() {
        let k = EpochKeys::derive(7, &[1; 32]);
        let a = k.seal(0, &hdr(), b"x");
        let b = k.seal(0, &Header { ctr: 0x01_02_04, ..hdr() }, b"x");
        // Same type and sender, yet the masked header bytes differ throughout.
        assert_ne!(a[4], b[4]);
        assert_ne!(a[5], b[5]);
        assert_ne!(&a[4..16], &hdr().encode());
    }

    #[test]
    fn text_capacity() {
        assert_eq!(OVERHEAD, 32);
        assert_eq!(MAX_TEXT, 134);
    }
}
