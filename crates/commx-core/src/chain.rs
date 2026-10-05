//! The per-room "blockchain": an append-only, hash-linked, double-signed log.
//!
//! Authors sign their payload; the host assigns `seq`, links `prev_hash` and
//! signs the block. Members verify both signatures and continuity, so a host
//! can't forge, reorder, drop or splice messages without being detected. There
//! is no consensus or mining: the host is the sequencer, and the chain lives
//! only in RAM so a nuke erases it.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::Sealed;
use crate::identity::{verify, Identity};
use crate::room::MemberInfo;
use crate::RoomId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Body {
    /// Ciphertext of a postcard-encoded `ChatPlain`, under the room key of `epoch`.
    Msg { nonce: [u8; 24], ct: Vec<u8> },
    /// New room key, sealed to each remaining member's sign_pk/dh_pk.
    KeyRotate { new_epoch: u32, sealed: Vec<([u8; 32], Sealed)> },
    Join { member: MemberInfo },
    /// File announcement: postcard `FileMeta` sealed under the room key of `epoch`.
    File { file_id: [u8; 16], nonce: [u8; 24], ct: Vec<u8> },
    /// Call start: postcard `voice::CallMeta` sealed under the room key of `epoch`.
    Call { call_id: [u8; 16], nonce: [u8; 24], ct: Vec<u8> },
    Leave { sign_pk: [u8; 32] },
}

#[derive(Serialize, Deserialize)]
pub struct ChatPlain {
    pub text: String,
}

/// Plaintext 32 KiB per file chunk.
pub const FILE_CHUNK: usize = 32 * 1024;
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// What a room learns about a shared file. `key` encrypts its chunks and is
/// only ever kept in RAM.
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub chunks: u32,
    pub hash: [u8; 32],
    pub key: [u8; 32],
}

impl FileMeta {
    pub fn expected_chunks(size: u64) -> u32 {
        size.div_ceil(FILE_CHUNK as u64).max(1) as u32
    }

    pub fn is_consistent(&self) -> bool {
        self.size <= MAX_FILE_SIZE && self.chunks == Self::expected_chunks(self.size)
    }
}

/// AAD for a file chunk: binds it to its file and position.
pub fn chunk_aad(file_id: &[u8; 16], idx: u32) -> Vec<u8> {
    let mut aad = b"commx-chunk".to_vec();
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&idx.to_be_bytes());
    aad
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub room_id: RoomId,
    pub author: [u8; 32],
    pub epoch: u32,
    pub ts_min: u64,
    pub body: Body,
    pub author_sig: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub payload: Payload,
    pub host_sig: Vec<u8>,
}

impl Payload {
    pub fn new(me: &Identity, room_id: RoomId, epoch: u32, body: Body) -> Self {
        let mut p = Payload {
            room_id,
            author: me.public().sign_pk,
            epoch,
            ts_min: crate::now_minute(),
            body,
            author_sig: Vec::new(),
        };
        p.author_sig = me.sign(&p.signing_bytes());
        p
    }

    fn signing_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(&(
            "commx-payload-v1",
            &self.room_id,
            &self.author,
            self.epoch,
            self.ts_min,
            &self.body,
        ))
        .expect("serialize payload")
    }

    pub fn verify_author(&self) -> bool {
        verify(&self.author, &self.signing_bytes(), &self.author_sig)
    }
}

/// AAD for message ciphertext: binds it to room, epoch and author.
pub fn msg_aad(room_id: &RoomId, epoch: u32, author: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(52);
    aad.extend_from_slice(room_id);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(author);
    aad
}

impl Block {
    fn signing_bytes(seq: u64, prev_hash: &[u8; 32], payload: &Payload) -> Vec<u8> {
        postcard::to_allocvec(&("commx-block-v1", seq, prev_hash, payload)).expect("serialize block")
    }

    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&postcard::to_allocvec(self).expect("serialize block")).as_bytes()
    }
}

/// Chain head tracking. Blocks themselves aren't kept: members only need the
/// head to verify the next link, and keeping less means less to wipe.
pub struct Chain {
    pub room_id: RoomId,
    pub host_pk: [u8; 32],
    pub next_seq: u64,
    pub head: [u8; 32],
}

impl Chain {
    pub fn genesis(room_id: RoomId, host_pk: [u8; 32]) -> Self {
        Self { room_id, host_pk, next_seq: 0, head: [0; 32] }
    }

    /// Resume from a head handed over at join time.
    pub fn resume(room_id: RoomId, host_pk: [u8; 32], next_seq: u64, head: [u8; 32]) -> Self {
        Self { room_id, host_pk, next_seq, head }
    }

    /// Host side: seal a payload into the next block.
    pub fn append(&mut self, host: &Identity, payload: Payload) -> Block {
        let seq = self.next_seq;
        let host_sig = host.sign(&Block::signing_bytes(seq, &self.head, &payload));
        let block = Block { seq, prev_hash: self.head, payload, host_sig };
        self.head = block.hash();
        self.next_seq += 1;
        block
    }

    /// Member side: accept a block only if it extends our head exactly.
    pub fn verify_append(&mut self, block: &Block) -> Result<()> {
        if block.payload.room_id != self.room_id {
            bail!("block for another room");
        }
        if block.seq != self.next_seq {
            bail!("sequence gap or replay: expected {}, got {}", self.next_seq, block.seq);
        }
        if block.prev_hash != self.head {
            bail!("hash link broken at seq {}", block.seq);
        }
        let bytes = Block::signing_bytes(block.seq, &block.prev_hash, &block.payload);
        if !verify(&self.host_pk, &bytes, &block.host_sig) {
            bail!("bad host signature at seq {}", block.seq);
        }
        if !block.payload.verify_author() {
            bail!("bad author signature at seq {}", block.seq);
        }
        self.head = block.hash();
        self.next_seq += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Identity, Identity, Chain, Chain) {
        let host = Identity::generate("host");
        let alice = Identity::generate("alice");
        let id = [7u8; 16];
        let hc = Chain::genesis(id, host.public().sign_pk);
        let mc = Chain::genesis(id, host.public().sign_pk);
        (host, alice, hc, mc)
    }

    fn msg(author: &Identity, n: u8) -> Payload {
        Payload::new(author, [7u8; 16], 0, Body::Msg { nonce: [n; 24], ct: vec![n] })
    }

    #[test]
    fn valid_chain_verifies() {
        let (host, alice, mut hc, mut mc) = setup();
        for i in 0..5 {
            let b = hc.append(&host, msg(&alice, i));
            mc.verify_append(&b).unwrap();
        }
        assert_eq!(hc.head, mc.head);
    }

    #[test]
    fn detects_gap_reorder_and_tamper() {
        let (host, alice, mut hc, mut mc) = setup();
        let b0 = hc.append(&host, msg(&alice, 0));
        let b1 = hc.append(&host, msg(&alice, 1));
        let b2 = hc.append(&host, msg(&alice, 2));

        // gap: skip b0
        assert!(Chain::genesis([7; 16], host.public().sign_pk).verify_append(&b1).is_err());

        mc.verify_append(&b0).unwrap();
        // reorder: b2 before b1
        assert!(mc.verify_append(&b2).is_err());
        // replay
        assert!(mc.verify_append(&b0).is_err());

        // tampered ciphertext breaks author + host sigs
        let mut evil = b1.clone();
        evil.payload.body = Body::Msg { nonce: [9; 24], ct: vec![9] };
        assert!(mc.verify_append(&evil).is_err());

        // host forging a message "from" alice
        let mut forged = msg(&host, 1);
        forged.author = alice.public().sign_pk;
        let mut hc2 = Chain::resume([7; 16], host.public().sign_pk, 1, b0.hash());
        let fb = hc2.append(&host, forged);
        assert!(mc.verify_append(&fb).is_err());

        mc.verify_append(&b1).unwrap();
        mc.verify_append(&b2).unwrap();
    }

    #[test]
    fn rejects_foreign_host() {
        let (_host, alice, _hc, mut mc) = setup();
        let imposter = Identity::generate("imposter");
        let mut ic = Chain::genesis([7; 16], imposter.public().sign_pk);
        let b = ic.append(&imposter, msg(&alice, 0));
        assert!(mc.verify_append(&b).is_err());
    }
}
