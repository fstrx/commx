//! Node-to-node messages, carried inside an authenticated Noise channel.
//!
//! The Noise static keys are per-run node keys, not alias keys, so one listener
//! can host rooms for several aliases without linking them. Alias identity is
//! proven by signing the Noise handshake hash, which binds the proof to this
//! exact channel and defeats relay/MITM.

use serde::{Deserialize, Serialize};

use crate::chain::{Block, Payload};
use crate::crypto::Sealed;
use crate::identity::verify;
use crate::room::{MemberInfo, RoomConfig};
use crate::RoomId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireMsg {
    JoinReq {
        room_id: RoomId,
        token: [u8; 16],
        member: MemberInfo,
        /// Signature over `channel_binding(handshake_hash)`.
        sig: Vec<u8>,
    },
    JoinOk {
        cfg: RoomConfig,
        host: MemberInfo,
        host_sig: Vec<u8>,
        epoch: u32,
        sealed_key: Sealed,
        members: Vec<MemberInfo>,
        next_seq: u64,
        head: [u8; 32],
    },
    JoinDenied { reason: String },
    /// Member → host: please sequence this payload.
    Submit(Payload),
    /// Host → members: a sequenced, signed block.
    Block(Block),
    Heartbeat,
    /// Encrypted file chunk (bulk lane). Relayed by the host, never chained:
    /// its file's signed announcement carries the hash that authenticates it.
    FileChunk { room_id: RoomId, file_id: [u8; 16], idx: u32, nonce: [u8; 24], ct: Vec<u8> },
    /// Host → members: destroy this room now.
    Nuke { room_id: RoomId, sig: Vec<u8> },
    /// Member → host: I'm leaving.
    Leave { room_id: RoomId },
}

pub fn channel_binding(handshake_hash: &[u8], role: &str) -> Vec<u8> {
    let mut v = b"commx-chan-v1:".to_vec();
    v.extend_from_slice(role.as_bytes());
    v.push(b':');
    v.extend_from_slice(handshake_hash);
    v
}

pub fn nuke_bytes(room_id: &RoomId) -> Vec<u8> {
    let mut v = b"commx-nuke-v1:".to_vec();
    v.extend_from_slice(room_id);
    v
}

pub fn verify_nuke(host_pk: &[u8; 32], room_id: &RoomId, sig: &[u8]) -> bool {
    verify(host_pk, &nuke_bytes(room_id), sig)
}

pub fn encode(msg: &WireMsg) -> Vec<u8> {
    postcard::to_allocvec(msg).expect("serialize wire msg")
}

pub fn decode(bytes: &[u8]) -> anyhow::Result<WireMsg> {
    Ok(postcard::from_bytes(bytes)?)
}
