//! Client ↔ daemon protocol: newline-delimited JSON over a private unix socket.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::room::KillMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Status,
    Unlock { passphrase: String },
    AliasNew { name: String, ephemeral: bool, passphrase: Option<String> },
    AliasUse { name: String },
    AliasList,
    RoomNew { name: String, kill_mode: KillMode, grace_secs: u64, dm: bool },
    Invite { room_id: String },
    Join { code: String },
    Send { room_id: String, text: String },
    History { room_id: String },
    /// `None` nukes everything.
    Nuke { room_id: Option<String> },
    SendFile { room_id: String, path: String },
    Files { room_id: String },
    /// Export a decrypted copy of file `no` to `dest` (never overwrites).
    SaveFile { room_id: String, no: u32, dest: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomSummary {
    pub room_id: String,
    pub name: String,
    pub kill_mode: KillMode,
    pub grace_secs: u64,
    pub is_dm: bool,
    pub is_host: bool,
    pub alias: String,
    pub host_fp: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub no: u32,
    pub name: String,
    pub size: u64,
    pub from: String,
    /// "sending", "receiving 40%", "ready", "sent", "failed: ..."
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasInfo {
    pub name: String,
    pub fingerprint: String,
    pub ephemeral: bool,
    pub active: bool,
}

/// Wiped on drop: every copy of a message's plaintext that the code holds
/// is scrubbed when it goes away.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChatLine {
    pub from: String,
    pub text: String,
    pub ts_min: u64,
    pub mine: bool,
    pub system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum IpcEvent {
    Ok { msg: String },
    Error { msg: String },
    Status {
        alias: Option<String>,
        fingerprint: Option<String>,
        listen: String,
        power: String,
        rooms: Vec<RoomSummary>,
    },
    Aliases { list: Vec<AliasInfo> },
    InviteCode { room_id: String, name: String, code: String },
    Room { room: RoomSummary },
    Line { room_id: String, line: ChatLine },
    History { room_id: String, lines: Vec<ChatLine> },
    Nuked { room_id: String, name: String, reason: String },
    Files { room_id: String, list: Vec<FileInfo> },
}
