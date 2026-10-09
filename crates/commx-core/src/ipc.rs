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
    /// Create (or replace) the room's reusable, password-protected invite.
    InvitePassword { room_id: String, password: String },
    InviteRevoke { room_id: String },
    Join {
        code: String,
        /// Needed for `cx2:` invites.
        #[serde(default)]
        password: Option<String>,
    },
    Send { room_id: String, text: String },
    History { room_id: String },
    /// `None` nukes everything.
    Nuke { room_id: Option<String> },
    SendFile { room_id: String, path: String },
    Files { room_id: String },
    /// Export a decrypted copy of file `no` to `dest` (never overwrites).
    SaveFile { room_id: String, no: u32, dest: String },
    /// Start a call in the room, or join the one already running.
    Call { room_id: String },
    Hangup { room_id: String },
    /// One encoded 20 ms Opus frame from this client's microphone (hex).
    VoiceOut { room_id: String, opus: String },
    /// Fault injection for containment tests. Only exists in debug builds.
    #[cfg(debug_assertions)]
    DebugFault { scope: String, room_id: Option<String> },
    /// Send a file under a raw, unsanitized name (malicious-sender tests). Debug builds only.
    #[cfg(debug_assertions)]
    DebugSendFileAs { room_id: String, path: String, name: String },
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
    /// Voice transport: "udp", "tcp", "tor", or "udp n/m" when hosting.
    #[serde(default)]
    pub link: String,
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
pub struct CallInfo {
    pub participants: Vec<String>,
    pub joined: bool,
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
    InviteCode {
        room_id: String,
        name: String,
        code: String,
        /// Browser join link, when the host serves the web client.
        #[serde(default)]
        web_link: Option<String>,
        /// SHA-256 of the web client's self-signed certificate (`--web-tls`).
        #[serde(default)]
        web_cert: Option<String>,
        /// Reusable password invite (`cx2:`) rather than single use.
        #[serde(default)]
        reusable: bool,
    },
    Room { room: RoomSummary },
    Line { room_id: String, line: ChatLine },
    History { room_id: String, lines: Vec<ChatLine> },
    Nuked { room_id: String, name: String, reason: String },
    Files { room_id: String, list: Vec<FileInfo> },
    /// Call state changed; `None` when there's no call in the room.
    Call { room_id: String, call: Option<CallInfo> },
    /// Opus frame from someone in a call we've joined (hex).
    VoiceIn { room_id: String, from: String, seq: u64, opus: String },
}
