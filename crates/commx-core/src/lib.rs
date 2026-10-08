//! commx-core: identities, crypto, the per-room hash chain and every message
//! format shared by the daemon and the client. No IO lives here.

pub mod chain;
pub mod crypto;
pub mod identity;
pub mod invite;
pub mod ipc;
pub mod keystore;
#[cfg(feature = "native")]
pub mod local_ipc;
pub mod room;
pub mod secmem;
pub mod text;
pub mod voice;
pub mod wire;

pub type RoomId = [u8; 16];

/// Longest chat message accepted, in bytes. Keeps every frame well under the
/// 64 KiB Noise message limit.
pub const MAX_TEXT_LEN: usize = 8 * 1024;

/// Current unix time coarsened to the minute, to leak less timing metadata.
pub fn now_minute() -> u64 {
    // Browsers: std's clock panics on wasm32-unknown-unknown; ask JS.
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        (js_sys::Date::now() / 60_000.0) as u64
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 60)
            .unwrap_or(0)
    }
}

/// Default home for alias files and the control socket.
#[cfg(feature = "native")]
pub fn default_data_dir() -> std::path::PathBuf {
    directories::ProjectDirs::from("", "", "commx")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(".commx"))
}

pub fn room_id_hex(id: &RoomId) -> String {
    hex::encode(id)
}

pub fn parse_room_id(s: &str) -> Option<RoomId> {
    hex::decode(s).ok()?.try_into().ok()
}
