use serde::{Deserialize, Serialize};

use crate::identity::PublicIdentity;

pub const DEFAULT_GRACE_SECS: u64 = 15;
pub const MIN_GRACE_SECS: u64 = 2;

/// What happens to a room when a node drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillMode {
    /// Host drop nukes the room. A member drop removes it and rotates the key.
    HostOnly,
    /// Any node dropping nukes the room for everyone.
    AnyMember,
}

impl KillMode {
    pub fn label(self) -> &'static str {
        match self {
            KillMode::HostOnly => "host-only",
            KillMode::AnyMember => "any-member",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomConfig {
    pub name: String,
    pub kill_mode: KillMode,
    pub grace_secs: u64,
    pub is_dm: bool,
}

impl RoomConfig {
    /// Heartbeat often enough that a live peer can't miss the grace window.
    pub fn heartbeat_secs(&self) -> u64 {
        (self.grace_secs / 3).clamp(1, 5)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub name: String,
    pub id: PublicIdentity,
}
