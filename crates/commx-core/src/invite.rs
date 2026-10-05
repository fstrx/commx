use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity::PublicIdentity;
use crate::RoomId;

const PREFIX: &str = "cx1:";

/// Shared out-of-band (Signal, in person, paper). Contains no secrets that
/// outlive it: the token is single use and expires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub addr: String,
    pub host: PublicIdentity,
    pub room_id: RoomId,
    pub token: [u8; 16],
}

impl Invite {
    pub fn encode(&self) -> String {
        let bytes = postcard::to_allocvec(self).expect("serialize invite");
        format!("{PREFIX}{}", data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase())
    }

    pub fn decode(s: &str) -> Result<Self> {
        let body = s.trim().strip_prefix(PREFIX).ok_or_else(|| anyhow!("not a commx invite"))?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .context("invite is corrupted")?;
        postcard::from_bytes(&bytes).context("invite is corrupted")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn roundtrip() {
        let inv = Invite {
            addr: "10.0.0.5:4700".into(),
            host: Identity::generate("h").public(),
            room_id: [1; 16],
            token: [2; 16],
        };
        let code = inv.encode();
        assert!(code.starts_with("cx1:"));
        assert_eq!(Invite::decode(&code).unwrap(), inv);
        assert_eq!(Invite::decode(&code.to_uppercase().replace("CX1:", "cx1:")).unwrap(), inv);
        assert!(Invite::decode("cx1:zzzz").is_err());
        assert!(Invite::decode("nope").is_err());
    }
}
