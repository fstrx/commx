use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::identity::PublicIdentity;
use crate::RoomId;

/// Single use, expires.
const PREFIX: &str = "cx1:";
/// Reusable for the room's lifetime, but only together with a password.
const PREFIX_PW: &str = "cx2:";

/// Shared out-of-band (Signal, in person, paper).
///
/// A `cx1:` invite contains no secrets that outlive it: the token is single
/// use and expires. A `cx2:` invite (`password == true`) can be used any
/// number of times until the room ends or the host revokes it, and is useless
/// without the password, which is never sent over the network: joiners prove
/// they know it with [`password_proof`], and only after the host has proven
/// its identity on the same channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub addr: String,
    pub host: PublicIdentity,
    pub room_id: RoomId,
    pub token: [u8; 16],
    /// Encoded in the prefix, not the body, so `cx1:` codes keep their format.
    #[serde(skip)]
    pub password: bool,
}

impl Invite {
    pub fn encode(&self) -> String {
        let bytes = postcard::to_allocvec(self).expect("serialize invite");
        let prefix = if self.password { PREFIX_PW } else { PREFIX };
        format!("{prefix}{}", data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase())
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let (body, password) = match (s.strip_prefix(PREFIX), s.strip_prefix(PREFIX_PW)) {
            (Some(b), _) => (b, false),
            (_, Some(b)) => (b, true),
            _ => return Err(anyhow!("not a commx invite")),
        };
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .context("invite is corrupted")?;
        let mut inv: Invite = postcard::from_bytes(&bytes).context("invite is corrupted")?;
        inv.password = password;
        Ok(inv)
    }
}

/// Minimum invite password length (characters).
pub const MIN_PASSWORD_CHARS: usize = 8;

/// Password key for a `cx2:` invite. Salted with the room and token, so the
/// same password on another room or a revoked invite gives a different key.
/// Moderate Argon2id cost (19 MiB, t=2): it also runs in browsers, and the
/// proof it keys is only ever shown to the authenticated host.
pub fn password_key(password: &str, room_id: &RoomId, token: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = b"commx-invite-v1:".to_vec();
    salt.extend_from_slice(room_id);
    salt.extend_from_slice(token);
    let params = argon2::Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| anyhow!("argon2: {e}"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, out.as_mut())
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

/// Proof of the password, bound to one Noise channel: useless on any other.
pub fn password_proof(key: &[u8; 32], handshake_hash: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, &crate::wire::channel_binding(handshake_hash, "invite-password")).as_bytes()
}

/// Constant-time check of a joiner's proof.
pub fn check_password_proof(key: &[u8; 32], handshake_hash: &[u8], proof: &[u8; 32]) -> bool {
    blake3::Hash::from(password_proof(key, handshake_hash)) == blake3::Hash::from(*proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn invite(password: bool) -> Invite {
        Invite {
            addr: "10.0.0.5:4700".into(),
            host: Identity::generate("h").public(),
            room_id: [1; 16],
            token: [2; 16],
            password,
        }
    }

    #[test]
    fn roundtrip() {
        let inv = invite(false);
        let code = inv.encode();
        assert!(code.starts_with("cx1:"));
        assert_eq!(Invite::decode(&code).unwrap(), inv);
        assert_eq!(Invite::decode(&code.to_uppercase().replace("CX1:", "cx1:")).unwrap(), inv);
        assert!(Invite::decode("cx1:zzzz").is_err());
        assert!(Invite::decode("nope").is_err());
    }

    #[test]
    fn password_invites_roundtrip_and_differ_only_in_prefix() {
        let a = invite(false);
        let b = Invite { password: true, ..a.clone() };
        let (ca, cb) = (a.encode(), b.encode());
        assert!(cb.starts_with("cx2:"));
        assert_eq!(ca[4..], cb[4..]);
        assert_eq!(Invite::decode(&cb).unwrap(), b);
    }

    #[test]
    fn password_proof_is_bound_to_password_room_token_and_channel() {
        let k = password_key("correct horse", &[1; 16], &[2; 16]).unwrap();
        let p = password_proof(&k, b"chan-a");
        assert!(check_password_proof(&k, b"chan-a", &p));
        assert!(!check_password_proof(&k, b"chan-b", &p));
        for other in [
            password_key("wrong horse", &[1; 16], &[2; 16]).unwrap(),
            password_key("correct horse", &[9; 16], &[2; 16]).unwrap(),
            password_key("correct horse", &[1; 16], &[9; 16]).unwrap(),
        ] {
            assert!(!check_password_proof(&other, b"chan-a", &p));
        }
    }
}
