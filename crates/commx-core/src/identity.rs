use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as DhPublic, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::secmem::Locked;

/// A local alias. Each alias has its own unrelated keys, so two aliases on the
/// same machine can't be linked through key material.
///
/// Secret keys live on a locked page (`sign_sk || dh_sk`); short-lived
/// dalek key objects are built per operation and zeroized on drop.
pub struct Identity {
    pub name: String,
    keys: Locked<64>,
    public: PublicIdentity,
}

/// The public half of an alias, safe to hand to peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub sign_pk: [u8; 32],
    pub dh_pk: [u8; 32],
}

/// Raw secret material, used only by the keystore.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret {
    pub name: String,
    pub sign_sk: [u8; 32],
    pub dh_sk: [u8; 32],
}

impl Identity {
    pub fn generate(name: impl Into<String>) -> Self {
        Self::from_keys(name.into(), Locked::random())
    }

    fn from_keys(name: String, keys: Locked<64>) -> Self {
        let mut id = Self {
            name,
            keys,
            public: PublicIdentity { sign_pk: [0; 32], dh_pk: [0; 32] },
        };
        id.public = PublicIdentity {
            sign_pk: id.signing_key().verifying_key().to_bytes(),
            dh_pk: DhPublic::from(&id.dh_secret()).to_bytes(),
        };
        id
    }

    pub fn from_secret(s: &IdentitySecret) -> Self {
        let mut keys = Locked::<64>::zeroed();
        keys.bytes_mut()[..32].copy_from_slice(&s.sign_sk);
        keys.bytes_mut()[32..].copy_from_slice(&s.dh_sk);
        Self::from_keys(s.name.clone(), keys)
    }

    pub fn to_secret(&self) -> IdentitySecret {
        let k = self.keys.bytes();
        IdentitySecret {
            name: self.name.clone(),
            sign_sk: k[..32].try_into().unwrap(),
            dh_sk: k[32..].try_into().unwrap(),
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(self.keys.bytes()[..32].try_into().unwrap())
    }

    fn dh_secret(&self) -> StaticSecret {
        let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(self.keys.bytes()[32..].try_into().unwrap());
        StaticSecret::from(*bytes)
    }

    pub fn public(&self) -> PublicIdentity {
        self.public
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key().sign(msg).to_bytes().to_vec()
    }

    /// X25519 with a peer public key. The result is wiped on drop.
    pub fn dh(&self, peer: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.dh_secret().diffie_hellman(&DhPublic::from(*peer)).to_bytes())
    }

    pub fn fingerprint(&self) -> String {
        self.public().fingerprint()
    }
}

impl PublicIdentity {
    /// Short human-comparable fingerprint, e.g. `k3j9-xq2m-...`.
    pub fn fingerprint(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"commx-fp-v1");
        h.update(&self.sign_pk);
        h.update(&self.dh_pk);
        let enc = data_encoding::BASE32_NOPAD
            .encode(&h.finalize().as_bytes()[..10])
            .to_lowercase();
        enc.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }
}

/// Verify an Ed25519 signature made by `sign_pk`.
pub fn verify(sign_pk: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(sign_pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify_strict(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_roundtrip() {
        let id = Identity::generate("ghost");
        let sig = id.sign(b"hello");
        assert!(verify(&id.public().sign_pk, b"hello", &sig));
        assert!(!verify(&id.public().sign_pk, b"hellp", &sig));

        let back = Identity::from_secret(&id.to_secret());
        assert_eq!(back.public(), id.public());
        assert_eq!(back.fingerprint(), id.fingerprint());
    }

    #[test]
    fn aliases_unlinkable() {
        let a = Identity::generate("a");
        let b = Identity::generate("a");
        assert_ne!(a.public(), b.public());
    }
}
