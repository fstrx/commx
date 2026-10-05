use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as DhPublic};
use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::secmem::Locked;

/// Symmetric key shared by every member of a room. Lives on a locked page and
/// is wiped on drop, so dropping it is the core of a nuke: without it,
/// ciphertext is noise.
#[derive(Clone)]
pub struct RoomKey(Locked<32>);

impl RoomKey {
    pub fn generate() -> Self {
        Self(Locked::random())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: &[u8; 32] = b.try_into().map_err(|_| anyhow!("bad room key length"))?;
        Ok(Self(Locked::from_bytes(arr)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.bytes()
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<([u8; 24], Vec<u8>)> {
        aead_encrypt(self.0.bytes(), plaintext, aad)
    }

    pub fn decrypt(&self, nonce: &[u8; 24], ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        aead_decrypt(self.0.bytes(), nonce, ct, aad)
    }
}

pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<([u8; 24], Vec<u8>)> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| anyhow!("encrypt failed"))?;
    Ok((nonce, ct))
}

pub fn aead_decrypt(key: &[u8; 32], nonce: &[u8; 24], ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("decrypt failed"))
}

/// Data encrypted to one recipient's X25519 key (an anonymous "sealed box").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sealed {
    pub eph_pk: [u8; 32],
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

fn seal_key(shared: &[u8; 32], eph_pk: &[u8; 32], recipient: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new([0u8; 96]);
    material[..32].copy_from_slice(shared);
    material[32..64].copy_from_slice(eph_pk);
    material[64..].copy_from_slice(recipient);
    Zeroizing::new(blake3::derive_key("commx seal v1", material.as_ref()))
}

pub fn seal_to(recipient_dh_pk: &[u8; 32], plaintext: &[u8]) -> Result<Sealed> {
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pk = DhPublic::from(&eph).to_bytes();
    let shared = Zeroizing::new(eph.diffie_hellman(&DhPublic::from(*recipient_dh_pk)).to_bytes());
    let key = seal_key(&shared, &eph_pk, recipient_dh_pk);
    let (nonce, ct) = aead_encrypt(&key, plaintext, b"commx-sealed")?;
    Ok(Sealed { eph_pk, nonce, ct })
}

pub fn open_sealed(me: &Identity, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    let shared = me.dh(&sealed.eph_pk);
    let key = seal_key(&shared, &sealed.eph_pk, &me.public().dh_pk);
    aead_decrypt(&key, &sealed.nonce, &sealed.ct, b"commx-sealed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_key_roundtrip_and_wrong_key() {
        let k = RoomKey::generate();
        let (n, ct) = k.encrypt(b"secret", b"aad").unwrap();
        assert_eq!(&**k.decrypt(&n, &ct, b"aad").unwrap(), b"secret");
        assert!(k.decrypt(&n, &ct, b"other").is_err());
        assert!(RoomKey::generate().decrypt(&n, &ct, b"aad").is_err());
    }

    #[test]
    fn sealed_box() {
        let alice = Identity::generate("alice");
        let mallory = Identity::generate("mallory");
        let s = seal_to(&alice.public().dh_pk, b"room key").unwrap();
        assert_eq!(&**open_sealed(&alice, &s).unwrap(), b"room key");
        assert!(open_sealed(&mallory, &s).is_err());
    }
}
