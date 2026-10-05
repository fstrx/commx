//! Alias files at rest:
//! `CXK2 | m_kib(4) | t(4) | p(4) | salt(16) | nonce(24) | XChaCha20-Poly1305(postcard(IdentitySecret))`,
//! keyed with Argon2id(passphrase, salt, m, t, p). Parameters are stored so they
//! can be raised later without breaking old files. File names are random so
//! they reveal nothing about the alias.

use anyhow::{anyhow, bail, Result};
use rand::{rngs::OsRng, RngCore};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::{aead_decrypt, aead_encrypt};
use crate::identity::{Identity, IdentitySecret};

const MAGIC: &[u8; 4] = b"CXK2";
const HEADER: usize = 4 + 12 + 16 + 24;
/// 64 MiB, 3 passes: well above OWASP's floor, ~0.3s on a laptop.
const M_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

fn derive(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    if !(8 * 1024..=1024 * 1024).contains(&m) || !(1..=16).contains(&t) || !(1..=8).contains(&p) {
        bail!("alias file has unreasonable KDF parameters");
    }
    let params = argon2::Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("argon2: {e}"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

pub fn seal_identity(id: &Identity, passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive(passphrase, &salt, M_KIB, T_COST, P_COST)?;
    let plain = Zeroizing::new(postcard::to_allocvec(&id.to_secret())?);
    let mut header = Vec::with_capacity(HEADER);
    header.extend_from_slice(MAGIC);
    for v in [M_KIB, T_COST, P_COST] {
        header.extend_from_slice(&v.to_le_bytes());
    }
    // The header is authenticated: tampering with params or magic fails decryption.
    let (nonce, ct) = aead_encrypt(&key, &plain, &header)?;
    let mut out = header;
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_identity(bytes: &[u8], passphrase: &str) -> Result<Identity> {
    if bytes.len() < HEADER || &bytes[..4] != MAGIC {
        bail!("not a commx alias file");
    }
    let word = |i: usize| u32::from_le_bytes(bytes[4 + i * 4..8 + i * 4].try_into().unwrap());
    let key = derive(passphrase, &bytes[16..32], word(0), word(1), word(2))?;
    let nonce: [u8; 24] = bytes[32..56].try_into()?;
    let plain =
        aead_decrypt(&key, &nonce, &bytes[HEADER..], &bytes[..16]).map_err(|_| anyhow!("wrong passphrase"))?;
    let secret: IdentitySecret = postcard::from_bytes(&plain)?;
    Ok(Identity::from_secret(&secret))
}

/// Write an alias into `dir` under a random name. Returns the path.
pub fn save(dir: &Path, id: &Identity, passphrase: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut name = [0u8; 12];
    OsRng.fill_bytes(&mut name);
    let path = dir.join(format!("{}.cx", hex::encode(name)));
    write_private(&path, &seal_identity(id, passphrase)?)?;
    Ok(path)
}

/// Every alias in `dir` that opens with this passphrase.
pub fn load_all(dir: &Path, passphrase: &str) -> Vec<Identity> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "cx"))
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|b| open_identity(&b, passphrase).ok())
        .collect()
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    Ok(std::fs::write(path, bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_wrong_passphrase() {
        let id = Identity::generate("ghost");
        let blob = seal_identity(&id, "correct horse").unwrap();
        let back = open_identity(&blob, "correct horse").unwrap();
        assert_eq!(back.public(), id.public());
        assert_eq!(back.name, "ghost");
        assert!(open_identity(&blob, "wrong").is_err());

        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_identity(&tampered, "correct horse").is_err());
    }
}
