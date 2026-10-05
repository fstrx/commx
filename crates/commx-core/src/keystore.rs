//! Alias files at rest: `CXK1 | salt(16) | nonce(24) | XChaCha20-Poly1305(postcard(IdentitySecret))`,
//! keyed with Argon2id(passphrase, salt). File names are random so they reveal
//! nothing about the alias.

use anyhow::{anyhow, bail, Result};
use rand::{rngs::OsRng, RngCore};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto::{aead_decrypt, aead_encrypt};
use crate::identity::{Identity, IdentitySecret};

const MAGIC: &[u8; 4] = b"CXK1";

fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(out)
}

pub fn seal_identity(id: &Identity, passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive(passphrase, &salt)?;
    let plain = Zeroizing::new(postcard::to_allocvec(&id.to_secret())?);
    let (nonce, ct) = aead_encrypt(&key, &plain, MAGIC)?;
    let mut out = Vec::with_capacity(4 + 16 + 24 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_identity(bytes: &[u8], passphrase: &str) -> Result<Identity> {
    if bytes.len() < 44 || &bytes[..4] != MAGIC {
        bail!("not a commx alias file");
    }
    let key = derive(passphrase, &bytes[4..20])?;
    let nonce: [u8; 24] = bytes[20..44].try_into()?;
    let plain = aead_decrypt(&key, &nonce, &bytes[44..], MAGIC).map_err(|_| anyhow!("wrong passphrase"))?;
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
