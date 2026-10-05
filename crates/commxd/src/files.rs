//! Shared files at rest.
//!
//! A received file lives in `<data-dir>/blobs/<random>.blob` as ciphertext only:
//! fixed-size slots of `nonce | len | ct | random padding`, with the slot count
//! padded up to a size bucket and the spare slots filled with random bytes.
//! The name and the size on disk say little, and the bytes look random. The
//! file key exists only in RAM, so dropping it (a nuke) makes the blob noise,
//! and the blob is unlinked too.

use anyhow::{bail, Context, Result};
use commx_core::chain::{chunk_aad, FileMeta, FILE_CHUNK};
use commx_core::crypto::aead_decrypt;
use commx_core::ipc::FileInfo;
use commx_core::secmem::Locked;
use rand::{rngs::OsRng, RngCore};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const SLOT: u64 = (24 + 4 + FILE_CHUNK + 16).next_multiple_of(64) as u64;

/// Pad to the next power of two up to 64 slots (2 MiB), then to multiples of 64.
fn padded_slots(chunks: u32) -> u64 {
    let c = chunks as u64;
    if c <= 64 {
        c.next_power_of_two()
    } else {
        c.next_multiple_of(64)
    }
}

pub fn blob_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("blobs")
}

/// Blobs left behind by a crash are undecryptable (their keys died with the
/// process); remove them at startup.
pub fn purge_orphans(data_dir: &Path) {
    let dir = blob_dir(data_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

pub struct Blob {
    path: PathBuf,
    file: File,
}

impl Blob {
    fn create(data_dir: &Path) -> Result<Self> {
        let dir = blob_dir(data_dir);
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut name = [0u8; 16];
        OsRng.fill_bytes(&mut name);
        let path = dir.join(format!("{}.blob", hex::encode(name)));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let file = opts.open(&path)?;
        Ok(Self { path, file })
    }

    fn write_slot(&mut self, idx: u64, nonce: &[u8; 24], ct: &[u8]) -> Result<()> {
        let mut slot = vec![0u8; SLOT as usize];
        slot[..24].copy_from_slice(nonce);
        slot[24..28].copy_from_slice(&(ct.len() as u32).to_le_bytes());
        slot[28..28 + ct.len()].copy_from_slice(ct);
        OsRng.fill_bytes(&mut slot[28 + ct.len()..]);
        self.file.seek(SeekFrom::Start(idx * SLOT))?;
        self.file.write_all(&slot)?;
        Ok(())
    }

    fn fill_padding(&mut self, from: u64, to: u64) -> Result<()> {
        let mut slot = vec![0u8; SLOT as usize];
        for idx in from..to {
            OsRng.fill_bytes(&mut slot);
            self.file.seek(SeekFrom::Start(idx * SLOT))?;
            self.file.write_all(&slot)?;
        }
        self.file.flush()?;
        Ok(())
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub enum FileState {
    Sending,
    Sent,
    Receiving { got: Vec<bool>, count: u32 },
    Verifying,
    Ready,
    Failed(String),
}

pub struct FileEntry {
    pub no: u32,
    pub id: [u8; 16],
    pub author: [u8; 32],
    pub from: String,
    pub name: String,
    pub size: u64,
    pub chunks: u32,
    pub hash: [u8; 32],
    pub key: Locked<32>,
    pub blob: Option<Blob>,
    pub state: FileState,
    pub last_progress: std::time::Instant,
}

impl FileEntry {
    pub fn incoming(no: u32, id: [u8; 16], author: [u8; 32], from: String, meta: &FileMeta, data_dir: &Path) -> Self {
        let (blob, state) = match Blob::create(data_dir) {
            Ok(b) => (Some(b), FileState::Receiving { got: vec![false; meta.chunks as usize], count: 0 }),
            Err(e) => (None, FileState::Failed(format!("can't store: {e}"))),
        };
        Self::new(no, id, author, from, meta, blob, state)
    }

    pub fn outgoing(no: u32, id: [u8; 16], author: [u8; 32], from: String, meta: &FileMeta) -> Self {
        Self::new(no, id, author, from, meta, None, FileState::Sending)
    }

    fn new(
        no: u32,
        id: [u8; 16],
        author: [u8; 32],
        from: String,
        meta: &FileMeta,
        blob: Option<Blob>,
        state: FileState,
    ) -> Self {
        Self {
            no,
            id,
            author,
            from,
            name: meta.name.clone(),
            size: meta.size,
            chunks: meta.chunks,
            hash: meta.hash,
            key: Locked::from_bytes(&meta.key),
            blob,
            state,
            last_progress: std::time::Instant::now(),
        }
    }

    /// Receiving, but nothing arrived for a while (sender left, or a relay
    /// skipped chunks for us).
    pub fn stalled(&self, after: std::time::Duration) -> bool {
        matches!(self.state, FileState::Receiving { .. }) && self.last_progress.elapsed() > after
    }

    pub fn info(&self) -> FileInfo {
        let state = match &self.state {
            FileState::Sending => "sending".into(),
            FileState::Sent => "sent".into(),
            FileState::Receiving { count, .. } => {
                format!("receiving {}%", (*count as u64 * 100) / self.chunks.max(1) as u64)
            }
            FileState::Verifying => "verifying".into(),
            FileState::Ready => "ready".into(),
            FileState::Failed(e) => format!("failed: {e}"),
        };
        FileInfo { no: self.no, name: self.name.clone(), size: self.size, from: self.from.clone(), state }
    }

    /// Store one chunk. Returns true when the last missing chunk arrived.
    pub fn store_chunk(&mut self, idx: u32, nonce: &[u8; 24], ct: &[u8]) -> bool {
        let FileState::Receiving { got, count } = &mut self.state else { return false };
        if idx >= self.chunks || got[idx as usize] {
            return false;
        }
        // Authenticate now so garbage is caught early; plaintext is dropped (wiped).
        if aead_decrypt(self.key.bytes(), nonce, ct, &chunk_aad(&self.id, idx)).is_err() {
            self.state = FileState::Failed("corrupt chunk".into());
            self.blob = None;
            return false;
        }
        let Some(blob) = &mut self.blob else { return false };
        if let Err(e) = blob.write_slot(idx as u64, nonce, ct) {
            self.state = FileState::Failed(format!("disk: {e}"));
            self.blob = None;
            return false;
        }
        got[idx as usize] = true;
        *count += 1;
        self.last_progress = std::time::Instant::now();
        if *count == self.chunks {
            let pad = blob.fill_padding(self.chunks as u64, padded_slots(self.chunks));
            self.state = match pad {
                Ok(()) => FileState::Verifying,
                Err(e) => FileState::Failed(format!("disk: {e}")),
            };
            return matches!(self.state, FileState::Verifying);
        }
        false
    }

    /// What a blocking task needs to verify or export this file.
    pub fn reader(&self) -> Option<BlobReader> {
        let blob = self.blob.as_ref()?;
        Some(BlobReader {
            path: blob.path.clone(),
            id: self.id,
            chunks: self.chunks,
            size: self.size,
            hash: self.hash,
            key: self.key.clone(),
        })
    }
}

pub struct BlobReader {
    path: PathBuf,
    id: [u8; 16],
    chunks: u32,
    size: u64,
    hash: [u8; 32],
    key: Locked<32>,
}

impl BlobReader {
    /// Decrypt every chunk in order, feeding plaintext to `sink`.
    fn stream(&self, mut sink: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut f = File::open(&self.path)?;
        let mut slot = zeroize::Zeroizing::new(vec![0u8; SLOT as usize]);
        let mut total = 0u64;
        for idx in 0..self.chunks {
            f.seek(SeekFrom::Start(idx as u64 * SLOT))?;
            f.read_exact(&mut slot)?;
            let nonce: [u8; 24] = slot[..24].try_into().unwrap();
            let len = u32::from_le_bytes(slot[24..28].try_into().unwrap()) as usize;
            if len > SLOT as usize - 28 {
                bail!("corrupt blob");
            }
            let plain = aead_decrypt(self.key.bytes(), &nonce, &slot[28..28 + len], &chunk_aad(&self.id, idx))?;
            total += plain.len() as u64;
            sink(&plain)?;
        }
        if total != self.size {
            bail!("size mismatch");
        }
        Ok(())
    }

    /// Check the reassembled plaintext against the signed announcement.
    pub fn verify(&self) -> Result<()> {
        let mut h = blake3::Hasher::new();
        self.stream(|p| {
            h.update(p);
            Ok(())
        })?;
        if h.finalize().as_bytes() != &self.hash {
            bail!("hash mismatch");
        }
        Ok(())
    }

    /// Write a decrypted copy to `dest`, refusing to overwrite anything.
    pub fn export(&self, dest: &Path) -> Result<()> {
        self.verify()?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .with_context(|| format!("can't create {}", dest.display()))?;
        let res = self.stream(|p| Ok(out.write_all(p)?));
        if res.is_err() {
            let _ = std::fs::remove_file(dest);
        }
        res
    }
}

/// Hash a file and count its size (first pass before announcing).
pub fn hash_file(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut f = File::open(path).with_context(|| format!("can't open {}", path.display()))?;
    let mut h = blake3::Hasher::new();
    let mut buf = zeroize::Zeroizing::new(vec![0u8; FILE_CHUNK]);
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        h.update(&buf[..n]);
    }
    Ok((size, *h.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commx_core::crypto::aead_encrypt;

    #[test]
    fn padding_buckets() {
        assert_eq!(padded_slots(1), 1);
        assert_eq!(padded_slots(3), 4);
        assert_eq!(padded_slots(64), 64);
        assert_eq!(padded_slots(65), 128);
        assert_eq!(padded_slots(130), 192);
    }

    #[test]
    fn store_verify_export_roundtrip() {
        let dir = std::env::temp_dir().join(format!("cx-files-{}", std::process::id()));
        let data: Vec<u8> = (0..(FILE_CHUNK * 2 + 100)).map(|i| (i % 251) as u8).collect();
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        let meta = FileMeta {
            name: "x.bin".into(),
            size: data.len() as u64,
            chunks: FileMeta::expected_chunks(data.len() as u64),
            hash: *blake3::hash(&data).as_bytes(),
            key,
        };
        let id = [3u8; 16];
        let mut e = FileEntry::incoming(1, id, [0; 32], "bob".into(), &meta, &dir);
        let mut done = false;
        for (i, chunk) in data.chunks(FILE_CHUNK).enumerate().rev() {
            let (n, ct) = aead_encrypt(&key, chunk, &chunk_aad(&id, i as u32)).unwrap();
            done = e.store_chunk(i as u32, &n, &ct);
        }
        assert!(done);
        let blob_path = e.blob.as_ref().unwrap().path.clone();
        let on_disk = std::fs::read(&blob_path).unwrap();
        assert_eq!(on_disk.len() as u64, 4 * SLOT, "padded to bucket");
        assert!(!on_disk.windows(64).any(|w| data.windows(64).next() == Some(w)), "no plaintext on disk");

        let r = e.reader().unwrap();
        r.verify().unwrap();
        let out = dir.join("out.bin");
        let _ = std::fs::remove_file(&out);
        r.export(&out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), data);
        assert!(r.export(&out).is_err(), "never overwrites");

        drop(e);
        assert!(!blob_path.exists(), "blob unlinked on drop");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
