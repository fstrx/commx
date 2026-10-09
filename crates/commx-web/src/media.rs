//! Files and voice for the browser member. Same formats as the apps; the
//! difference is storage: a browser has no blob directory, so received files
//! are held decrypted in this page's memory only, and dropped (wiped) when
//! the room ends.

use anyhow::{bail, Result};
use commx_core::chain::{chunk_aad, FileMeta, FILE_CHUNK};
use commx_core::crypto::{aead_decrypt, aead_encrypt};
use commx_core::voice::ReplayWindow;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Received files held in page memory at once, all files together.
pub const MAX_HELD_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub enum FileState {
    Receiving,
    Ready,
    Sending,
    Sent,
    Failed(String),
}

impl FileState {
    pub fn label(&self, got: u32, chunks: u32) -> String {
        match self {
            Self::Receiving => format!("receiving {}%", (u64::from(got) * 100 / u64::from(chunks.max(1))).min(99)),
            Self::Ready => "ready".into(),
            Self::Sending => format!("sending {}%", (u64::from(got) * 100 / u64::from(chunks.max(1))).min(99)),
            Self::Sent => "sent".into(),
            Self::Failed(why) => format!("failed: {why}"),
        }
    }
}

pub struct WebFile {
    pub no: u32,
    pub author: [u8; 32],
    pub from: String,
    pub name: String,
    pub size: u64,
    pub chunks: u32,
    hash: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    /// Plaintext, filled as chunks arrive (incoming), or the file we're sending.
    data: Zeroizing<Vec<u8>>,
    have: Vec<bool>,
    /// Chunks received (incoming) or handed to the network (outgoing).
    pub got: u32,
    pub state: FileState,
}

impl WebFile {
    pub fn incoming(no: u32, author: [u8; 32], from: String, meta: &FileMeta, room_for: u64) -> Self {
        let mut f = Self::new(no, author, from, meta, Zeroizing::new(Vec::new()), FileState::Receiving);
        if meta.size > room_for {
            f.state = FileState::Failed("too large to hold in a browser tab; use the desktop or Android app".into());
        }
        f
    }

    fn new(no: u32, author: [u8; 32], from: String, meta: &FileMeta, data: Zeroizing<Vec<u8>>, state: FileState) -> Self {
        Self {
            no,
            author,
            from,
            name: meta.name.clone(),
            size: meta.size,
            chunks: meta.chunks,
            hash: meta.hash,
            key: Zeroizing::new(meta.key),
            data,
            have: Vec::new(),
            got: 0,
            state,
        }
    }

    pub fn held(&self) -> u64 {
        match self.state {
            FileState::Receiving | FileState::Ready => self.size,
            _ => 0,
        }
    }

    /// Store one chunk. Returns true when the state changed (done or failed).
    pub fn store_chunk(&mut self, file_id: &[u8; 16], idx: u32, nonce: &[u8; 24], ct: &[u8]) -> bool {
        if self.state != FileState::Receiving || idx >= self.chunks {
            return false;
        }
        if self.have.is_empty() {
            self.data = Zeroizing::new(vec![0u8; self.size as usize]);
            self.have = vec![false; self.chunks as usize];
        }
        if self.have[idx as usize] {
            return false;
        }
        let start = idx as usize * FILE_CHUNK;
        let want = (self.size as usize - start.min(self.size as usize)).min(FILE_CHUNK);
        let Ok(plain) = aead_decrypt(&self.key, nonce, ct, &chunk_aad(file_id, idx)) else {
            self.fail("a chunk didn't authenticate");
            return true;
        };
        if plain.len() != want {
            self.fail("a chunk had the wrong size");
            return true;
        }
        self.data[start..start + want].copy_from_slice(&plain);
        self.have[idx as usize] = true;
        self.got += 1;
        if self.got == self.chunks {
            if blake3::hash(&self.data) == blake3::Hash::from(self.hash) {
                self.state = FileState::Ready;
            } else {
                self.fail("contents don't match the signed hash");
            }
            return true;
        }
        false
    }

    fn fail(&mut self, why: &str) {
        self.state = FileState::Failed(why.into());
        self.data = Zeroizing::new(Vec::new());
    }

    /// Decrypted contents, once verified.
    pub fn bytes(&self) -> Option<&[u8]> {
        (self.state == FileState::Ready).then_some(&self.data[..])
    }
}

pub struct SealedChunk {
    pub idx: u32,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// A file we're uploading: plaintext in memory, chunks sealed on demand.
pub struct Outgoing {
    pub file_id: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    data: Zeroizing<Vec<u8>>,
    pub next: u32,
    pub chunks: u32,
}

impl Outgoing {
    /// Hash and key a file for announcing. Returns (meta, upload state).
    pub fn prepare(name: String, data: Vec<u8>, file_id: [u8; 16], key: [u8; 32]) -> Result<(FileMeta, Self)> {
        let size = data.len() as u64;
        if size > commx_core::chain::MAX_FILE_SIZE {
            bail!("file too large (max 256 MiB)");
        }
        let data = Zeroizing::new(data);
        let meta = FileMeta { name, size, chunks: FileMeta::expected_chunks(size), hash: *blake3::hash(&data).as_bytes(), key };
        let chunks = meta.chunks;
        Ok((meta, Self { file_id, key: Zeroizing::new(key), data, next: 0, chunks }))
    }

    /// Seal the next chunk, if any.
    pub fn next_chunk(&mut self) -> Result<Option<SealedChunk>> {
        if self.next >= self.chunks {
            return Ok(None);
        }
        let idx = self.next;
        let start = (idx as usize * FILE_CHUNK).min(self.data.len());
        let end = (start + FILE_CHUNK).min(self.data.len());
        let (nonce, ct) = aead_encrypt(&self.key, &self.data[start..end], &chunk_aad(&self.file_id, idx))?;
        self.next += 1;
        Ok(Some(SealedChunk { idx, nonce, ct }))
    }
}

pub struct WebCall {
    pub id: [u8; 16],
    pub key: Zeroizing<[u8; 32]>,
    /// Join order.
    pub participants: Vec<[u8; 32]>,
    pub my_seq: u64,
    pub replay: HashMap<[u8; 32], ReplayWindow>,
}

impl WebCall {
    pub fn new(id: [u8; 16], key: [u8; 32], starter: [u8; 32]) -> Self {
        Self { id, key: Zeroizing::new(key), participants: vec![starter], my_seq: 0, replay: HashMap::new() }
    }

    pub fn has(&self, pk: &[u8; 32]) -> bool {
        self.participants.contains(pk)
    }

    /// Returns true if the roster changed.
    pub fn set(&mut self, pk: [u8; 32], joined: bool) -> bool {
        if joined {
            if self.has(&pk) {
                return false;
            }
            self.participants.push(pk);
            true
        } else {
            let before = self.participants.len();
            self.participants.retain(|p| *p != pk);
            self.replay.remove(&pk);
            before != self.participants.len()
        }
    }
}

/// Voice frames for the page, packed as repeated
/// `[u8 name_len][name][u64 seq LE][u16 len LE][opus]`.
#[derive(Default)]
pub struct VoiceOut(pub Vec<u8>);

impl VoiceOut {
    pub fn push(&mut self, from: &str, seq: u64, opus: &[u8]) {
        let name = &from.as_bytes()[..from.len().min(255)];
        self.0.push(name.len() as u8);
        self.0.extend_from_slice(name);
        self.0.extend_from_slice(&seq.to_le_bytes());
        self.0.extend_from_slice(&(opus.len() as u16).to_le_bytes());
        self.0.extend_from_slice(opus);
        // A tab that stops pulling audio mustn't grow without bound (~2 s).
        if self.0.len() > 64 * 1024 {
            self.0.clear();
        }
    }
}
