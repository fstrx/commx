//! Encrypted, authenticated node-to-node channels.
//!
//! Every connection runs a Noise XX handshake with this run's node key, then
//! carries length-prefixed Noise transport messages. The stream type is boxed,
//! so a Tor transport can hand in an onion-service stream later without
//! touching anything above this module.

pub mod tcp;

use anyhow::{bail, Result};
use commx_core::wire::{self, WireMsg};
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use zeroize::Zeroizing;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;
const TAG_LEN: usize = 16;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

pub trait Transport: Send + Sync + 'static {
    fn dial(&self, addr: &str) -> impl Future<Output = Result<Conn>> + Send;
}

/// Noise static key for this daemon run. Regenerated at every start and never
/// written to disk, so it can't link aliases across sessions.
pub struct NodeKey {
    private: Zeroizing<Vec<u8>>,
}

impl NodeKey {
    pub fn generate() -> Result<Self> {
        let kp = snow::Builder::new(NOISE_PARAMS.parse()?).generate_keypair()?;
        Ok(Self { private: Zeroizing::new(kp.private) })
    }
}

pub struct Conn {
    pub reader: SecureReader,
    pub writer: SecureWriter,
    /// Unique per channel; aliases sign it to prove who's on the other end.
    pub handshake_hash: Vec<u8>,
}

type Noise = Arc<snow::StatelessTransportState>;

pub struct SecureReader {
    io: ReadHalf<Box<dyn Stream>>,
    noise: Noise,
    nonce: u64,
}

pub struct SecureWriter {
    io: WriteHalf<Box<dyn Stream>>,
    noise: Noise,
    nonce: u64,
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u32().await? as usize;
    if len > MAX_NOISE_MSG {
        bail!("oversized frame");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<()> {
    w.write_u32(bytes.len() as u32).await?;
    w.write_all(bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn handshake(stream: Box<dyn Stream>, key: &NodeKey, initiator: bool) -> Result<Conn> {
    let builder = snow::Builder::new(NOISE_PARAMS.parse()?).local_private_key(&key.private);
    let mut hs = if initiator { builder.build_initiator()? } else { builder.build_responder()? };
    let (mut r, mut w) = tokio::io::split(stream);
    let mut buf = vec![0u8; MAX_NOISE_MSG];

    // XX: -> e ; <- e, ee, s, es ; -> s, se
    for step in 0..3 {
        let we_send = (step % 2 == 0) == initiator;
        if we_send {
            let n = hs.write_message(&[], &mut buf)?;
            write_frame(&mut w, &buf[..n]).await?;
        } else {
            let msg = read_frame(&mut r).await?;
            hs.read_message(&msg, &mut buf)?;
        }
    }
    if !hs.is_handshake_finished() {
        bail!("noise handshake incomplete");
    }
    let handshake_hash = hs.get_handshake_hash().to_vec();
    let noise: Noise = Arc::new(hs.into_stateless_transport_mode()?);
    Ok(Conn {
        reader: SecureReader { io: r, noise: noise.clone(), nonce: 0 },
        writer: SecureWriter { io: w, noise, nonce: 0 },
        handshake_hash,
    })
}

impl SecureWriter {
    pub async fn send(&mut self, msg: &WireMsg) -> Result<()> {
        let plain = Zeroizing::new(wire::encode(msg));
        if plain.len() > MAX_NOISE_MSG - TAG_LEN {
            bail!("message too large for one frame");
        }
        let mut out = vec![0u8; plain.len() + TAG_LEN];
        let n = self.noise.write_message(self.nonce, &plain, &mut out)?;
        self.nonce += 1;
        write_frame(&mut self.io, &out[..n]).await
    }
}

impl SecureReader {
    pub async fn recv(&mut self) -> Result<WireMsg> {
        let frame = read_frame(&mut self.io).await?;
        let mut plain = Zeroizing::new(vec![0u8; frame.len()]);
        let n = self.noise.read_message(self.nonce, &frame, &mut plain)?;
        self.nonce += 1;
        wire::decode(&plain[..n])
    }
}
