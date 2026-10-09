//! Encrypted, authenticated node-to-node channels.
//!
//! Every connection runs a Noise XX handshake with this run's node key, then
//! carries length-prefixed Noise transport messages. Underneath is either a
//! direct TCP stream or a Tor circuit; nothing above [`Net`] knows which.

pub mod tor;

use anyhow::{anyhow, bail, Context, Result};
use commx_core::wire::{self, WireMsg};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use zeroize::Zeroizing;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;
const TAG_LEN: usize = 16;

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

const TCP_TIMEOUT: Duration = Duration::from_secs(10);
/// Tor circuits are slow to build, and a brand-new onion takes a while to
/// publish its descriptor, so keep retrying for this long.
const TOR_DIAL_WINDOW: Duration = Duration::from_secs(180);
const TOR_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

enum Mode {
    Tcp { advertise: String },
    Tor { tor: std::sync::RwLock<Option<Arc<tor::Tor>>>, status: std::sync::Mutex<String> },
}

/// The daemon's network: dialing peers, accepting them, and giving each room
/// an address to put in invites.
pub struct Net {
    key: NodeKey,
    /// Loopback/LAN port our TCP listener is bound to.
    local_port: u16,
    mode: Mode,
}

impl Net {
    pub fn tcp(key: NodeKey, local_port: u16, advertise: String) -> Self {
        Self { key, local_port, mode: Mode::Tcp { advertise } }
    }

    pub fn tor(key: NodeKey, local_port: u16) -> Self {
        let mode = Mode::Tor { tor: std::sync::RwLock::new(None), status: std::sync::Mutex::new("tor starting".into()) };
        Self { key, local_port, mode }
    }

    pub fn is_tor(&self) -> bool {
        matches!(self.mode, Mode::Tor { .. })
    }

    /// Run tor under supervision: launch, bootstrap, then health-check. If
    /// tor dies, the slot is cleared (new rooms/joins report "not ready") and
    /// tor is relaunched with backoff. Rooms hosted on the dead instance lose
    /// their onions and end via the kill switch, as they should.
    pub fn start_tor(self: &Arc<Self>, bin: String, dir: PathBuf) {
        let net = self.clone();
        crate::supervise::supervise("tor", move || {
            let (net, bin, dir) = (net.clone(), bin.clone(), dir.clone());
            async move { net.run_tor(&bin, &dir).await }
        });
    }

    async fn run_tor(&self, bin: &str, dir: &std::path::Path) {
        let Mode::Tor { tor, status } = &self.mode else { return std::future::pending().await };
        let set = |s: String| *status.lock().unwrap_or_else(|e| e.into_inner()) = s;
        let slot = |t: Option<Arc<tor::Tor>>| *tor.write().unwrap_or_else(|e| e.into_inner()) = t;
        slot(None);
        set("tor starting".into());
        let t = match tor::Tor::launch(bin, dir).await {
            Ok(t) => Arc::new(t),
            Err(e) => {
                set(format!("tor failed: {e}"));
                // Don't hammer a missing/broken binary; supervisor backs off too.
                tokio::time::sleep(Duration::from_secs(10)).await;
                return;
            }
        };
        loop {
            match t.bootstrap_progress().await {
                Ok(100) => break,
                Ok(p) => set(format!("tor bootstrapping {p}%")),
                Err(e) => return set(format!("tor failed: {e}")),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        slot(Some(t.clone()));
        set("tor ready".into());
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if t.bootstrap_progress().await.is_err() {
                slot(None);
                set("tor died; restarting".into());
                return;
            }
        }
    }

    fn tor_ready(&self) -> Result<Arc<tor::Tor>> {
        match &self.mode {
            Mode::Tor { tor, status } => tor
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or_else(|| anyhow!("not ready yet: {}", status.lock().unwrap_or_else(|e| e.into_inner()))),
            Mode::Tcp { .. } => bail!("tor is off (start commxd with --tor)"),
        }
    }

    /// Our direct address (empty in Tor mode, where rooms have onions).
    pub fn advertised(&self) -> String {
        match &self.mode {
            Mode::Tcp { advertise } => advertise.clone(),
            Mode::Tor { .. } => String::new(),
        }
    }

    /// Short description for the status bar.
    pub fn label(&self) -> String {
        match &self.mode {
            Mode::Tcp { advertise } => format!("tcp {advertise}"),
            Mode::Tor { status, .. } => status.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        }
    }

    /// Address for a new room's invites, plus the onion id to release on nuke.
    pub async fn room_endpoint(&self) -> Result<(String, Option<String>)> {
        match &self.mode {
            Mode::Tcp { advertise } => Ok((advertise.clone(), None)),
            Mode::Tor { .. } => {
                let id = self.tor_ready()?.add_onion(self.local_port).await?;
                Ok((format!("{id}.onion:{}", tor::ONION_PORT), Some(id)))
            }
        }
    }

    /// Take a room's onion service down (fire and forget).
    pub fn release(self: &Arc<Self>, onion_id: String) {
        let net = self.clone();
        tokio::spawn(async move {
            if let Ok(t) = net.tor_ready() {
                let _ = t.del_onion(&onion_id).await;
            }
        });
    }

    pub async fn dial(&self, addr: &str) -> Result<Conn> {
        let (host, port) = addr.rsplit_once(':').ok_or_else(|| anyhow!("address needs host:port"))?;
        let port: u16 = port.parse().context("bad port")?;
        let onion = host.ends_with(".onion");
        match &self.mode {
            Mode::Tcp { .. } => {
                if onion {
                    bail!("that invite is an onion address; start commxd with --tor");
                }
                let stream = tokio::time::timeout(TCP_TIMEOUT, TcpStream::connect(addr))
                    .await
                    .context("connect timed out")?
                    .with_context(|| format!("can't reach {addr}"))?;
                stream.set_nodelay(true)?;
                tokio::time::timeout(TCP_TIMEOUT, handshake(Box::new(stream), &self.key, true))
                    .await
                    .context("handshake timed out")?
            }
            Mode::Tor { .. } => {
                // Never leak a clearnet connection (and our IP) in Tor mode.
                if !onion {
                    bail!("refusing non-onion address in tor mode");
                }
                let tor = self.tor_ready()?;
                let deadline = Instant::now() + TOR_DIAL_WINDOW;
                let stream = loop {
                    match tor.connect(host, port).await {
                        Ok(s) => break s,
                        Err(e) if Instant::now() >= deadline => return Err(e),
                        Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
                    }
                };
                tokio::time::timeout(TOR_HANDSHAKE_TIMEOUT, handshake(Box::new(stream), &self.key, true))
                    .await
                    .context("handshake timed out")?
            }
        }
    }

    pub async fn accept(&self, listener: &TcpListener) -> Result<TcpStream> {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Responder side over any byte stream (e.g. a bridged WebSocket).
    pub async fn respond_boxed(&self, stream: Box<dyn Stream>) -> Result<Conn> {
        let limit = if self.is_tor() { TOR_HANDSHAKE_TIMEOUT } else { TCP_TIMEOUT };
        tokio::time::timeout(limit, handshake(stream, &self.key, false)).await.context("handshake timed out")?
    }

    pub async fn respond(&self, stream: TcpStream) -> Result<Conn> {
        let limit = if self.is_tor() { TOR_HANDSHAKE_TIMEOUT } else { TCP_TIMEOUT };
        tokio::time::timeout(limit, handshake(Box::new(stream), &self.key, false))
            .await
            .context("handshake timed out")?
    }
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
