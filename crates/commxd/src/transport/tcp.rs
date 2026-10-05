use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

use super::{handshake, Conn, NodeKey, Stream, Transport};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Direct TCP + Noise. Peers see each other's IP; Tor comes next.
pub struct TcpTransport {
    pub key: Arc<NodeKey>,
}

impl Transport for TcpTransport {
    async fn dial(&self, addr: &str) -> Result<Conn> {
        let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("connect timed out")?
            .with_context(|| format!("can't reach {addr}"))?;
        stream.set_nodelay(true)?;
        let boxed: Box<dyn Stream> = Box::new(stream);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(boxed, &self.key, true))
            .await
            .context("handshake timed out")?
    }
}

impl TcpTransport {
    pub async fn accept(&self, listener: &TcpListener) -> Result<TcpStream> {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    pub async fn respond(&self, stream: TcpStream) -> Result<Conn> {
        let boxed: Box<dyn Stream> = Box::new(stream);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(boxed, &self.key, false))
            .await
            .context("handshake timed out")?
    }
}
