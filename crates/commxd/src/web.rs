//! Browser members (`commxd --web <dir>`).
//!
//! The peer port also answers plain HTTP: it serves the web client (a fixed
//! whitelist of files from `<dir>`, nothing else) and upgrades `/ws` to a
//! WebSocket. The WebSocket is bridged into a byte stream, so a browser
//! member then goes through exactly the same Noise handshake, join, chain and
//! kill-switch code as any other peer. Nothing here is trusted: the browser
//! still has to present a valid invite inside the encrypted channel.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const HEAD_LIMIT: usize = 8 * 1024;
const MAX_WS_PAYLOAD: u64 = 1 << 20;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The only files ever served, and their types.
const FILES: &[(&str, &str, &str)] = &[
    ("/", "index.html", "text/html; charset=utf-8"),
    ("/index.html", "index.html", "text/html; charset=utf-8"),
    ("/app.js", "app.js", "text/javascript; charset=utf-8"),
    ("/style.css", "style.css", "text/css; charset=utf-8"),
    ("/commx_web.js", "commx_web.js", "text/javascript; charset=utf-8"),
    ("/commx_web_bg.wasm", "commx_web_bg.wasm", "application/wasm"),
];

const SECURITY_HEADERS: &str = "Referrer-Policy: no-referrer\r\n\
X-Content-Type-Options: nosniff\r\n\
Cross-Origin-Opener-Policy: same-origin\r\n\
Cross-Origin-Resource-Policy: same-origin\r\n\
Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
Cache-Control: no-store\r\n";

/// Does this connection start with an HTTP request (vs. a Noise frame)?
pub async fn looks_like_http(stream: &TcpStream) -> bool {
    let mut b = [0u8; 4];
    matches!(tokio::time::timeout(HTTP_TIMEOUT, stream.peek(&mut b)).await, Ok(Ok(4)) if &b == b"GET ")
}

struct Request {
    path: String,
    host: Option<String>,
    origin: Option<String>,
    ws_key: Option<String>,
    upgrade: bool,
}

async fn read_head(stream: &mut TcpStream) -> Result<Request> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEAD_LIMIT {
            bail!("request head too large");
        }
        if stream.read(&mut byte).await? == 0 {
            bail!("closed");
        }
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).context("non-utf8 request")?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    if method != "GET" {
        bail!("method not allowed");
    }
    let mut req = Request { path: path.to_string(), host: None, origin: None, ws_key: None, upgrade: false };
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "host" => req.host = Some(v.to_string()),
            "origin" => req.origin = Some(v.to_string()),
            "sec-websocket-key" => req.ws_key = Some(v.to_string()),
            "upgrade" => req.upgrade = v.eq_ignore_ascii_case("websocket"),
            _ => {}
        }
    }
    Ok(req)
}

/// Is this a plain `host[:port]` (no spaces, quotes or `;`), safe to put in a header?
fn plain_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 255 && h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

/// `connect-src 'self'` should cover our own `ws://`, but Safari (WebKit bug
/// 201591) doesn't apply it to WebSockets, so name the exact origin too.
fn csp(host: Option<&str>) -> String {
    let ws = match host {
        Some(h) if plain_host(h) => format!(" ws://{h} wss://{h}"),
        _ => String::new(),
    };
    format!(
        "Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
connect-src 'self'{ws}; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
    )
}

async fn respond(stream: &mut TcpStream, host: Option<&str>, status: &str, ctype: &str, body: &[u8]) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{}{SECURITY_HEADERS}Connection: close\r\n\r\n",
        body.len(),
        csp(host)
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Same-origin check for the WebSocket upgrade: another website can't make a
/// visitor's browser talk to this node.
fn same_origin(req: &Request) -> bool {
    match (&req.origin, &req.host) {
        (Some(o), Some(h)) => o.strip_prefix("http://").or_else(|| o.strip_prefix("https://")) == Some(h.as_str()),
        _ => false,
    }
}

fn ws_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    data_encoding::BASE64.encode(&h.finalize())
}

/// Handle an HTTP connection. Returns a byte stream if it became a WebSocket
/// (to be handed to the normal peer code), or None if a file was served.
pub async fn accept(mut stream: TcpStream, dir: &Path) -> Result<Option<tokio::io::DuplexStream>> {
    let req = tokio::time::timeout(HTTP_TIMEOUT, read_head(&mut stream)).await.context("slow request")??;
    let path = req.path.split(['?', '#']).next().unwrap_or("");
    let host = req.host.as_deref();
    if path == "/ws" {
        let (true, Some(key), true) = (req.upgrade, req.ws_key.as_deref(), same_origin(&req)) else {
            respond(&mut stream, host, "403 Forbidden", "text/plain", b"forbidden").await?;
            return Ok(None);
        };
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws_accept(key)
        );
        stream.write_all(head.as_bytes()).await?;
        return Ok(Some(bridge(stream)));
    }
    match FILES.iter().find(|(p, ..)| *p == path) {
        Some((_, file, ctype)) => match tokio::fs::read(dir.join(file)).await {
            Ok(body) => respond(&mut stream, host, "200 OK", ctype, &body).await?,
            Err(_) => respond(&mut stream, host, "404 Not Found", "text/plain", b"web client not installed").await?,
        },
        None => respond(&mut stream, host, "404 Not Found", "text/plain", b"not found").await?,
    }
    Ok(None)
}

/// Bridge WebSocket binary messages <-> a plain byte stream.
fn bridge(stream: TcpStream) -> tokio::io::DuplexStream {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let (mut net_r, mut net_w) = stream.into_split();
    let (mut pipe_r, mut pipe_w) = tokio::io::split(ours);
    let (pong_tx, mut pong_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    // WebSocket → bytes
    tokio::spawn(async move {
        while let Ok(Some((op, payload))) = read_frame(&mut net_r).await {
            match op {
                0x0 | 0x2 => {
                    if pipe_w.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                0x9 => {
                    let _ = pong_tx.send(payload);
                }
                0x8 => break,
                _ => {} // text, pong: ignored
            }
        }
        let _ = pipe_w.shutdown().await;
    });
    // bytes → WebSocket
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                n = pipe_r.read(&mut buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => if write_frame(&mut net_w, 0x2, &buf[..n]).await.is_err() { break },
                },
                Some(p) = pong_rx.recv() => if write_frame(&mut net_w, 0xA, &p).await.is_err() { break },
            }
        }
        let _ = write_frame(&mut net_w, 0x8, &[]).await;
        let _ = net_w.shutdown().await;
    });
    theirs
}

/// One client frame (always masked). Returns (opcode, unmasked payload).
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<(u8, Vec<u8>)>> {
    let mut h = [0u8; 2];
    if r.read_exact(&mut h).await.is_err() {
        return Ok(None);
    }
    let op = h[0] & 0x0f;
    if h[1] & 0x80 == 0 {
        bail!("unmasked client frame");
    }
    let len = match h[1] & 0x7f {
        126 => r.read_u16().await? as u64,
        127 => r.read_u64().await?,
        n => n as u64,
    };
    if len > MAX_WS_PAYLOAD {
        bail!("frame too large");
    }
    let mut mask = [0u8; 4];
    r.read_exact(&mut mask).await?;
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok(Some((op, payload)))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, op: u8, payload: &[u8]) -> Result<()> {
    let mut h = vec![0x80 | op];
    match payload.len() {
        n if n < 126 => h.push(n as u8),
        n if n <= u16::MAX as usize => {
            h.push(126);
            h.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            h.push(127);
            h.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    w.write_all(&h).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_accept_key_matches_rfc6455_example() {
        assert_eq!(ws_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn csp_names_own_websocket_origin_only_for_plain_hosts() {
        assert!(csp(Some("192.168.1.19:4700")).contains("connect-src 'self' ws://192.168.1.19:4700 wss://192.168.1.19:4700;"));
        assert!(csp(Some("[::1]:4700")).contains("ws://[::1]:4700"));
        for evil in ["a; script-src *", "a b", "a'b", "x\r\nSet-Cookie: y", ""] {
            assert!(csp(Some(evil)).contains("connect-src 'self';"), "{evil:?}");
        }
        assert!(csp(None).contains("connect-src 'self';"));
    }

    #[test]
    fn origin_must_match_host() {
        let req = |o: Option<&str>, h: Option<&str>| Request {
            path: "/ws".into(),
            host: h.map(Into::into),
            origin: o.map(Into::into),
            ws_key: None,
            upgrade: true,
        };
        assert!(same_origin(&req(Some("http://10.0.0.5:4700"), Some("10.0.0.5:4700"))));
        assert!(!same_origin(&req(Some("http://evil.example"), Some("10.0.0.5:4700"))));
        assert!(!same_origin(&req(None, Some("10.0.0.5:4700"))));
    }
}
