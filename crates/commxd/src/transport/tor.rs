//! Tor transport: a private tor process owned by commxd, one ephemeral onion
//! service per room, and outbound connections through SOCKS5 with per-connection
//! circuit isolation.
//!
//! The tor process exits when commxd does (`__OwningControllerProcess`), and
//! onion keys are discarded at creation (`Flags=DiscardPK`), so a room's
//! address can never come back after it's nuked.

use anyhow::{anyhow, bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Virtual port every room onion listens on.
pub const ONION_PORT: u16 = 4700;

struct Ctl {
    r: BufReader<OwnedReadHalf>,
    w: OwnedWriteHalf,
}

pub struct Tor {
    ctl: Mutex<Ctl>,
    pub socks: SocketAddr,
    _child: Child,
}

impl Ctl {
    /// Send one control-port command; return the reply lines (codes stripped).
    async fn cmd(&mut self, line: &str) -> Result<Vec<String>> {
        self.w.write_all(format!("{line}\r\n").as_bytes()).await?;
        let mut out = Vec::new();
        loop {
            let mut l = String::new();
            if self.r.read_line(&mut l).await? == 0 {
                bail!("tor control connection closed");
            }
            let l = l.trim_end_matches(['\r', '\n']);
            if l.len() < 4 {
                bail!("bad tor control reply: {l}");
            }
            let (code, sep, rest) = (&l[..3], l.as_bytes()[3], &l[4..]);
            match sep {
                b'-' => out.push(rest.to_string()),
                b'+' => {
                    out.push(rest.to_string());
                    loop {
                        let mut d = String::new();
                        if self.r.read_line(&mut d).await? == 0 {
                            bail!("tor control connection closed");
                        }
                        let d = d.trim_end_matches(['\r', '\n']);
                        if d == "." {
                            break;
                        }
                        out.push(d.to_string());
                    }
                }
                b' ' if code.starts_with('2') => {
                    out.push(rest.to_string());
                    return Ok(out);
                }
                _ => bail!("tor: {l}"),
            }
        }
    }
}

/// `PORT=127.0.0.1:9151` → address.
fn parse_port_file(s: &str) -> Option<SocketAddr> {
    s.lines().find_map(|l| l.trim().strip_prefix("PORT=")?.parse().ok())
}

/// `net/listeners/socks="127.0.0.1:9050" ...` → first address.
fn parse_socks_listener(lines: &[String]) -> Option<SocketAddr> {
    let l = lines.iter().find(|l| l.starts_with("net/listeners/socks="))?;
    l.split('"').nth(1)?.parse().ok()
}

/// `status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 ...` → 45.
fn parse_progress(lines: &[String]) -> Option<u8> {
    let l = lines.iter().find(|l| l.contains("PROGRESS="))?;
    let rest = &l[l.find("PROGRESS=")? + 9..];
    rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

impl Tor {
    /// Start a private tor instance with its state in `dir`.
    pub async fn launch(bin: &str, dir: &Path) -> Result<Self> {
        let port_file = dir.join("control.port");
        let cookie_file = dir.join("control_auth_cookie");
        let _ = std::fs::remove_file(&port_file);
        let child = Command::new(bin)
            .arg("--ignore-missing-torrc")
            .arg("-f")
            .arg(dir.join("torrc-none"))
            .arg("--defaults-torrc")
            .arg(dir.join("torrc-defaults-none"))
            .arg("--DataDirectory")
            .arg(dir)
            .args(["--SocksPort", "127.0.0.1:auto", "--ControlPort", "127.0.0.1:auto"])
            .arg("--ControlPortWriteToFile")
            .arg(&port_file)
            .args(["--CookieAuthentication", "1"])
            .arg("--CookieAuthFile")
            .arg(&cookie_file)
            .args(["--__OwningControllerProcess", &std::process::id().to_string()])
            .args(["--AvoidDiskWrites", "1", "--Log", "err stderr"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("can't start tor ('{bin}'); install it or pass --tor-bin"))?;

        let mut ctl_addr = None;
        for _ in 0..600 {
            if let Some(a) = std::fs::read_to_string(&port_file).ok().and_then(|s| parse_port_file(&s)) {
                ctl_addr = Some(a);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let ctl_addr = ctl_addr.ok_or_else(|| anyhow!("tor didn't open its control port"))?;
        let (r, w) = TcpStream::connect(ctl_addr).await?.into_split();
        let mut ctl = Ctl { r: BufReader::new(r), w };

        let cookie = std::fs::read(&cookie_file).context("read tor auth cookie")?;
        ctl.cmd(&format!("AUTHENTICATE {}", hex::encode(cookie))).await?;
        ctl.cmd("TAKEOWNERSHIP").await?;
        ctl.cmd("RESETCONF __OwningControllerProcess").await?;
        let socks = parse_socks_listener(&ctl.cmd("GETINFO net/listeners/socks").await?)
            .ok_or_else(|| anyhow!("tor has no SOCKS listener"))?;
        Ok(Self { ctl: Mutex::new(ctl), socks, _child: child })
    }

    pub async fn bootstrap_progress(&self) -> Result<u8> {
        let lines = self.ctl.lock().await.cmd("GETINFO status/bootstrap-phase").await?;
        parse_progress(&lines).ok_or_else(|| anyhow!("can't read tor bootstrap status"))
    }

    /// New onion service forwarding to `127.0.0.1:local_port`. Returns the
    /// service id (address without `.onion`). The private key never leaves tor.
    pub async fn add_onion(&self, local_port: u16) -> Result<String> {
        let lines = self
            .ctl
            .lock()
            .await
            .cmd(&format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={ONION_PORT},127.0.0.1:{local_port}"))
            .await?;
        lines
            .iter()
            .find_map(|l| l.strip_prefix("ServiceID="))
            .map(str::to_string)
            .ok_or_else(|| anyhow!("tor didn't return a service id"))
    }

    pub async fn del_onion(&self, service_id: &str) -> Result<()> {
        self.ctl.lock().await.cmd(&format!("DEL_ONION {service_id}")).await?;
        Ok(())
    }

    /// Connect to `host:port` through tor. Fresh random SOCKS credentials put
    /// every connection on its own circuit (IsolateSOCKSAuth).
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut iso = [0u8; 16];
        OsRng.fill_bytes(&mut iso);
        socks5_connect(self.socks, host, port, &hex::encode(iso)).await
    }
}

fn connect_request(host: &str, port: u16) -> Result<Vec<u8>> {
    if host.is_empty() || host.len() > 255 {
        bail!("bad host");
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

fn socks_error(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "not allowed",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        0xF0 => "onion descriptor not found (not published yet, or gone)",
        0xF1 => "onion descriptor invalid",
        0xF2 => "onion introduction failed",
        0xF3 => "onion rendezvous failed",
        0xF6 => "bad onion address",
        _ => "unknown error",
    }
}

async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16, isolation: &str) -> Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await.context("tor SOCKS port unreachable")?;
    s.set_nodelay(true)?;
    // Offer only username/password auth: tor uses the creds purely for isolation.
    s.write_all(&[5, 1, 2]).await?;
    let mut two = [0u8; 2];
    s.read_exact(&mut two).await?;
    if two != [5, 2] {
        bail!("SOCKS proxy refused auth method");
    }
    let mut auth = vec![1, isolation.len() as u8];
    auth.extend_from_slice(isolation.as_bytes());
    auth.extend_from_slice(&[1, b'x']);
    s.write_all(&auth).await?;
    s.read_exact(&mut two).await?;
    if two != [1, 0] {
        bail!("SOCKS auth failed");
    }
    s.write_all(&connect_request(host, port)?).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        bail!("tor: {}", socks_error(head[1]));
    }
    let skip = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            n[0] as usize
        }
        _ => bail!("bad SOCKS reply"),
    } + 2;
    let mut sink = vec![0u8; skip];
    s.read_exact(&mut sink).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_replies() {
        assert_eq!(parse_port_file("PORT=127.0.0.1:41234\n"), Some("127.0.0.1:41234".parse().unwrap()));
        let socks = vec![r#"net/listeners/socks="127.0.0.1:39001" "127.0.0.1:39002""#.to_string()];
        assert_eq!(parse_socks_listener(&socks), Some("127.0.0.1:39001".parse().unwrap()));
        let boot = vec!["status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_status".to_string()];
        assert_eq!(parse_progress(&boot), Some(45));
    }

    #[test]
    fn builds_socks_request() {
        let r = connect_request("abc.onion", 4700).unwrap();
        assert_eq!(&r[..5], &[5, 1, 0, 3, 9]);
        assert_eq!(&r[5..14], b"abc.onion");
        assert_eq!(&r[14..], &4700u16.to_be_bytes());
        assert!(connect_request("", 1).is_err());
    }
}
